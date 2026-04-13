"""
tools/parsers/dirlist_crawler.py
Directory listing page detector and recursive crawler.

Detects Apache/Nginx "Index of" pages, extracts linked files/subdirectories,
and recursively crawls up to a configurable depth to build a file tree.
"""
from __future__ import annotations

import logging
import re
from dataclasses import dataclass, field
from typing import Optional
from urllib.parse import urljoin, urlparse

from backend.tools.executor import ToolExecutor, LogCallback, RecordCallback

logger = logging.getLogger(__name__)

_DIR_LISTING_PATTERNS = [
    # Apache / Nginx
    re.compile(r"Index\s+of\s+/", re.IGNORECASE),
    re.compile(r"<title>\s*Index\s+of\s+", re.IGNORECASE),
    re.compile(r"Parent\s+Directory", re.IGNORECASE),
    re.compile(r"<h1>\s*Index\s+of\s+", re.IGNORECASE),
    re.compile(r'class="indexcolname"', re.IGNORECASE),
    # IIS
    re.compile(r"Directory\s+Listing\s+--?\s+/", re.IGNORECASE),
    re.compile(r"<title>\s*\S+\s*-\s*/.*</title>", re.IGNORECASE),
    # Tomcat
    re.compile(r"Directory\s+Listing\s+For\s+/", re.IGNORECASE),
    # Python http.server / SimpleHTTPServer
    re.compile(r"Directory\s+listing\s+for\s+/", re.IGNORECASE),
    # LightTPD
    re.compile(r"<title>\s*Index\s+of\s+/", re.IGNORECASE),
    # Generic table-based directory listing (Name + Last Modified + Size columns)
    re.compile(
        r"<th[^>]*>\s*Name\s*</th>.*<th[^>]*>\s*Last\s+Modified\s*</th>",
        re.IGNORECASE | re.DOTALL,
    ),
]

_HREF_RE = re.compile(r'href\s*=\s*["\']([^"\']+)["\']', re.IGNORECASE)

_INTERESTING_EXTENSIONS = {
    ".php", ".jsp", ".py", ".rb", ".pl", ".cgi", ".sh", ".bash",
    ".conf", ".cfg", ".ini", ".xml", ".yaml", ".yml", ".json", ".properties",
    ".sql", ".db", ".sqlite", ".sqlite3", ".mdb",
    ".bak", ".old", ".backup", ".swp", ".save", ".orig", ".tmp",
    ".zip", ".tar", ".tar.gz", ".tgz", ".rar", ".7z", ".gz",
    ".key", ".pem", ".crt", ".cer", ".p12", ".pfx",
    ".log", ".txt", ".csv", ".env", ".htaccess", ".htpasswd",
    ".java", ".class", ".war", ".jar",
}


@dataclass
class DirListEntry:
    """A single entry found in a directory listing."""
    path: str
    is_dir: bool = False
    interesting: bool = False
    depth: int = 0
    size_hint: int = 0


@dataclass
class DirListResult:
    """Result of crawling directory listings."""
    entries: list[DirListEntry] = field(default_factory=list)
    dir_listing_paths: list[str] = field(default_factory=list)

    @property
    def file_tree_text(self) -> str:
        if not self.entries:
            return ""
        lines = []
        for entry in sorted(self.entries, key=lambda e: e.path):
            prefix = "  " * entry.depth
            marker = "[DIR] " if entry.is_dir else "[FILE]"
            star = " *" if entry.interesting else ""
            lines.append(f"{prefix}{marker} {entry.path}{star}")
        return "\n".join(lines[:80])


def is_directory_listing(html: str) -> bool:
    """Check if HTML content looks like a directory listing page."""
    if not html:
        return False
    return any(pat.search(html) for pat in _DIR_LISTING_PATTERNS)


def extract_listing_links(html: str, base_path: str) -> list[tuple[str, bool]]:
    """Extract file/directory links from a directory listing HTML page.

    Returns list of (path, is_dir) tuples.
    """
    if not html:
        return []

    results: list[tuple[str, bool]] = []
    seen: set[str] = set()

    for match in _HREF_RE.finditer(html):
        href = match.group(1).strip()
        if not href or href.startswith(("?", "#", "mailto:", "javascript:")):
            continue
        if href in ("../", "/", "."):
            continue

        is_dir = href.endswith("/")

        if href.startswith("http://") or href.startswith("https://"):
            parsed = urlparse(href)
            full_path = parsed.path
        elif href.startswith("/"):
            full_path = href
        else:
            base_dir = base_path if base_path.endswith("/") else base_path.rsplit("/", 1)[0] + "/"
            full_path = urljoin(f"http://dummy{base_dir}", href)
            full_path = urlparse(full_path).path

        if not full_path.startswith("/"):
            full_path = "/" + full_path

        if full_path in seen:
            continue
        seen.add(full_path)
        results.append((full_path, is_dir))

    return results


def _is_interesting_file(path: str) -> bool:
    """Check if a file path has an interesting extension."""
    lower = path.lower().rstrip("/")
    return any(lower.endswith(ext) for ext in _INTERESTING_EXTENSIONS)


async def crawl_directory_listings(
    base_url: str,
    seed_paths: list[str],
    executor: ToolExecutor,
    *,
    max_depth: int = 5,
    max_total_entries: int = 100,
    log_callback: LogCallback = None,
    record_callback: RecordCallback = None,
) -> DirListResult:
    """Crawl discovered paths that are directory listings, recursively extracting links.

    Args:
        base_url: e.g. "http://192.168.1.100:80"
        seed_paths: paths discovered by previous probes (e.g. ["/files/", "/backup/"])
        executor: ToolExecutor for running curl commands
        max_depth: maximum recursion depth (default 2)
        max_total_entries: cap on total entries to prevent runaway crawling
    """
    result = DirListResult()
    visited: set[str] = set()
    queue: list[tuple[str, int]] = [(p, 0) for p in seed_paths]

    while queue and len(result.entries) < max_total_entries:
        path, depth = queue.pop(0)
        if path in visited:
            continue
        visited.add(path)

        url = f"{base_url.rstrip('/')}{path}"
        try:
            curl_result = await executor.run_script(
                script_content=f'curl -sS -L --max-time 8 "{url}" 2>/dev/null | head -c 50000',
                timeout=15,
                log_callback=log_callback,
                record_callback=record_callback,
                record_phase="surface_enum",
                record_purpose="dirlist_crawl",
            )
        except Exception as e:
            logger.debug(f"[DirListCrawler] 获取 {path} 失败: {e}")
            continue

        html = curl_result.stdout or ""
        if not is_directory_listing(html):
            continue

        result.dir_listing_paths.append(path)
        links = extract_listing_links(html, path)

        for link_path, link_is_dir in links:
            if link_path in visited:
                continue
            interesting = _is_interesting_file(link_path)
            result.entries.append(DirListEntry(
                path=link_path,
                is_dir=link_is_dir,
                interesting=interesting,
                depth=depth + 1,
            ))

            if link_is_dir and depth + 1 < max_depth:
                queue.append((link_path, depth + 1))

            if len(result.entries) >= max_total_entries:
                break

    # Fetch Content-Length for interesting files via HEAD requests
    interesting_entries = [e for e in result.entries if e.interesting and not e.is_dir]
    if interesting_entries:
        head_targets = interesting_entries[:30]
        head_script_parts = ['set +e']
        for ent in head_targets:
            url = f"{base_url.rstrip('/')}{ent.path}"
            head_script_parts.append(
                f'CL=$(curl -sS -I --max-time 5 "{url}" 2>/dev/null '
                f'| grep -i "^content-length:" | head -1 '
                f'| tr -d "\\r" | awk \'{{print $2}}\'); '
                f'echo "{ent.path}|${{CL:-0}}"'
            )
        head_script = "\n".join(head_script_parts)
        try:
            head_result = await executor.run_script(
                script_content=head_script,
                timeout=30,
                log_callback=log_callback,
                record_callback=record_callback,
                record_phase="surface_enum",
                record_purpose="dirlist_head_size",
            )
            if head_result.stdout:
                path_to_entry = {e.path: e for e in result.entries}
                for line in head_result.stdout.strip().splitlines():
                    parts = line.strip().rsplit("|", 1)
                    if len(parts) == 2:
                        p, sz = parts
                        try:
                            path_to_entry[p].size_hint = int(sz)
                        except (KeyError, ValueError):
                            pass
        except Exception as e:
            logger.debug(f"[DirListCrawler] HEAD size probe failed: {e}")

    if result.entries:
        interesting_count = sum(1 for e in result.entries if e.interesting)
        logger.info(
            f"[DirListCrawler] 爬取完成: {len(result.entries)} 条目 "
            f"({interesting_count} 个有价值文件), "
            f"{len(result.dir_listing_paths)} 个目录列表页"
        )

    return result
