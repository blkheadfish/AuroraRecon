"""
phpinfo_parser.py
Deterministic extraction of security-relevant runtime facts from phpinfo() output.

Supports two input formats:
  - HTML: the default phpinfo page, rows rendered as
          ``<tr><td class="e">key</td><td class="v">value</td></tr>``
          (and the three-column "local / master" variant).
  - Plain text: ``php -i`` / ``cli -i`` style ``key => value`` or
          ``key => local => master``.

Output is a flat dict (``PhpinfoFacts``) with only fields that we can
confidently extract.  Missing fields are omitted rather than set to empty
strings, so downstream code can use ``"key" in facts`` / ``.get(...)``
without guessing.
"""
from __future__ import annotations

import html as _html
import re
from typing import Any

# ── Regex helpers ─────────────────────────────────────────

_HTML_ROW_RE = re.compile(
    r'<tr[^>]*>\s*'
    r'<t[dh][^>]*class="e"[^>]*>(?P<key>.*?)</t[dh]>\s*'
    r'<t[dh][^>]*class="v"[^>]*>(?P<val>.*?)</t[dh]>'
    r'(?:\s*<t[dh][^>]*class="v"[^>]*>(?P<val2>.*?)</t[dh]>)?'
    r'\s*</tr>',
    re.IGNORECASE | re.DOTALL,
)

_TAG_STRIP_RE = re.compile(r'<[^>]+>')

_PLAIN_LINE_RE = re.compile(
    r'^(?P<key>[A-Za-z][A-Za-z0-9_\.\- ]+?)\s*=>\s*(?P<val>.+?)'
    r'(?:\s*=>\s*(?P<val2>.+?))?\s*$',
    re.MULTILINE,
)


def _clean(value: str) -> str:
    """Remove HTML tags/entities and surrounding whitespace."""
    if not value:
        return ""
    stripped = _TAG_STRIP_RE.sub(" ", value)
    return _html.unescape(stripped).strip()


def _to_bool(value: str) -> bool:
    return value.strip().lower() in ("on", "enabled", "1", "true", "yes")


_KEY_NORMALISE = {
    # section-scoped php runtime keys we care about
    "php version": "php_version",
    "system": "system",
    "server api": "sapi",
    "loaded configuration file": "loaded_config",
    "disable_functions": "disable_functions",
    "disable_classes": "disable_classes",
    "open_basedir": "open_basedir",
    "allow_url_fopen": "allow_url_fopen",
    "allow_url_include": "allow_url_include",
    "doc_root": "doc_root",
    "document_root": "doc_root",
    "user_dir": "user_dir",
    "short_open_tag": "short_open_tag",
    "magic_quotes_gpc": "magic_quotes_gpc",
    "safe_mode": "safe_mode",
    "upload_tmp_dir": "upload_tmp_dir",
    "session.save_path": "session_save_path",
    "expose_php": "expose_php",
    "register_globals": "register_globals",
    "max_execution_time": "max_execution_time",
    "memory_limit": "memory_limit",
    "post_max_size": "post_max_size",
    "upload_max_filesize": "upload_max_filesize",
}

_BOOL_KEYS = {
    "allow_url_fopen",
    "allow_url_include",
    "short_open_tag",
    "magic_quotes_gpc",
    "safe_mode",
    "expose_php",
    "register_globals",
}


def _normalise_key(raw: str) -> str:
    key = raw.strip().lower()
    key = re.sub(r'\s+', ' ', key)
    return _KEY_NORMALISE.get(key, "")


def _prefer_local(local: str, master: str) -> str:
    """phpinfo often shows 'local | master' — prefer non-empty local."""
    local = (local or "").strip()
    if local and local.lower() not in ("no value", "(none)"):
        return local
    master = (master or "").strip()
    if master.lower() in ("no value", "(none)"):
        return ""
    return master


def _extract_loaded_extensions(text: str) -> list[str]:
    """Return a sorted list of loaded PHP extensions.

    phpinfo HTML: section headers use ``<h2>ExtensionName</h2>``.
    CLI output: ``[PHP Modules]`` followed by newline-separated names.
    """
    extensions: set[str] = set()

    for m in re.finditer(
        r'<h2[^>]*>\s*(?:<a[^>]*>)?\s*([A-Za-z][\w.+-]{1,40})\s*(?:</a>)?\s*</h2>',
        text,
        re.IGNORECASE,
    ):
        name = m.group(1).strip()
        if name.lower() in ("configuration", "environment", "php variables",
                            "php credits", "php license", "apache environment",
                            "headers", "additional modules", "php core"):
            continue
        extensions.add(name)

    cli_block = re.search(
        r'\[PHP Modules\]\s*(.*?)(?:\[Zend Modules\]|\Z)',
        text,
        re.DOTALL | re.IGNORECASE,
    )
    if cli_block:
        for line in cli_block.group(1).splitlines():
            name = line.strip()
            if name and re.match(r'^[A-Za-z][\w.+-]+$', name):
                extensions.add(name)

    return sorted(extensions, key=str.lower)


def parse_phpinfo(text: str) -> dict[str, Any]:
    """Parse phpinfo HTML or CLI text and return a structured facts dict.

    Only fields we can confidently identify are included.  Boolean directives
    (``allow_url_include`` etc.) are coerced to ``True/False``.
    """
    if not text:
        return {}

    facts: dict[str, Any] = {}

    is_html = "<td" in text.lower() or "<tr" in text.lower()
    rows_found = 0

    if is_html:
        for m in _HTML_ROW_RE.finditer(text):
            raw_key = _clean(m.group("key"))
            raw_val1 = _clean(m.group("val") or "")
            raw_val2 = _clean(m.group("val2") or "")
            key = _normalise_key(raw_key)
            if not key:
                continue
            value = _prefer_local(raw_val1, raw_val2)
            facts[key] = value
            rows_found += 1

    if rows_found == 0:
        for m in _PLAIN_LINE_RE.finditer(text):
            raw_key = m.group("key")
            raw_val1 = m.group("val") or ""
            raw_val2 = m.group("val2") or ""
            key = _normalise_key(raw_key)
            if not key:
                continue
            value = _prefer_local(raw_val1, raw_val2)
            facts[key] = value

    # Coerce booleans
    for bk in _BOOL_KEYS:
        if bk in facts:
            facts[bk] = _to_bool(str(facts[bk]))

    # disable_functions → list
    if "disable_functions" in facts:
        raw = str(facts["disable_functions"])
        if raw.strip().lower() in ("no value", "none", "(none)", ""):
            facts["disable_functions"] = []
        else:
            items = [x.strip() for x in re.split(r'[,\s]+', raw) if x.strip()]
            facts["disable_functions"] = items

    # disable_classes → list (same handling)
    if "disable_classes" in facts:
        raw = str(facts["disable_classes"])
        if raw.strip().lower() in ("no value", "none", "(none)", ""):
            facts["disable_classes"] = []
        else:
            facts["disable_classes"] = [x.strip() for x in re.split(r'[,\s]+', raw) if x.strip()]

    # loaded extensions via secondary scan (h2 headers / CLI block)
    loaded = _extract_loaded_extensions(text)
    if loaded:
        facts["loaded_extensions"] = loaded

    if "php_version" not in facts:
        m = re.search(r'PHP\s+Version\s*</?[^>]*>?\s*([\d.]+(?:-[\w.]+)?)',
                      text, re.IGNORECASE)
        if m:
            facts["php_version"] = m.group(1).strip()
        else:
            m2 = re.search(r'PHP\s+Version\s*=>\s*([\d.]+(?:-[\w.]+)?)',
                           text, re.IGNORECASE)
            if m2:
                facts["php_version"] = m2.group(1).strip()

    return facts


def is_phpinfo_content(text: str) -> bool:
    """Heuristic: does this body look like phpinfo() output?"""
    if not text:
        return False
    lt = text.lower()
    markers = 0
    if "php version" in lt:
        markers += 1
    if "system =>" in lt or "<td class=\"e\">system" in lt or 'system</td>' in lt:
        markers += 1
    if "php credits" in lt or "zend engine" in lt:
        markers += 1
    if "configuration file" in lt or "loaded configuration" in lt:
        markers += 1
    return markers >= 2


def summarise_for_context(facts: dict[str, Any], max_chars: int = 800) -> str:
    """Render a compact summary block for LLM prompt injection."""
    if not facts:
        return ""
    lines: list[str] = ["PHP 运行时约束摘要:"]
    if facts.get("php_version"):
        lines.append(f"- PHP Version: {facts['php_version']}")
    if facts.get("sapi"):
        lines.append(f"- SAPI: {facts['sapi']}")
    if facts.get("doc_root"):
        lines.append(f"- DocRoot: {facts['doc_root']}")
    if "allow_url_include" in facts:
        lines.append(f"- allow_url_include: {'On' if facts['allow_url_include'] else 'Off'}")
    if "allow_url_fopen" in facts:
        lines.append(f"- allow_url_fopen: {'On' if facts['allow_url_fopen'] else 'Off'}")
    if facts.get("open_basedir"):
        lines.append(f"- open_basedir: {facts['open_basedir']}")
    if facts.get("disable_functions"):
        df = facts["disable_functions"]
        if isinstance(df, list):
            df = ", ".join(df[:20])
        lines.append(f"- disable_functions: {df}")
    if facts.get("session_save_path"):
        lines.append(f"- session.save_path: {facts['session_save_path']}")
    if facts.get("upload_tmp_dir"):
        lines.append(f"- upload_tmp_dir: {facts['upload_tmp_dir']}")
    result = "\n".join(lines)
    return result[:max_chars]


_CMD_EXEC_FUNCTIONS = frozenset([
    "system", "exec", "passthru", "shell_exec", "popen", "proc_open",
])


def derive_attack_surface(facts: dict[str, Any]) -> dict[str, Any]:
    """Convert raw facts into high-level attack-surface flags.

    Returned keys (all booleans unless noted):
      - rfi_possible: allow_url_include is On
      - url_fopen: allow_url_fopen is On
      - shell_cmd_restricted: all of system/exec/passthru/shell_exec/popen/proc_open disabled
      - disabled_cmd_functions: list[str] of disabled shell-cmd functions
      - open_basedir_restricted: open_basedir is set and non-empty
      - log_candidates: list of inferred log paths based on loaded SAPI
    """
    surface: dict[str, Any] = {}
    if facts.get("allow_url_include") is True:
        surface["rfi_possible"] = True
    if facts.get("allow_url_fopen") is True:
        surface["url_fopen"] = True
    disabled = facts.get("disable_functions") or []
    if isinstance(disabled, list):
        disabled_cmd = [d for d in disabled if d in _CMD_EXEC_FUNCTIONS]
        surface["disabled_cmd_functions"] = disabled_cmd
        surface["shell_cmd_restricted"] = (
            len(disabled_cmd) >= len(_CMD_EXEC_FUNCTIONS)
        )
    ob = facts.get("open_basedir")
    if ob and str(ob).strip().lower() not in ("no value", "(none)", "none"):
        surface["open_basedir_restricted"] = True
        surface["open_basedir_value"] = ob
    return surface
