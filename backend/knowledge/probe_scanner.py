"""
knowledge/probe_scanner.py
KB 主动探针扫描器

设计目的：
  把 KB 从"被动文本检索器"升级为"主动指纹扫描引擎"。
  在 intel_harvest 阶段，对每一个 KB 条目里声明的 probes 直接发送 HTTP/TCP
  探测请求，根据 success_signs 命中即给出 ProbeHit。

为什么不复用 Skill 的 probe？
  - Skill probe 是"利用前确认环境约束"，属于具体 Skill 内部逻辑；
  - KB probe 是"快速指纹/CVE 命中扫描"，跨多个 CVE 串行扫一遍，命中后再
    把指挥权交给 Skill 进行真正的利用。

输出 → SkillRegistry.match() 用 dispatch_skill 直接决定 Skill。
"""
from __future__ import annotations

import asyncio
import logging
import re
from dataclasses import dataclass, field
from typing import Any, Awaitable, Callable, Optional

from backend.knowledge.exploit_kb import ExploitEntry, ExploitKB

logger = logging.getLogger(__name__)


# ── 输入：每次探测一个 base_url ────────────────────────────

@dataclass
class ProbeTarget:
    """一次探测的目标 + 默认上下文"""
    base_url: str          # e.g. "http://10.0.0.5:8080"
    host: str              # e.g. "10.0.0.5"
    port: int              # e.g. 8080
    scheme: str = "http"   # http | https


# ── 输出：探针命中记录 ───────────────────────────────────

@dataclass
class ProbeHit:
    """探针命中：一个 KB 条目被成功识别。"""
    vuln_id: str            # 命中的 KB 条目 vuln_id
    probe_id: str           # 触发命中的具体 probe id
    dispatch_skill: str     # 指向利用 Skill 的 ID（可为空）
    confidence: float       # 0.0~1.0
    evidence: str           # 简短证据片段（响应头/正文摘要）
    base_url: str           # 命中的 base_url
    port: int               # 命中的端口
    cves: list[str] = field(default_factory=list)
    description: str = ""


# ── 工具执行接口（避免硬依赖具体 ToolExecutor 实现）─────

ScriptRunner = Callable[..., Awaitable[Any]]


# ── 探针扫描器主体 ────────────────────────────────────

# 默认用于 HTTP 探针扫描的 web 端口（若 finding 里没明确）
DEFAULT_WEB_PORTS = (80, 443, 8000, 8080, 8081, 8090, 8161, 8443, 8888, 7001, 9000, 9090, 9200)


class ProbeScanner:
    """
    使用 KB 中声明的 probes 对目标进行主动扫描。

    用法：
        scanner = ProbeScanner(kb, executor)
        targets = [ProbeTarget("http://10.0.0.5:8080", "10.0.0.5", 8080), ...]
        hits = await scanner.scan(targets, task_id="task-123")
        for hit in hits:
            print(hit.vuln_id, hit.dispatch_skill, hit.confidence)
    """

    def __init__(
        self,
        kb: Optional[ExploitKB] = None,
        executor: Any = None,
        *,
        max_concurrent: int = 6,
        per_probe_timeout: int = 12,
    ):
        self.kb = kb or ExploitKB()
        self.executor = executor
        self.max_concurrent = max_concurrent
        self.per_probe_timeout = per_probe_timeout

    # ── 主入口 ─────────────────────────────────────────

    async def scan(
        self,
        targets: list[ProbeTarget],
        *,
        task_id: Optional[str] = None,
        log_callback: Any = None,
        record_callback: Any = None,
    ) -> list[ProbeHit]:
        """
        对每个目标 base_url 执行 KB 里所有适配的探针。

        注意：
          - probe 自带 ports → 只在端口匹配时执行
          - probe 不带 ports → 适用于一切 web 端口
          - method=RAW_TCP 的探针走 ncat 路径（极少数，如 WebLogic T3）
        """
        if not targets or not self.executor:
            return []

        entries = self.kb.list_all()
        plans: list[tuple[ExploitEntry, dict, ProbeTarget]] = []

        for entry in entries:
            for probe in (entry.probes or []):
                if not isinstance(probe, dict):
                    continue
                allowed_ports = probe.get("ports") or []
                for tgt in targets:
                    if allowed_ports and tgt.port not in allowed_ports:
                        continue
                    plans.append((entry, probe, tgt))

        if not plans:
            return []

        logger.info(
            f"[ProbeScanner] 规划 {len(plans)} 次探针 "
            f"({len(entries)} KB 条目 × {len(targets)} 目标)"
        )

        sem = asyncio.Semaphore(self.max_concurrent)

        async def _run_one(entry: ExploitEntry, probe: dict, tgt: ProbeTarget) -> Optional[ProbeHit]:
            async with sem:
                try:
                    return await self._execute_probe(
                        entry, probe, tgt,
                        task_id=task_id,
                        log_callback=log_callback,
                        record_callback=record_callback,
                    )
                except Exception as e:
                    logger.debug(
                        f"[ProbeScanner] 探针异常 vuln={entry.vuln_id} "
                        f"probe={probe.get('id')} target={tgt.base_url}: {e}"
                    )
                    return None

        results = await asyncio.gather(*[_run_one(e, p, t) for e, p, t in plans])

        # 同一 vuln_id+base_url 可能多个 probe 都命中：保留最高 confidence 的那条
        best: dict[tuple[str, str], ProbeHit] = {}
        for hit in results:
            if hit is None:
                continue
            key = (hit.vuln_id, hit.base_url)
            prev = best.get(key)
            if prev is None or hit.confidence > prev.confidence:
                best[key] = hit

        hits = list(best.values())
        if hits:
            summary = ", ".join(
                f"{h.vuln_id}({h.confidence:.2f})" for h in sorted(
                    hits, key=lambda x: -x.confidence
                )[:8]
            )
            logger.info(f"[ProbeScanner] 命中 {len(hits)} 个 KB 条目: {summary}")

        return hits

    # ── 单次探针执行 ───────────────────────────────────

    async def _execute_probe(
        self,
        entry: ExploitEntry,
        probe: dict,
        tgt: ProbeTarget,
        *,
        task_id: Optional[str],
        log_callback: Any,
        record_callback: Any,
    ) -> Optional[ProbeHit]:
        method = (probe.get("method") or "GET").upper()

        if method == "RAW_TCP":
            return await self._execute_tcp_probe(entry, probe, tgt, task_id=task_id)

        # 默认走 HTTP 路径
        return await self._execute_http_probe(
            entry, probe, tgt,
            task_id=task_id,
            log_callback=log_callback,
            record_callback=record_callback,
        )

    async def _execute_http_probe(
        self,
        entry: ExploitEntry,
        probe: dict,
        tgt: ProbeTarget,
        *,
        task_id: Optional[str],
        log_callback: Any,
        record_callback: Any,
    ) -> Optional[ProbeHit]:
        method = (probe.get("method") or "GET").upper()
        path = probe.get("path") or "/"
        headers = probe.get("headers") or {}
        body = probe.get("body") or ""
        timeout = int(probe.get("timeout") or self.per_probe_timeout)

        # 拼出最终 URL（path 已经是 /xxx 或 /a?b=c 格式）
        url = tgt.base_url.rstrip("/") + (path if path.startswith("/") else f"/{path}")

        script = _build_curl_script(
            method=method, url=url, headers=headers, body=body, timeout=timeout,
        )

        try:
            result = await self.executor.run_script(
                script_content=script,
                timeout=timeout + 5,
                log_callback=log_callback,
                record_callback=record_callback,
                record_phase="intel_harvest",
                record_purpose=f"kb_probe:{entry.vuln_id}:{probe.get('id', '')}",
                task_id=task_id,
            )
        except Exception as e:
            logger.debug(f"[ProbeScanner] 执行失败 {url}: {e}")
            return None

        raw = (result.stdout or "") + "\n" + (result.stderr or "")
        status_code, headers_text, body_text = _parse_curl_output(raw)

        if not _evaluate_success(probe.get("success_signs") or {}, status_code, headers_text, body_text):
            return None

        return ProbeHit(
            vuln_id=entry.vuln_id,
            probe_id=probe.get("id", ""),
            dispatch_skill=entry.dispatch_skill,
            confidence=float(probe.get("confidence") or 0.7),
            evidence=_extract_evidence(headers_text, body_text, max_chars=400),
            base_url=tgt.base_url,
            port=tgt.port,
            cves=list(entry.match_cves),
            description=entry.description,
        )

    async def _execute_tcp_probe(
        self,
        entry: ExploitEntry,
        probe: dict,
        tgt: ProbeTarget,
        *,
        task_id: Optional[str],
    ) -> Optional[ProbeHit]:
        """少数协议探针（如 T3）：发送原始字节，观察响应。"""
        payload_hex = probe.get("payload_hex") or ""
        timeout = int(probe.get("timeout") or self.per_probe_timeout)
        if not payload_hex:
            return None

        script = (
            f'set +e\n'
            f'(printf "%b" "$(echo {_shell_quote(payload_hex)} | xxd -r -p)" '
            f'| timeout {timeout} ncat -w {timeout} {_shell_quote(tgt.host)} {tgt.port}) 2>&1 | head -c 2048'
        )

        try:
            result = await self.executor.run_script(
                script_content=script,
                timeout=timeout + 5,
                record_phase="intel_harvest",
                record_purpose=f"kb_probe_tcp:{entry.vuln_id}:{probe.get('id', '')}",
                task_id=task_id,
            )
        except Exception as e:
            logger.debug(f"[ProbeScanner] TCP 探针失败 {tgt.host}:{tgt.port}: {e}")
            return None

        raw = (result.stdout or "") + (result.stderr or "")
        success_signs = probe.get("success_signs") or {}
        contains_any = success_signs.get("response_contains_any") or []
        if contains_any and not any(sub.lower() in raw.lower() for sub in contains_any):
            return None
        if not contains_any and not raw.strip():
            return None

        return ProbeHit(
            vuln_id=entry.vuln_id,
            probe_id=probe.get("id", ""),
            dispatch_skill=entry.dispatch_skill,
            confidence=float(probe.get("confidence") or 0.6),
            evidence=raw[:300],
            base_url=tgt.base_url,
            port=tgt.port,
            cves=list(entry.match_cves),
            description=entry.description,
        )


# ── 辅助函数 ─────────────────────────────────────────

def _shell_quote(value: str) -> str:
    """简单 shell 单引号包裹。"""
    safe = str(value).replace("'", "'\"'\"'")
    return f"'{safe}'"


def _build_curl_script(
    *,
    method: str,
    url: str,
    headers: dict[str, str],
    body: str,
    timeout: int,
) -> str:
    """
    用 curl + tee 拆分 status / headers / body，便于回来解析。
    输出格式（行分隔）：
        __PROBE_STATUS__:<http_code>
        __PROBE_HEADERS_BEGIN__
        <headers raw>
        __PROBE_HEADERS_END__
        __PROBE_BODY_BEGIN__
        <body>
        __PROBE_BODY_END__
    """
    parts = [
        "set +e",
        "TMP_H=$(mktemp); TMP_B=$(mktemp)",
        "trap 'rm -f \"$TMP_H\" \"$TMP_B\"' EXIT",
    ]

    cmd = [
        "curl", "-sS", "-i" if False else "",  # we capture headers via -D
        "-o", '"$TMP_B"',
        "-D", '"$TMP_H"',
        "-w", '"%{http_code}"',
        "--max-time", str(timeout),
        "-X", method,
    ]
    cmd = [c for c in cmd if c]

    for hk, hv in (headers or {}).items():
        cmd.extend(["-H", _shell_quote(f"{hk}: {hv}")])

    if body and method in ("POST", "PUT", "PATCH"):
        cmd.extend(["--data-binary", _shell_quote(body)])

    cmd.append(_shell_quote(url))

    parts.append("CODE=$(" + " ".join(cmd) + ")")
    parts.append('echo "__PROBE_STATUS__:${CODE:-000}"')
    parts.append('echo "__PROBE_HEADERS_BEGIN__"')
    parts.append('head -c 2048 "$TMP_H" | tr -d "\\r"')
    parts.append('echo ""')
    parts.append('echo "__PROBE_HEADERS_END__"')
    parts.append('echo "__PROBE_BODY_BEGIN__"')
    parts.append('head -c 4096 "$TMP_B"')
    parts.append('echo ""')
    parts.append('echo "__PROBE_BODY_END__"')

    return "\n".join(parts)


_STATUS_RE = re.compile(r"__PROBE_STATUS__:(\d{3})", re.M)


def _parse_curl_output(raw: str) -> tuple[int, str, str]:
    """从 _build_curl_script 的输出里抽出 status_code / headers / body。"""
    if not raw:
        return 0, "", ""

    m = _STATUS_RE.search(raw)
    status = int(m.group(1)) if m else 0

    headers = _slice_between(raw, "__PROBE_HEADERS_BEGIN__", "__PROBE_HEADERS_END__")
    body = _slice_between(raw, "__PROBE_BODY_BEGIN__", "__PROBE_BODY_END__")
    return status, headers, body


def _slice_between(text: str, begin: str, end: str) -> str:
    bi = text.find(begin)
    if bi < 0:
        return ""
    bi += len(begin)
    ei = text.find(end, bi)
    if ei < 0:
        return text[bi:]
    return text[bi:ei]


def _evaluate_success(success_signs: dict, status_code: int, headers: str, body: str) -> bool:
    """判定探针是否命中。"""
    if not success_signs:
        return False

    headers_lower = (headers or "").lower()
    body_lower = (body or "").lower()
    combined_lower = headers_lower + "\n" + body_lower

    # 1. status_codes
    status_codes = success_signs.get("status_codes") or []
    if status_codes:
        if status_code not in status_codes:
            return False

    # 2. body_contains_any
    body_any = success_signs.get("body_contains_any") or []
    if body_any:
        if not any(sub.lower() in body_lower for sub in body_any):
            return False

    # 3. body_contains_all
    body_all = success_signs.get("body_contains_all") or []
    if body_all:
        if not all(sub.lower() in body_lower for sub in body_all):
            return False

    # 4. header_contains: list of [name, substring]
    header_contains = success_signs.get("header_contains") or []
    for item in header_contains:
        if not isinstance(item, (list, tuple)) or len(item) < 2:
            continue
        name, sub = str(item[0]).lower(), str(item[1]).lower()
        # 匹配 "set-cookie: rememberMe=deleteMe" 风格
        if not _header_contains(headers_lower, name, sub):
            return False

    # 5. regex
    pat = success_signs.get("regex") or ""
    if pat:
        try:
            if not re.search(pat, combined_lower, re.IGNORECASE | re.M):
                return False
        except re.error:
            return False

    # 至少有一条规则被检验过才算成功
    has_rule = any([
        status_codes, body_any, body_all, header_contains, pat,
    ])
    return bool(has_rule)


def _header_contains(headers_lower: str, name_lower: str, sub_lower: str) -> bool:
    """检查 headers 文本里是否有  'name: ...sub...' 行。"""
    for line in headers_lower.splitlines():
        if ":" not in line:
            continue
        hname, _, hval = line.partition(":")
        if hname.strip() == name_lower and sub_lower in hval:
            return True
    return False


def _extract_evidence(headers: str, body: str, *, max_chars: int = 300) -> str:
    """从命中响应里抽出一段简短证据文本。"""
    h = (headers or "").strip()[:max_chars // 2]
    b = (body or "").strip()[:max_chars - len(h) - 8]
    if h and b:
        return f"{h}\n---\n{b}"
    return h or b


# ── orchestrator 适配辅助：把 PentestState 端口转 ProbeTarget ──

def build_probe_targets_from_ports(
    *, host: str, ports: list, scheme_for_port: Optional[Callable[[int], str]] = None
) -> list[ProbeTarget]:
    """
    从 (port_obj_with .port .service .version) 构造 ProbeTarget 列表。

    只挑 web/HTTP 类端口，其他协议探针由各自 probe 的 ports 字段筛选。
    """
    if not host or not ports:
        return []

    targets: list[ProbeTarget] = []
    seen: set[int] = set()
    for p in ports:
        port = getattr(p, "port", None) if not isinstance(p, int) else p
        service = getattr(p, "service", "") if not isinstance(p, int) else ""
        if not isinstance(port, int):
            continue
        if port in seen:
            continue
        is_web = (
            port in DEFAULT_WEB_PORTS
            or "http" in (service or "").lower()
        )
        if not is_web:
            continue
        seen.add(port)

        if scheme_for_port:
            scheme = scheme_for_port(port)
        else:
            scheme = "https" if port in (443, 8443) else "http"

        targets.append(ProbeTarget(
            base_url=f"{scheme}://{host}:{port}",
            host=host,
            port=port,
            scheme=scheme,
        ))

    return targets
