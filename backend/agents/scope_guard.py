"""Runtime scope enforcement — checks command targets against authorized scope."""
from __future__ import annotations

import ipaddress
import logging
import re
from urllib.parse import urlparse

logger = logging.getLogger(__name__)

_IPV4_PATTERN = re.compile(r'\b(?:\d{1,3}\.){3}\d{1,3}\b')
_HOST_PORT_PATTERN = re.compile(r'[\w.-]+\.[\w.-]+:\d{1,5}')
_HOSTNAME_PATTERN = re.compile(r'(?<![A-Za-z0-9_.-])([A-Za-z0-9][A-Za-z0-9_.-]*\.)+[A-Za-z]{2,}(?![A-Za-z0-9_.-]|[:\d])')
_URL_PATTERN = re.compile(r'(?:https?|ftp|ssh|telnet|ldaps?|smb|winrm|rdp)://[^\s\'"]+')

EXCLUDED_PATTERNS = (
    "0.0.0.0",
    "127.0.0.1",
    "localhost",
    "255.255.255.255",
)


def _is_excluded(target: str) -> bool:
    low = target.lower().strip()
    for pat in EXCLUDED_PATTERNS:
        if low == pat or low.startswith(pat):
            return True
    return False


def _looks_like_ip(text: str) -> bool:
    try:
        ipaddress.IPv4Address(text)
        return True
    except ValueError:
        return False


_IP_IN_URL_RE = re.compile(r'(?:https?|ftp|ssh)://(\[[^\]]+\]|[^/:]+)(?::(\d+))?(/[^\s\'"]*)?')


def extract_targets_from_command(cmd: str) -> list[str]:
    if not cmd:
        return []
    found: list[str] = []

    for match in _IP_IN_URL_RE.finditer(cmd):
        host = match.group(1)
        if host and not _is_excluded(host):
            found.append(host)

    for match in _IPV4_PATTERN.finditer(cmd):
        ip_str = match.group(0)
        if not _is_excluded(ip_str) and ip_str not in found:
            found.append(ip_str)

    for match in _HOSTNAME_PATTERN.finditer(cmd):
        host = match.group(0).rstrip(".")
        if not _is_excluded(host) and host not in found and not _looks_like_ip(host):
            found.append(host)

    for match in _HOST_PORT_PATTERN.finditer(cmd):
        host_part = match.group(0)
        host = host_part.rsplit(":", 1)[0] if ":" in host_part else host_part
        if not _is_excluded(host) and host not in found:
            found.append(host)

    return found


def is_in_scope(target: str, scope: list[str]) -> bool:
    if not scope:
        return True
    if not target:
        return True

    target = target.strip()
    if not target:
        return True

    for scope_entry in scope:
        scope_entry = scope_entry.strip()
        if not scope_entry:
            continue

        try:
            if re.match(r'^\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}/\d{1,2}$', scope_entry):
                net = ipaddress.IPv4Network(scope_entry, strict=False)
                try:
                    addr = ipaddress.IPv4Address(target)
                    if addr in net:
                        return True
                except ValueError:
                    try:
                        import socket
                        resolved = socket.gethostbyname(target)
                        addr = ipaddress.IPv4Address(resolved)
                        if addr in net:
                            return True
                    except Exception:
                        pass
                continue
        except Exception:
            pass

        target_lower = target.lower()
        scope_lower = scope_entry.lower()

        if target_lower == scope_lower:
            return True

        if scope_lower.endswith(".*") or scope_lower.endswith(".+") or scope_lower.endswith(".?"):
            prefix = scope_lower.rstrip(".*+?")
            if target_lower.startswith(prefix + ".") or target_lower == prefix:
                return True

        if "." in scope_lower and target_lower.endswith("." + scope_lower):
            return True

        if (target_lower.endswith("." + scope_lower + ".")
                or ("." + scope_lower + ".") in target_lower):
            return True

        if scope_lower == "private":
            try:
                addr = ipaddress.IPv4Address(target)
                if addr.is_private:
                    return True
            except ValueError:
                pass

    return False


def check_scope(cmd: str, scope: list[str]) -> tuple[bool, str]:
    if not scope:
        return (True, "")
    targets = extract_targets_from_command(cmd)
    for t in targets:
        if not is_in_scope(t, scope):
            return (False, f"命令目标 {t} 不在授权范围 {scope} 内")
    return (True, "")
