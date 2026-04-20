from __future__ import annotations

import re
from dataclasses import dataclass
from typing import Any

from backend.agents.fact_hooks import canonical_command_hash, is_lfi_reprobe_command


@dataclass
class GuardDecision:
    allowed: bool
    reason: str = ""
    code: str = ""


class NoReprobeGuard:
    """Block redundant probes and repeated failed commands."""

    _SSH_SCAN_RE = re.compile(r"\bnmap\b.*\b-p\b.*\b22\b|\bnmap\b.*\bssh\b", re.IGNORECASE)
    _LFI_PARAM_ENUM_RE = re.compile(
        r"(page|file|include|path|image|content|template|doc|folder|view)\s*=",
        re.IGNORECASE,
    )

    def evaluate(
        self,
        command: str,
        *,
        confirmed_facts: dict[str, Any] | None = None,
        failed_commands: list[str] | None = None,
    ) -> GuardDecision:
        cmd = (command or "").strip()
        if not cmd:
            return GuardDecision(False, "empty command", "empty_command")

        confirmed = confirmed_facts or {}
        lfi = confirmed.get("lfi") or {}
        services = confirmed.get("services") or {}

        if services.get("ssh_port") and self._SSH_SCAN_RE.search(cmd):
            return GuardDecision(
                False,
                f"ssh_port already confirmed={services.get('ssh_port')}, skip redundant scan",
                "ssh_port_already_known",
            )

        if lfi.get("param") and lfi.get("depth"):
            if is_lfi_reprobe_command(cmd):
                return GuardDecision(
                    False,
                    "lfi param/depth already confirmed, reprobe loop blocked",
                    "lfi_reprobe_blocked",
                )
            if self._LFI_PARAM_ENUM_RE.search(cmd) and "seq" in cmd:
                return GuardDecision(
                    False,
                    "lfi parameter/depth enumeration blocked by guard",
                    "lfi_enum_blocked",
                )

        failed = failed_commands or []
        if failed:
            current_hash = canonical_command_hash(cmd)
            failed_hashes = {canonical_command_hash(c) for c in failed}
            if current_hash in failed_hashes:
                return GuardDecision(
                    False,
                    "command semantically matches a previous failed attempt",
                    "repeat_failed_command",
                )

        return GuardDecision(True)
