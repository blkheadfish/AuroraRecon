"""Tests for runtime scope enforcement."""
from __future__ import annotations

import pytest

from backend.agents.models import PentestState
from backend.agents.scope_guard import (
    check_scope,
    extract_targets_from_command,
    is_in_scope,
)


class TestExtractTargets:
    def test_finds_ipv4(self):
        targets = extract_targets_from_command("nmap -sV 10.0.0.1")
        assert "10.0.0.1" in targets

    def test_finds_hostname_in_url(self):
        targets = extract_targets_from_command("curl http://example.com:8080/path")
        assert "example.com" in targets

    def test_excludes_localhost(self):
        targets = extract_targets_from_command("curl http://localhost:8080/test")
        assert all("localhost" not in t.lower() for t in targets)

    def test_excludes_zero_addr(self):
        targets = extract_targets_from_command("nc 0.0.0.0 4444")
        assert "0.0.0.0" not in targets

    def test_excludes_loopback(self):
        targets = extract_targets_from_command("ssh root@127.0.0.1")
        assert "127.0.0.1" not in targets

    def test_empty_command(self):
        assert extract_targets_from_command("") == []
        assert extract_targets_from_command(None) == []

    def test_plain_text_no_target(self):
        targets = extract_targets_from_command("whoami; id; pwd")
        assert targets == []


class TestIsInScope:
    def test_ip_in_cidr(self):
        assert is_in_scope("10.0.0.5", ["10.0.0.0/24"]) is True

    def test_ip_out_of_cidr(self):
        assert is_in_scope("10.0.1.5", ["10.0.0.0/24"]) is False

    def test_exact_host_match(self):
        assert is_in_scope("example.com", ["example.com"]) is True

    def test_host_not_in_scope(self):
        assert is_in_scope("evil.com", ["example.com"]) is False

    def test_empty_scope_allows_all(self):
        assert is_in_scope("8.8.8.8", []) is True

    def test_private_scope_keyword(self):
        assert is_in_scope("192.168.1.1", ["private"]) is True
        assert is_in_scope("10.0.0.1", ["private"]) is True
        assert is_in_scope("8.8.8.8", ["private"]) is False if not __import__("ipaddress").IPv4Address("8.8.8.8").is_private else True

    def test_wildcard_prefix_scope(self):
        scope = ["10.0.*"]
        assert is_in_scope("10.0.0.1", scope) is True

    def test_subdomain_parent_scope(self):
        assert is_in_scope("sub.example.com", ["example.com"]) is True


class TestCheckScope:
    def test_in_scope_passes(self):
        ok, reason = check_scope("nmap 10.0.0.5", ["10.0.0.0/24"])
        assert ok is True
        assert reason == ""

    def test_out_of_scope_blocks(self):
        ok, reason = check_scope("curl http://8.8.8.8/admin", ["10.0.0.0/24"])
        assert ok is False
        assert "8.8.8.8" in reason

    def test_command_with_no_targets_passes(self):
        ok, reason = check_scope("whoami && id", ["10.0.0.0/24"])
        assert ok is True

    def test_empty_scope_passes(self):
        ok, reason = check_scope("curl 8.8.8.8", [])
        assert ok is True


class TestPentestStateScopeFields:
    def test_authorized_scope_defaults_empty(self):
        state = PentestState()
        assert state.authorized_scope == []

    def test_scope_violations_defaults_empty(self):
        state = PentestState()
        assert state.scope_violations == []

    def test_can_set_authorized_scope(self):
        state = PentestState(authorized_scope=["10.0.0.0/24"])
        assert state.authorized_scope == ["10.0.0.0/24"]

    def test_can_append_violation(self):
        state = PentestState()
        state.scope_violations.append({
            "command": "nmap 8.8.8.8",
            "targets": ["8.8.8.8"],
            "ts": "2025-01-01T00:00:00",
        })
        assert len(state.scope_violations) == 1
