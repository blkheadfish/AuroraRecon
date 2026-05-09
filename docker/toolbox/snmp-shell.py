#!/usr/bin/env python3
"""snmp-shell -- read/walk/set SNMP OIDs against a target.

Non-interactive mode (default):
    python3 snmp-shell.py <host> [community] [port]
    → auto-walks the entire MIB tree from 1.3.6.1

Interactive mode is available when imported as a module.
"""
import sys
import cmd
from pysnmp.hlapi import *


class SnmpShell(cmd.Cmd):
    intro = "SNMP Shell — get <oid> | set <oid> <value> | walk <oid> | exit"
    prompt = "snmp> "

    def __init__(self, host, community="public", port=161):
        super().__init__()
        self.host = host
        self.community = community
        self.port = port

    def _get(self, oid):
        it = getCmd(
            SnmpEngine(),
            CommunityData(self.community),
            UdpTransportTarget((self.host, self.port)),
            ContextData(),
            ObjectType(ObjectIdentity(oid)),
        )
        _, _, _, varBinds = next(it)
        for vb in varBinds:
            print(f"{vb[0].prettyPrint()} = {vb[1].prettyPrint()}")

    def _walk(self, oid):
        for _, _, _, varBinds in nextCmd(
            SnmpEngine(),
            CommunityData(self.community),
            UdpTransportTarget((self.host, self.port)),
            ContextData(),
            ObjectType(ObjectIdentity(oid)),
            lexicographicMode=False,
        ):
            for vb in varBinds:
                print(f"{vb[0].prettyPrint()} = {vb[1].prettyPrint()}")

    def _set(self, oid, value):
        it = setCmd(
            SnmpEngine(),
            CommunityData(self.community),
            UdpTransportTarget((self.host, self.port)),
            ContextData(),
            ObjectType(ObjectIdentity(oid), OctetString(value)),
        )
        _, _, _, varBinds = next(it)
        for vb in varBinds:
            print(f"SET {vb[0].prettyPrint()} = {vb[1].prettyPrint()}")

    def do_get(self, arg):
        """get <oid>"""
        if not arg:
            print("Usage: get <oid>")
            return
        try:
            self._get(arg.strip())
        except Exception as e:
            print(f"ERROR: {e}")

    def do_walk(self, arg):
        """walk [oid]"""
        oid = arg.strip() or "1.3.6.1"
        try:
            self._walk(oid)
        except Exception as e:
            print(f"ERROR: {e}")

    def do_set(self, arg):
        """set <oid> <value>"""
        parts = arg.split(maxsplit=1)
        if len(parts) < 2:
            print("Usage: set <oid> <value>")
            return
        try:
            self._set(parts[0], parts[1])
        except Exception as e:
            print(f"ERROR: {e}")

    def do_exit(self, _):
        return True

    def do_quit(self, _):
        return True


if __name__ == "__main__":
    if len(sys.argv) < 2:
        print("Usage: snmp-shell.py <host> [community] [port]")
        sys.exit(1)
    host = sys.argv[1]
    community = sys.argv[2] if len(sys.argv) > 2 else "public"
    port = int(sys.argv[3]) if len(sys.argv) > 3 else 161
    try:
        shell = SnmpShell(host, community, port)
        shell.do_walk("1.3.6.1")
    except Exception as e:
        print(f"ERROR: {e}")
        sys.exit(1)
