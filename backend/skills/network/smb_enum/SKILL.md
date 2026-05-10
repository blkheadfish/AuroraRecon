---
name: smb-enumeration-exploitation
description: Enumerates and exploits SMB services on ports 445/139 through null sessions, anonymous access, share enumeration, credential spraying, and known CVEs (EternalBlue CVE-2017-0144).
skill_type: exploit
severity: critical
tags: [smb, samba, netbios, eternalblue, enumeration, credential-spray]
---

# SMB Enumeration and Exploitation

## Essential Principles

1. SMB (Server Message Block) on ports 445/139 can expose shares, users, and system info
2. Null sessions allow unauthenticated enumeration of users, shares, and OS information
3. Anonymous access to writable shares can lead to file upload (malware, webshells)
4. EternalBlue (CVE-2017-0144) enables RCE on unpatched Windows systems
5. Tools: enum4linux-ng, smbmap, netexec (crackmapexec)

## When to Use

- Port 445 or 139 is open
- Windows or Samba-based file sharing detected
- Need to enumerate users, shares, or OS details for lateral movement

## When NOT to Use

- SMB is not accessible (filtered/blocked)
- Target is a domain controller in a monitored environment (may trigger alerts)

## Path Selection

| Condition | Path | Description |
|-----------|------|-------------|
| smb_readable_shares | smb_anon_access | List and read accessible anonymous shares |
| Always available | smb_cred_spray | Credential spray with common passwords |

## Quick Start

```bash
# Full enumeration
enum4linux-ng -A TARGET_IP

# Share mapping
smbmap -H TARGET_IP

# Null session shares
netexec smb TARGET_IP -u '' -p '' --shares
```
