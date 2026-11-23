# Censys infrastructure context

Censys can show which services, host names and network details it observed for an IP address. This is
optional context. It does not change an indicator verdict, run a scan or add intelligence on its own.

1. Use a Censys account whose terms allow your purpose. API requests can consume credits.
2. Set `INSIGHT_CENSYS_PAT` on the Insight host. Add `INSIGHT_CENSYS_ORG_ID` for your organization account;
   it is optional for an individual account. Use the Platform personal access token, not a Legacy Search key.
3. Restart Insight. Settings shows whether the host configuration is ready, without showing any token.
4. Use private sign-in. Censys reads and lookups are unavailable while temporary open access is on.
5. In **Investigate → Indicators**, expand a public IPv4 or IPv6 address with an accepted observation in a
   current TLP:CLEAR report. Open **Censys infrastructure context** and approve sending that address.

The answer shows up to 100 services and 20 host names, the announcing network and country code. The date
beside a service is Censys's observation time; the fetched date is when Insight received it. The address
can have changed since it was observed. No accessible record does not establish that an address is unused.

Insight reuses answers for 24 hours, rechecks the supporting review decision on each read, and audits new
requests and cache reuse. A failed request does not erase an earlier cached answer. Provider errors name
token, access or throttle problems without showing provider error text or credentials. No lookup runs on
a schedule, in a bulk batch, or when you open a page.

Only one approved address leaves Insight. No report text is sent. Contact details, banners and raw protocol
data are not stored. Censys data remains private context and is excluded from intelligence exports,
STIX/TAXII, MCP, hunt packages and briefs. Keep within the terms of your account; a CLEAR source indicator
does not make provider data free to redistribute.

[API setup](https://docs.censys.com/reference/get-started) ·
[General terms](https://censys.com/terms-of-service/) ·
[Starter terms](https://censys.com/self-service-subscription-terms-of-service/) ·
[Design and limits](adr/0043-censys-platform-enrichment.md)
