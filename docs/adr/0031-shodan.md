# ADR 0031: Optional Shodan exposure context for reviewed IPs

Status: Accepted

## Context
TIP 3.7 asks for optional exposure context for IPs from Shodan or Censys, only with the operator's own key,
from allowlisted hosts, with no default schedule that spends credits, parser fixtures, and credit or quota
errors visible in the workspace. Insight already has one manual IP lookup with exactly these properties:
GreyNoise Community (reviewed public IPv4 in a current TLP:CLEAR report, explicit approval, cached, audited).

Shodan's host lookup (`GET /shodan/host/{ip}`) does not spend query credits; every API plan is limited to one
request per second; products may use the API if the data is attributed to Shodan. Censys is replacing its
Legacy Search API (deprecated in 2026) with the Platform API, which needs a personal access token and an
organisation ID, and its full host record spends credits.

## Decision
1. **Shodan only, for now.** A Shodan host lookup joins GreyNoise with the same rules: off without
   `INSIGHT_SHODAN_KEY`; never scheduled; only a reviewed public IPv4 in a current TLP:CLEAR report; the
   operator approves each uncached lookup in the workspace (or calls the API with a session or an unlimited
   read-write key); one request per second shared by every caller; answers, including "no record", reused for
   24 hours and rechecked for eligibility on every read; every lookup audited (`ip.lookup`, "Shodan").
   Censys is left until its Platform API settles; the cache and policy are shared, so adding it is a client
   module and its terms review.
2. **Metadata only.** Insight asks for the minified host record and keeps open ports (at most 100, with the
   total), host names, organisation, network, ASN, country, operating system, tags, the CVE IDs Shodan links
   to the host, and the last update date. Service banners and anything unexpected are dropped; an answer
   about another address is refused.
3. **The key stays secret.** Shodan takes the key as a URL parameter, so errors are written by Insight (never
   from the HTTP library, whose messages contain the URL) and a logging filter hides `key=` in httpx request
   logs, whoever configures logging.
4. **Refusals are visible.** HTTP 401 names the setting; 402 and 403 say the plan, credits or access do not
   allow the lookup; 429 waits as long as Shodan says (or a minute). The workspace shows these messages in the
   lookup dialog; nothing is cached for a refusal.
5. **Attribution.** The dialog and both API answers say the data comes from Shodan.

## Consequences
- Analysts can see an address's exposure (ports, CVEs Shodan infers from software versions) next to its
  reports, at their own cost and with their own key, without anything leaving Insight unasked.
- Shodan's CVE list is an inference from banners, labelled as such; it does not change a verdict.
- Pricing and plan limits are Shodan's: see their published plans. No prices are copied here.
