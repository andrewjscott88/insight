# Infrastructure pivots

## Certificate transparency (TIP 4.6 part 2)

In **Settings › Sources › Infrastructure lookups**, turn on **Use crt.sh** (off by default).
In **Investigate › Indicators**, open **Pivot** for a reviewed domain in a current TLP:CLEAR report.
Approve sending that domain to crt.sh. The lookup sends a wildcard domain query, never report text.
No scheduled or bulk queries run. Switch changes, outbound requests and saved answers are audited.

Answers, including no matches, are reused for 24 hours. Every cache read checks that the domain still
has accepted evidence in a current CLEAR report. The link map shows certificate names with provider and
fetch date; a known visible indicator is linked when its value matches. This context never creates an
indicator or observation and is not evidence of ownership or malicious activity.

Only names, issuer and validity dates are kept. Names are de-duplicated; for renewals the newest validity
start wins, with validity end and issuer as deterministic tie breakers. At most 500 names are returned.
Each result certificate must contain the requested domain or a subdomain; its other names remain useful
certificate context. An unrelated or malformed row rejects the entire answer, even after the output cap.
Certificates, serial numbers, raw subjects and contact details are not retained. A limited result is marked
`truncated`; crt.sh may also limit its search, so the result is not a complete history.

The only destination is `https://crt.sh/`, using its JSON search interface. Insight allows one request per
60 seconds across all callers, one in flight, with a 30-second overall timeout and a 2 MB response cap.
These are Insight limits, not a provider service guarantee. HTTP 429 adds the provider's bounded wait.
crt.sh can be slow or unavailable; errors are written by Insight without response bodies or request URLs,
and failures are not cached. HTTPS host allowlisting, checked public DNS addresses and no redirects apply.

Review the provider's current access and reuse conditions before enabling it. A public search interface is
not a blanket redistribution licence. Interface references, reviewed 22 November 2026:
[crt.sh JSON query support](https://github.com/crtsh/certwatch_db/issues/56) and
[crt.sh interface source](https://github.com/crtsh/certwatch_db/blob/master/fnc/web_apis.fnc).
No provider source code is copied and no dependency is added.

This independently reviewable part includes the shared switch, consent, cache, route and graph support.
Companion RDAP/ASN and passive DNS parts are separate; combining the branches must reconcile shared files.
It uses the existing `Enrichment` and `SourceSwitch` tables and needs no migration.
