# Insight documentation

| I want to… | Read |
| --- | --- |
| Install and try it | [README](../README.md) |
| Run, back up, upgrade or troubleshoot it | [RUNBOOK](RUNBOOK.md), or `make help` ([Makefile](../Makefile)) |
| Publish it on the internet (reverse proxy, MFA, TLP limit) | [RUNBOOK](RUNBOOK.md) ("Reverse proxy", "Sign-in second factor"), then the checklist in [SECURITY](SECURITY.md) |
| Understand the design (including the API's auth, rate-limit and TLP pipeline) | [ARCHITECTURE](ARCHITECTURE.md), [decision records](adr/README.md) |
| Script against it (API key, `curl` for every call, SIEM recipes) | [API_GUIDE](API_GUIDE.md), then [API](API.md) for every field |
| Export indicators (IOCs) to share, block or hunt | [IOC_EXPORT](IOC_EXPORT.md), [schema](schemas/insight-ioc-v1.schema.json), [example](examples/insight-iocs-example.json) |
| Let a SIEM or TIP poll reviewed indicators over TAXII 2.1 | [TAXII](TAXII.md) |
| Build and download a plan to use in a hunt tool | [THREAT_HUNT](THREAT_HUNT.md), [ADR 0041](adr/0041-guided-threat-hunt-workspace.md) |
| Understand the opening brief, reporting periods and sharing labels | [EXECUTIVE_BRIEF](EXECUTIVE_BRIEF.md) |
| See which groups target an industry, export a threat guide, plan a hunt | [THREAT_GUIDES](THREAT_GUIDES.md), [ADR 0025](adr/0025-threat-guides.md) |
| Know what indicators it extracts and how well | [EXTRACTION](EXTRACTION.md) |
| Judge its security posture | [SECURITY](SECURITY.md), [reporting a vulnerability](../SECURITY.md) |
| Contribute | [CONTRIBUTING](../CONTRIBUTING.md), [TESTING](TESTING.md) |
| Cut a release or understand the pipeline | [RELEASING](RELEASING.md), [CI_CD](CI_CD.md) |
| See what a release was validated against | [VALIDATION](VALIDATION.md), [CHANGELOG](../CHANGELOG.md) |
| See what is planned next | [ROADMAP](../ROADMAP.md), then the detailed plan in [ROADMAP-TIP](ROADMAP-TIP.md) |
| Plan LLM features | [LLM_EXTENSION](LLM_EXTENSION.md) |
