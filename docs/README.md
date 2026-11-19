# Insight documentation

| I want to… | Read |
| --- | --- |
| Install and try it | [README](../README.md) |
| Run, back up, upgrade or troubleshoot it | [RUNBOOK](RUNBOOK.md), or `make help` ([Makefile](../Makefile)) |
| Publish it on the internet (reverse proxy, MFA, TLP limit) | [RUNBOOK](RUNBOOK.md) ("Reverse proxy", "Sign-in second factor"), then the checklist in [SECURITY](SECURITY.md) |
| Understand the design (including the API's auth, rate-limit and TLP pipeline) | [ARCHITECTURE](ARCHITECTURE.md), [decision records](adr/README.md) |
| Script against it (API key, `curl` for every call, SIEM recipes) | [API_GUIDE](API_GUIDE.md), then [API](API.md) for every field |
| Export indicators (IOCs) to share, block or hunt | [IOC_EXPORT](IOC_EXPORT.md), [schema](schemas/insight-ioc-v1.schema.json), [example](examples/insight-iocs-example.json) |
| Know what indicators it extracts and how well | [EXTRACTION](EXTRACTION.md) |
| Judge its security posture | [SECURITY](SECURITY.md), [reporting a vulnerability](../SECURITY.md) |
| Contribute | [CONTRIBUTING](../CONTRIBUTING.md), [TESTING](TESTING.md) |
| Cut a release or understand the pipeline | [RELEASING](RELEASING.md), [CI_CD](CI_CD.md) |
| See what a release was validated against | [VALIDATION](VALIDATION.md), [CHANGELOG](../CHANGELOG.md) |
| Plan LLM features | [LLM_EXTENSION](LLM_EXTENSION.md) |
