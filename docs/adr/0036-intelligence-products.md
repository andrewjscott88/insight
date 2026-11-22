# ADR 0036: Finished intelligence products

Status: accepted (unreleased)

## Context
Insight's cases (TIP 3.8, [ADR 0029](0029-cases.md)) collect one investigation's reports, indicators, actors,
campaigns and notes, and close with a note. That is the shape of an incident, and TIP Phase 4 leaves incidents
and response to the tools Insight feeds. What an intelligence team delivers instead is a finished product:
the answer first, judgements with how likely they are and how sure the analyst is, the evidence behind them,
and what is still unknown, issued under a label no lower than the strictest source cited. Leading platforms
(EclecticIQ, OpenCTI) treat reports and analyses this way. TIP 4.4 is required for 1.0.

Constraints: TLP per reader everywhere (ADR 0013, 0014); one audit log; nothing written by a model; the
released `/api/cases` routes keep working; no new dependency.

## Decision
1. **A case becomes a product.** The workspace section is now **Products**; the API keeps `/api/cases`
   (released in 0.9.0). Migration 0028 adds a product type (`assessment`, `alert`, `profile`, `summary`), an
   audience, a bottom line up front (`bluf`), a version count and the latest publication time. The existing
   `summary` is the analysis (now up to 30,000 characters). Existing cases become unpublished assessments.
2. **Key judgements** (`case_judgements`): a statement, a likelihood from ICD 203's seven expressions
   (almost no chance, 1-5%, to almost certain, 95-99%), the analyst's confidence (low, moderate, high), an
   order, and the product's evidence that supports it (`case_judgement_items`, items of the same case only).
   At most 50.
3. **Intelligence gaps** (`case_gaps`): questions the product cannot answer yet. Asking one files a request for
   information (TIP 4.1) with the gap's label and links it to the gap; asking again returns the same request.
4. **Labels, as for cases.** Judgements and gaps are labelled like the product unless the caller says
   otherwise; TLP markings in their text raise their label, and the product's with it. Removing one never
   lowers the product's label; an explicit change can, never below what remains. So a product's label is never
   below the strictest source, judgement or gap it holds.
5. **Publishing** stores the product exactly as it is (`case_versions`, the `insight-product-1` JSON shape) as
   the next version, with its label, time and author; the case stays open for the next version. It needs a
   bottom line up front and at least one key judgement, and every judgement must cite evidence (`409`
   otherwise). Readers see a version only within their limit. An archived (closed) case cannot be published.
6. **The product shape.** Title, kind, audience, label, version, the bottom line, judgements (with the numbers
   of the sources they cite), the analysis, gaps, and the sources: the evidence numbered in order, reports with
   their Admiralty grade (the source's reliability and the report's credibility, ADR 0033), indicators with
   their confidence scored from the reports within the product's label, actors and campaigns by name.
   Working notes are never part of a product.
7. **Exports**, of the draft or of a version: Markdown with the label first and last (all text escaped, as for
   threat guides), and a validated STIX 2.1 bundle: a `report` (title, bottom line and analysis; cited reports
   only as external references, never their text), a `note` per key judgement (STIX `confidence` 15, 50 or 85
   for low, moderate or high, as in STIX 2.1 Appendix A; the ICD 203 likelihood in its abstract and
   `x_insight_likelihood`; `object_refs` the report and the cited objects) and per gap, and an object per cited
   indicator, CVE, actor or campaign. A published version's STIX IDs are derived from the product, version and
   item, so they are the same on every export; a draft's are new each time. Every export is audited.
8. **Not built yet.** PDF export (TIP 4.4b, next), review and approval before publishing, distribution lists,
   and linking a product to the requirements it answers.

## Consequences
- An analyst writes the product where the evidence is, and every issued version can be shown exactly as it
  went out, with its label and author.
- Estimative language and confidence are structured, so exports and other tools can read them.
- The API name (`cases`) and the workspace name (Products) differ; the API reference says so.
