# 0041. Guided threat hunt workspace

Status: Accepted (1.0.0).

## Context

Readers need a direct path from a threat they care about to a plan their team can review. A menu led by
internal workflow terms made the existing intelligence harder to use. The brief also placed report volume
and severity numbers ahead of their meaning. This is a presentation and planning enhancement to existing
capabilities, not a new telemetry-hunting engine or a newly completed TIP milestone.

## Decision

Open the workspace on **Intel Brief**. Lead with known exploited products or reported threat themes, explain
source-stated effects in plain language, and retain exact CVE and severity details in the evidence sections.
Keep the existing date rules and 7/30-day choices. Remove the visible last-24-hour receipt section and
attention highlight; retain the existing `recent_reports` API field as compatibility metadata. No model
writes text.

Workspace explanations, brief summaries, report text and evidence fill their panels, as requested, rather
than stopping at a narrow reading column. This intentionally relaxes ADR 0017's 80-character line target
for those full-width workspace elements and expandable item labels; it is not a claim of full WCAG 1.4.8
compliance there. Bounded text such as dialog prose retains the line-length check. Browser checks still
require readable font size and line spacing, whole word wrapping, left alignment and no horizontal page
overflow, and now check that workspace prose uses its available width at standard and larger text sizes.

Replace the Products menu entry with **Threat Hunt**. It contains an on-demand guide builder, a collapsed
**Saved hunt packages** area and a separate **Advanced: intelligence reports** area for existing products.
Move requirements to **Settings → Intelligence questions (advanced)** without removing their APIs or
cross-links. Keep Share's other export and integration controls.

`services/hunt_guides.py`, `hunt_guide_subjects.py` and `hunt_guide_industries.py` gather visible evidence for
nine starting kinds: `theme`, `actor`, `cve`, `document`, `exploit`, `software`, `indicator`, `campaign` and
`industry` ([ADR 0045](0045-sector-threat-hunt-guides.md)). Pure `hunt_guide_plan.py`
supplies fixed planning steps and pinned-library source references. `hunt_guide.py` bounds the result and
renders Markdown or PDF through the existing PDF writer. The UI and authenticated GET routes share these
services. No new dependency, table or migration is needed.

Search filters choices before the 50-result cap. Plans use at most 20 current reports, 100 eligible reviewed
indicators and 12 techniques. Explicit campaign report/technique links supply context; other campaign links
are noted for review. Actor and software plans use explicit report links and catalog relationships. A theme
word match or shared indicator never establishes attribution. Parent-technique fallback is identified.

Use the stricter instance/caller TLP ceiling. Hidden subjects and missing subjects both return `404`.
Preserve the strictest contributing label, including metadata that affects truncation notices. Only metadata,
catalog context and fixed guidance leave in a guide: no publisher body, summary or analyst-note text. The
normal publisher terms still apply to source material. Plain audience badges retain the exact TLP token;
`Public · TLP:CLEAR` does not mean a work has no copyright. Unknown labels are not presented as public.

Guide previews and downloads are read-only except for actor-attributed `hunt.guide` audit entries. A download
is rebuilt from then-current visible data, rather than an immutable copy of the earlier preview.

Offer a separate **Save as hunt package** action after a guide is built. The service
`create_hunt_package_from_guide` creates an audited draft using the selected focus, generated guidance and
eligible facts, enforcing the same evidence and TLP boundaries. It rebuilds from currently visible evidence
at save time. The guidance becomes the hypothesis, capped at 10,000 characters with a shortening notice;
structured items retain the guide's technique, report and eligible-indicator caps. Only actor selections
set a group reference. Existing package audit events record creation and item writes;
`hunt_package.from_guide` records the starting kind and reference. Saving opens the draft editor. The button
then opens that saved package, preventing another save from the same built preview. Existing package
editing and publication remain explicit actions; **Start a blank package** remains available for manual
authoring. No guide action makes a network call, queries organisational telemetry, runs a rule or exploit,
or records a finding or inferred attribution.

## Consequences and validation

Readers get a bounded plan they must tailor and use in another tool. Existing products, requirements, hunt
packages and their APIs remain available. Generated guidance is distinct from published intelligence and
from an executed hunt. An imported bulletin is a possible starting report; no new publisher feed is implied.

Regression coverage includes every kind, explicit-link boundaries, metadata-only output, hidden/missing
equivalence, instance and API-key ceilings, planted AMBER records in the central GREEN sweep, audit actors,
bounded choices/output, Markdown escaping/defanging, PDF handling labels and mobile layout. The existing
brief date/count tests remain authoritative. Full quality gates and maintainer review remain required before
merge; this decision stays Proposed until accepted.
