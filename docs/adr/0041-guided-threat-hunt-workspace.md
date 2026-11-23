# 0041. Guided threat hunt workspace

Status: Proposed.

## Context

Readers need a direct path from a threat they care about to a plan their team can review. A menu led by
internal workflow terms made the existing intelligence harder to use. The brief also placed report volume
and severity numbers ahead of their meaning. This is a presentation and planning enhancement to existing
capabilities, not a new telemetry-hunting engine or a newly completed TIP milestone.

## Decision

Open the workspace on **Intel Brief**. Lead with known exploited products or reported threat themes, explain
source-stated effects in plain language, and retain exact CVE and severity details in the evidence sections.
Keep the existing date rules, 7/30-day choices and separate last-24-hour receipt count. No model writes text.

Replace the Products menu entry with **Threat Hunt**. It contains an on-demand guide builder, existing hunt
packages and an expandable **Saved intelligence reports** area for the existing products. Move requirements
to **Settings → Intelligence questions (advanced)** without removing their APIs or cross-links. Keep Share's
other export and integration controls.

`services/hunt_guides.py` and `hunt_guide_subjects.py` gather visible evidence for eight starting kinds:
`theme`, `actor`, `cve`, `document`, `exploit`, `software`, `indicator` and `campaign`. Pure `hunt_guide_plan.py`
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

Guide generation is read-only except for actor-attributed `hunt.guide` audit entries for previews and API
formats. It creates no persistent guide, package, product, finding or attribution. It makes no network call,
queries no organisational telemetry and runs no rule or exploit. A download is rebuilt from then-current
visible data, rather than an immutable copy of the earlier preview.

## Consequences and validation

Readers get a bounded plan they must tailor and use in another tool. Existing products, requirements, hunt
packages and their APIs remain available. Generated guidance is distinct from published intelligence and
from an executed hunt. An imported bulletin is a possible starting report; no new publisher feed is implied.

Regression coverage includes every kind, explicit-link boundaries, metadata-only output, hidden/missing
equivalence, instance and API-key ceilings, planted AMBER records in the central GREEN sweep, audit actors,
bounded choices/output, Markdown escaping/defanging, PDF handling labels and mobile layout. The existing
brief date/count tests remain authoritative. Full quality gates and maintainer review remain required before
merge; this decision stays Proposed until accepted.
