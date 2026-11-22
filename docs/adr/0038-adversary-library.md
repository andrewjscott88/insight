# ADR 0038: Adversary library imports

Status: Proposed. TIP 4.7 is reviewed in three parts.

## Part 3: timeline and Navigator decisions

- Reuse the pinned library, existing reports, packages and sightings. Never infer attribution or
  actor/campaign associations from shared reports, indicators, software or techniques.
- Add explicit `ActorCampaign` decisions with notes, caller/instance TLP enforcement, audit identity and
  deterministic uniqueness. Raise the campaign's label to its association floor and retain it after removal.
  Add `Campaign.updated_at`, backfilled to creation time, so label raises are visible to TAXII polling.
- Timeline event DTOs record source, date meaning, relation and effective label. Every stored read filters
  before aggregation. Existing guides consume the same service; guide format 1 gets an additive timeline.
  Reports use current revisions; sightings require accepted indicators in current explicit report links.
- Use only known current package publication/retirement timestamps. Do not reconstruct earlier cycles from
  unrelated audit records or imply complete historical coverage. Invalid dates are omitted, never invented.
- Bound all source reads and the final result. A conservative truncation flag does not expose hidden counts.
  Catalog/analyst group references are distinct; no name-based identity merge occurs.
- Software Navigator is a pure projection of explicit catalog software techniques. Actor layers add
  software-only techniques at score zero, with source comments, without modifying existing scores, direct
  group techniques or hunt hypotheses. Visible explicit analyst/software links also contribute context and
  their labels enter the guide envelope. Legacy software records remain valid with empty context.
- No new dependency, external fetch, provider job, model call or deployment setting is added.

Part 1 catalog and part 2 software-link/export decisions are maintained by their separate changes and must
be preserved when these parts are integrated. Full item completion requires all three parts and their gates.
