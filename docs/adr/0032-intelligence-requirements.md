# ADR 0032: Intelligence requirements and requests for information

Status: accepted (unreleased)

## Context
Leading threat-intelligence platforms organise work around the questions the business needs answered:
priority intelligence requirements (PIRs), the narrower intelligence requirements (IRs) under them, and
requests for information (RFIs). Insight had watch terms, which only highlight words, and no way to show
which questions a report helps answer or which questions have gone quiet. TIP 4.1 (required for 1.0) adds
requirements, and lets a hunt or response tool (such as the maintainer's Shift) ask a question without being
able to change anything else.

Constraints: TLP per reader everywhere (ADR 0013, 0014); one audit log; nothing written by a model; Insight
records intelligence, never response actions (TIP Phase 4 boundary); no new dependency.

## Decision
1. **Three tables** (migration 0024). `requirements` holds the kind (`pir`, `ir` or `rfi`), the question, why it
   matters, who needs the answer, priority (`high`, `medium`, `low`), status (`open`, `answered`, `retired`),
   label, an optional due date, the current answer, and the requester's own reference. Only an IR has a parent,
   and its parent must be a PIR. `requirement_criteria` and `requirement_evidence` cascade with their
   requirement; evidence also cascades with its report.
2. **Criteria, matched on read.** A report addresses a requirement when it meets any criterion: a `term` in its
   folded text (the inbox search's matching), a `cve` it mentions unless review rejected the mention, an ATT&CK
   `technique` tagged on it, or an explicit link to a threat `group` or `campaign`. A catalog group and the
   analyst actors linked to it count as one group. Only current reports the reader may see count, and a link
   counts only when the reader may see the link itself. Nothing is stored per match, so coverage is always
   current and never reveals a hidden report. A requirement with criteria and no visible match in 30 days is
   **quiet**.
3. **TLP, as for cases (ADR 0029).** The label is the most restrictive of the text (question, context, answer),
   the criteria (an analyst's actor or campaign keeps its own label; a term's TLP markings count) and the cited
   reports. Removing a criterion or citation never lowers it; an explicit change can, but never below what
   remains. A reader sees a requirement only within its limit.
4. **Answers.** Answering an RFI marks it `answered`; a PIR or IR stays open and shows the answer as its latest
   assessment. A retired requirement refuses changes (`409`) until reopened. A PIR with IRs under it cannot be
   deleted.
5. **`read-rfi` API keys** (renamed `read-feedback` by [ADR 0035](0035-sightings.md), which also lets them
   send sightings). A new access level between `read` and `read-write`: GET requests, plus
   `POST /api/rfis` and nothing else. A hunt tool can file a question within its TLP limit and poll
   `GET /api/requirements/{id}` for the answer. It cannot answer, edit or ingest. `external_ref` carries the
   tool's own reference.
6. **Interfaces.** `/api/requirements` (list, create, read, change, delete, criteria, evidence, answer, retire,
   reopen), `/api/rfis`, `/api/documents/{id}/requirements`; a **Requirements** section second in the side menu;
   "Addresses your requirements" with **Cite as evidence** in the reader; an **Open requests** counter on Today.
   Every change is audited (`requirement.*`).
7. **Not built yet.** Alerts when a report addresses a high-priority requirement, requirement health over time,
   and suggested criteria. Watch terms stay as they are.

## Consequences
- Each report shows which questions it helps answer, and each question shows its evidence and whether
  collection has gone quiet.
- Coverage costs one query per criterion when read. Requirement lists are capped at 200 and a requirement at 50
  criteria, so this stays small for one team.
- A hunt tool gets the narrowest write access Insight has: filing a question.
