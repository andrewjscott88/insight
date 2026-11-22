# ADR 0029: Lightweight case management

Status: accepted (unreleased)

## Context
Analysts work an investigation across several reports, indicators, actors and campaigns, but Insight only
offered an inbox and per-object links. TIP 3.8 asks for a case that groups them with notes, shows a timeline,
closes with a note, and takes the most restrictive TLP of its items, without becoming a SOAR.

Constraints: TLP per reader everywhere (ADR 0013, 0014); one audit log (no second event store); deleting a
report, indicator, actor or campaign must not leave dangling references; no new dependency.

## Decision
1. **Two tables** (migration 0021). `cases` holds the title, summary, status (`open` or `closed`), label,
   close note and times. `case_items` holds one report, indicator, actor or campaign (a nullable foreign key
   for each, exactly one set) or a note. Each target's foreign key cascades, so deleting the target removes it
   from every case. Adding the same target twice changes nothing; a case holds at most 1,000 items.
2. **TLP.** An item is labelled at least as restrictively as its target: a report's label, an indicator's
   least restrictive visible report (the floor used for threat links), an actor's or campaign's label. A
   caller may only raise it. The case takes the most restrictive label of its items and of TLP markings in
   its title, summary, notes and close note. **Removing an item never lowers the case**, because the text may
   have been written with that item in view; an explicit change may lower it, but never below the items it
   still holds. A reader sees a case only within its limit, and then every item in it; a caller can only add
   what it can see and only store labels within its limit (the instance limit for the workspace).
3. **Timeline from the audit log.** Every change is an audit event on the case (`case.open`, `case.update`,
   `case.item.add`, `case.item.remove`, `case.note`, `case.close`, `case.reopen`, `case.delete`), with the
   actor. `GET /api/cases/{id}/timeline` lists them; nothing is stored twice.
4. **Closed means frozen.** A closed case refuses changes (`409`) until it is reopened; reopening keeps the
   close note.
5. **Interfaces.** `/api/cases` (list, create, read, change, delete, items, notes, close, reopen, timeline),
   a **Cases** tab, and **Add to case** in the reader and the entity explorer. Read-only API keys may read
   cases; read-write keys may change them within their limit.
6. **Not built.** No webhook when a case opens (the roadmap's optional item): alerts stay for news the
   operator has not seen, and a case is opened by the operator. No assignment, due dates or automation.

## Consequences
- An investigation has one place for its evidence and decisions, and its label is never weaker than what it
  holds.
- A case can stay more restrictive than its remaining items after removals; the operator lowers it on
  purpose.
- The timeline is as complete as the audit log; it is not append-only or tamper-evident (see SECURITY.md).
