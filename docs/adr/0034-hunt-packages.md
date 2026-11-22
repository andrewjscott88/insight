# ADR 0034: Hunt packages over TAXII

Status: accepted (unreleased)

## Context
Insight feeds hunt tools (the maintainer's is Shift) but does not hunt itself: TIP Phase 4 draws the line at
the organisation's own telemetry. Since TIP 2.10 Insight has kept hunt *records* (checks and results per
technique), which is the hunt tool's job, and it had no way to hand a hunt tool what it needs: the idea to
test, the ATT&CK techniques, the indicators and the detection rules, as one unit, over an open standard. Its
rule library held YARA and Sigma only, so network rules (Suricata, Snort) could not travel with a hunt. TIP
4.3 is required for 1.0.

Constraints: TLP per reader everywhere (ADR 0013, 0014); one audit log; nothing written by a model; TAXII
stays read-only (ADR 0026); STIX 2.1 validated before it leaves; no new dependency.

## Decision
1. **Hunt packages** (migration 0026). `hunt_packages` holds a title, a hypothesis (what to look for and
   why), an optional threat group (an ATT&CK group ID or an analyst actor), a status, a label and a
   publication counter. `hunt_package_items` holds ATT&CK techniques, indicators, detection rules and reports,
   one target per row; deleting a rule, report or indicator removes its items, after marking the package
   changed so hunt tools get a new version.
2. **Labels, as for cases** (ADR 0029). A package takes the most restrictive label of its text (TLP markings
   included), its group and every item ever added. Removing an item never lowers it; an explicit change can,
   but never below what remains. Readers and API keys see a package only within their limit.
3. **Status.** `draft` packages are not served. `published` ones are served in a new, fixed TAXII collection,
   *Hunt packages* (`9d3f6b1a-2c4e-4a7b-8e5d-1f0a3c6b9e27`), and every change goes out as a new version.
   `retired` packages are served once more with every object `revoked`, so hunt tools learn the hypothesis no
   longer applies; they refuse changes until published again. STIX forbids new versions of a revoked object,
   so publishing a retired package again gives every object a new ID (the `publication` counter is part of
   each ID). A published package cannot be deleted (retire it first) and keeps at least one technique,
   indicator or rule.
4. **STIX projection.** One `grouping` per package (context `suspicious-activity`, description the
   hypothesis); an `attack-pattern` per technique; an `indicator` (STIX pattern) or `vulnerability` (CVE) per
   indicator; an `indicator` per rule with the rule text as `pattern` and `pattern_type` `sigma`, `yara`,
   `suricata` or `snort`; and an `indicates` relationship from a rule to a package technique it is linked to.
   The group and the reports are external references on the grouping: a report's own text never leaves in a
   package. Every object carries the package's TLP marking and its `modified` time. IDs are derived from the
   package, its publication and the item, so an item removed and added again is a new object. Packages are
   capped at 500 items, and a collection of more than 500 served packages is refused (`413`), not cut short.
5. **Rules.** Detection rules may be Suricata or Snort rules as well as YARA and Sigma. A light shape check
   (an action, then options with a numeric `sid`) catches pasting mistakes; rules are still never run.
6. **Interfaces.** `/api/hunt-packages` (list, create, read, change, delete, items, publish, retire, and a
   STIX download in any status, audited); **Hunt packages** in Share; **Add to hunt package** in the reader
   and the indicator explorer. Every change is audited (`hunt_package.*`).
7. **Hunt records stop growing.** The TIP 2.10 hunt records stay readable and writable, but get no new
   features: hunt tools record what they ran and found, and report sightings back (TIP 4.2b).

## Consequences
- A hunt tool polls one TAXII collection and gets ready-to-run hypotheses with their rules and indicators,
  within its key's TLP limit, without an Insight-specific integration.
- A package may include an indicator that review later rejects; the analyst chose it, and can remove it.
- Deleting a rule, report or indicator removes it from every package. If that leaves a published package with
  nothing to hunt for, it stops being served; retire it, so hunt tools are told.
- Every change to a package re-versions all of its objects. Packages are small, so this stays cheap and
  keeps versions consistent.
