# Architecture decision records

Short records of significant decisions: context, decision, consequences. New decisions get the next number;
superseded ones are marked, never deleted.

| # | Decision | Status |
| --- | --- | --- |
| [0001](0001-alembic-migrations.md) | Alembic owns the schema; datetime columns deferred | Accepted |
| [0002](0002-login-delay-not-lockout.md) | Sign-in throttling by delay, not lockout | Accepted |
| [0003](0003-single-query-layer-and-ui-panels.md) | One query layer; UI split into panel modules | Accepted |
| [0004](0004-revisions-for-synced-items.md) | Publisher edits become revisions, never edits or duplicates | Accepted |
| [0005](0005-container-and-supply-chain.md) | Hardened container and hash-pinned supply chain | Accepted |
| [0006](0006-five-tier-pipeline.md) | Five-tier CI/CD; CD means publishing | Accepted |
| [0007](0007-extraction-precision-first.md) | Extraction: a wrong indicator is worse than a missed one | Accepted |
| [0008](0008-folded-search-text.md) | Search on a folded copy of the text | Accepted |
| [0009](0009-tlp-policy.md) | TLP: default AMBER; markings can only raise the label | Accepted |
| [0010](0010-known-defect-register.md) | Known defects as strict expected-failure tests | Accepted |
| [0011](0011-offsets-code-points-and-utf16.md) | Evidence offsets: code points, plus UTF-16 for JavaScript | Accepted |
