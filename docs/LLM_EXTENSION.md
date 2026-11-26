# LLM integration boundary (not planned)

LLM proposals (TIP 3.6) were taken off the roadmap on 26 November 2026: Insight writes nothing with a model.
This page stays as the boundary any future work would have to meet.

Keep the current deterministic pipeline authoritative for exact observable extraction. Future model output should be stored as a new proposal with provider/model/version, request timestamp, exact source spans, input document hash and analyst review state.

Suggested interface:

```python
from dataclasses import dataclass
from typing import Protocol


@dataclass(frozen=True)
class AnalysisRequest:
    document_id: str
    content_hash: str
    permitted_text: str
    tlp: str


@dataclass(frozen=True)
class ProposedClaim:
    text: str
    evidence_start: int
    evidence_end: int
    model_id: str


class AnalystAssistant(Protocol):
    async def propose(self, request: AnalysisRequest) -> list[ProposedClaim]: ...
```

This is a design contract, not a connected runtime plugin. Initially prefer a local endpoint. Before any external provider, require explicit policy-controlled data release, correct recipients/purpose, retention review and secret protection. Never silently send restricted reports to a model. Treat source text as untrusted data, never as tool instructions. Models should not execute tools or change analyst decisions.

Gate adoption with held-out reports measuring span correctness, unsupported claims, reviewer correction rate, prompt-injection resilience, and time saved. Do not present model confidence as a calibrated probability without evaluation.
