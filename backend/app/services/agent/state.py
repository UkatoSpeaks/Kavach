"""Typed state and per-request context for the analysis graph."""

from dataclasses import dataclass
from typing import Annotated, TypedDict

from app.core.config import Settings
from app.schemas.entities import ExtractedEntities
from app.services.agent.llm import Reasoner
from app.services.pipeline import Checks, Narrative, PipelineOutput
from app.services.rules import RuleResult
from app.services.scoring import SignalOutcome
from app.services.screenshot import ScreenshotContext


def merge_latency(left: dict[str, float], right: dict[str, float]) -> dict[str, float]:
    """Reducer: each node adds its own timings."""
    return {**left, **right}


class AnalysisState(TypedDict, total=False):
    # input
    text: str
    message_text: bool  # False for bare URL/UPI/QR payloads
    language_hint: str | None
    explain: bool  # False: skip the LLM step entirely (?explain=false)
    screenshot: ScreenshotContext | None  # sender etc. seen by OCR; None for other inputs
    # extract
    entities: ExtractedEntities
    rule_result: RuleResult
    # run_checks
    outcomes: list[SignalOutcome]
    # reason
    llm_outcome: SignalOutcome
    narrative: Narrative | None
    # finalize
    output: PipelineOutput
    latency_ms: Annotated[dict[str, float], merge_latency]


@dataclass(frozen=True)
class AnalysisContext:
    """Per-request dependencies, passed to the compiled graph at invoke time."""

    settings: Settings
    checks: Checks | None = None  # None: only the pure layers run
    reasoner: Reasoner | None = None  # None: the LLM signal is reported unavailable
