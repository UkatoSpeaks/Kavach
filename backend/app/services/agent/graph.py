"""The analysis agent: a LangGraph StateGraph over the pipeline steps.

    extract -> run_checks (+ screenshot signals) -> reason (LLM) -> finalize
                         \\-------------------^   (?explain=false skips the LLM)

The graph is compiled once per process (get_graph) and shared; per-request dependencies
(settings, network checks, the LLM reasoner) are passed as the runtime context.
"""

import time
from dataclasses import replace
from functools import lru_cache
from typing import Any, Literal

from langgraph.graph import END, START, StateGraph
from langgraph.graph.state import CompiledStateGraph

from app.core.config import Settings
from app.services.agent import nodes
from app.services.agent.llm import Reasoner
from app.services.agent.state import AnalysisContext, AnalysisState
from app.services.pipeline import Checks, PipelineOutput
from app.services.screenshot import ScreenshotContext

AnalysisGraph = CompiledStateGraph[AnalysisState, AnalysisContext, Any, Any]


def _after_checks(state: AnalysisState) -> Literal["reason", "finalize"]:
    return "reason" if state.get("explain", True) else "finalize"


def build_graph() -> AnalysisGraph:
    g = StateGraph(AnalysisState, context_schema=AnalysisContext)
    g.add_node("extract", nodes.extract)
    g.add_node("run_checks", nodes.run_checks)
    g.add_node("reason", nodes.reason)
    g.add_node("finalize", nodes.finalize)
    g.add_edge(START, "extract")
    g.add_edge("extract", "run_checks")
    g.add_conditional_edges("run_checks", _after_checks, ["reason", "finalize"])
    g.add_edge("reason", "finalize")
    g.add_edge("finalize", END)
    return g.compile()


@lru_cache(maxsize=1)
def get_graph() -> AnalysisGraph:
    """The process-wide compiled graph (compiled on first use, i.e. at app startup)."""
    return build_graph()


async def run_analysis(
    text: str,
    settings: Settings,
    *,
    checks: Checks | None,
    reasoner: Reasoner | None,
    language_hint: str | None = None,
    message_text: bool = True,
    explain: bool = True,
    graph: AnalysisGraph | None = None,
    screenshot: ScreenshotContext | None = None,
) -> PipelineOutput:
    start = time.perf_counter()
    state = await (graph or get_graph()).ainvoke(
        {
            "text": text,
            "message_text": message_text,
            "language_hint": language_hint,
            "explain": explain,
            "screenshot": screenshot,
            "latency_ms": {},
        },
        context=AnalysisContext(settings=settings, checks=checks, reasoner=reasoner),
    )
    latency = {**state["latency_ms"], "total": round((time.perf_counter() - start) * 1000, 2)}
    return replace(state["output"], latency_ms=latency)
