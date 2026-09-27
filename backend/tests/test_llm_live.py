"""The real Groq API. Deselected by default (uses quota); run with `pytest -m llm`."""

import re

import pytest

from app.core.config import get_settings
from app.services.agent.llm import GroqReasoner
from tests.examples import SCAM_EXAMPLES
from tests.test_llm import INJECTION, evidence_for

pytestmark = pytest.mark.llm


@pytest.fixture
def reasoner() -> GroqReasoner:
    s = get_settings()
    if not s.GROQ_API_KEY:
        pytest.skip("GROQ_API_KEY is not set")
    return GroqReasoner(
        s.GROQ_API_KEY,
        s.GROQ_MODEL,
        s.GROQ_FALLBACK_MODEL,
        s.LLM_TIMEOUT_S,
        reasoning_effort=s.GROQ_REASONING_EFFORT,
    )


@pytest.mark.parametrize("text", [SCAM_EXAMPLES[0][1], INJECTION], ids=["pin-scam", "injection"])
async def test_real_groq_explains_a_scam(reasoner: GroqReasoner, text: str) -> None:
    evidence = evidence_for(text)
    result = await reasoner.reason(evidence)
    a = result.assessment
    assert a is not None, result.detail
    assert a.llm_risk >= 50, a
    assert set(a.cited_flags) <= evidence.flag_codes
    assert re.search(r"[ऀ-ॿ]", a.explanation_hi)
    assert 3 <= len(a.advice) <= 5
