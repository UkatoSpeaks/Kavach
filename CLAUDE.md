# Kavach — AI scam detector for Indian users

> Project name is a placeholder. Rename freely.

## What this is

A backend that analyzes suspicious messages, links, UPI IDs, QR codes and screenshots,
and returns an explainable scam verdict for Indian users. Differentiators:

1. A custom-trained Hinglish/Indian scam classifier with published metrics (precision, recall, F1).
2. Explainable scoring: every signal's contribution is shown, grounded in RBI/NPCI/cybercrime advisories via RAG.
3. WhatsApp-first delivery (a bot users forward messages to) — built after the core API.

## Hard constraints

- **No Docker.** The developer's machine has limited disk space. Never add Dockerfiles, docker-compose, or instructions that require Docker.
- **Keep local installs light.** Do NOT add `torch`, `tensorflow`, or `sentence-transformers` to the backend. Embeddings come from an API; the classifier is served with `onnxruntime`. Training happens separately on Google Colab.
- **Free tier only.** Database = Supabase (hosted Postgres + pgvector). LLM = Gemini API free tier (primary) or Groq (fallback). No paid services.
- **No Redis for now.** Cache in Postgres (`url_cache` table) or an in-process TTL cache.

## Stack

- Python 3.11+, FastAPI, Uvicorn, Pydantic v2, pydantic-settings
- SQLAlchemy 2.0 (async) + asyncpg, Alembic migrations, pgvector (`pgvector` Python package)
- LangGraph for the analysis agent; LLM via `google-genai` (Gemini) with a Groq fallback
- httpx for outbound calls; pytest + pytest-asyncio for tests; ruff for lint/format
- Dependency management: `uv` if available, otherwise `venv` + `requirements.txt`

## Layout

```
backend/
  app/
    main.py                 # FastAPI app, lifespan, router registration
    api/routes/             # health.py, analyze.py, report.py
    core/                   # config.py (settings), logging.py, errors.py
    db/                     # base.py, session.py, models.py
    schemas/                # pydantic request/response models
    services/
      extractors.py         # URLs, UPI IDs, phones, amounts, OTP mentions
      rules.py              # weighted rule engine
      upi.py                # UPI ID + upi:// URI analysis
      qr.py                 # QR decode
      ocr.py                # screenshot -> text
      url_intel.py          # Safe Browsing, phishing feeds, domain age
      reputation.py         # community-reported entities
      embeddings.py         # embedding API wrapper
      rag.py                # pgvector retrieval
      classifier.py         # ONNX model inference
      scoring.py            # combines signals -> final score + breakdown
      agent/                # LangGraph graph, nodes, prompts
  alembic/
  data/
    scam_patterns/          # markdown knowledge-base docs
    datasets/               # raw + processed training data (gitignored if large)
  ml/                       # Colab notebooks, eval scripts
  scripts/                  # seed/ingest scripts
  tests/
```

## Conventions

- Every service function is pure where possible and unit-tested.
- Every analysis returns the same `AnalysisResult` shape:
  `risk_score (0-100)`, `verdict (safe|suspicious|scam)`, `scam_type`, `red_flags[]`,
  `signal_breakdown[]` (source, score, weight, detail), `explanation_en`, `explanation_hi`, `advice[]`, `similar_patterns[]`.
- The LLM explains; it does not decide alone. Final score = weighted combination of rules, classifier, reputation/URL intel, and LLM judgement. Weights live in config.
- All external calls have timeouts and fail soft: if Gemini/Safe Browsing is down, return a result from the remaining signals and note the missing signal.
- Secrets only in `.env` (never committed). Provide `.env.example`.
- Commands:
  - run: `uvicorn app.main:app --reload`
  - test: `pytest -q`
  - lint: `ruff check . && ruff format --check .`
  - migrate: `alembic upgrade head`
