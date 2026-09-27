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
- **Keep local installs light.** Do NOT add `torch`, `tensorflow`, or `sentence-transformers` to the backend. Embeddings are computed locally with `fastembed` (ONNX, no torch); the classifier will be served with `onnxruntime`. Training happens separately on Google Colab.
- **Free tier only.** Database = Supabase (hosted Postgres + pgvector). LLM = Groq free tier. No paid services.
- **No Redis for now.** Cache in Postgres (`url_cache` table) or an in-process TTL cache.

## Stack

- Python 3.11+, FastAPI, Uvicorn, Pydantic v2, pydantic-settings
- SQLAlchemy 2.0 (async) + asyncpg, Alembic migrations, pgvector (`pgvector` Python package)
- LangGraph for the analysis agent
- LLM: Groq (`groq` SDK), JSON mode. Models come from config: `GROQ_MODEL` (currently
  `openai/gpt-oss-120b`), falling back to `GROQ_FALLBACK_MODEL` (currently `openai/gpt-oss-20b`)
  on rate limits/errors, then to template explanations. No `GROQ_API_KEY` → templates only.
  `GROQ_REASONING_EFFORT=low` (gpt-oss reasoning tokens count toward `max_tokens` and the free
  tier's 8k tokens/minute). Keep the system prompt lean for the same reason.
- Embeddings: local `fastembed`, `sentence-transformers/paraphrase-multilingual-MiniLM-L12-v2`,
  384-dim (`EMBEDDING_MODEL` / `EMBEDDING_DIM`). Downloaded once (~240 MB) into
  `backend/.cache/fastembed` (gitignored); loads in a background thread at startup.
- QR decode: `zxing-cpp` + Pillow.
- Screenshots (OCR): **undecided.** A Groq vision model if one is available on the free tier,
  otherwise a small local OCR (no torch). Not built yet.
- httpx for outbound calls; pytest + pytest-asyncio + respx for tests; ruff for lint/format
- Dependency management: `uv` (`pyproject.toml` + `uv.lock`)

## Layout

```
backend/
  app/
    main.py                 # FastAPI app, lifespan (engine, http client, embedder, graph, reasoner)
    api/
      deps.py               # session, session factory, http client, pattern search, reasoner
      errors.py             # {error: {code, message}} for every error; ApiError; prod hides internals
      protection.py         # client IP behind Render's proxy, per-IP rate limits (`limits`),
                            # body size limit, security headers
      routes/               # health.py (/health cheap, /health/db), analyze.py
                            # (/analyze/{text,url,upi,qr}, GET /analysis/{id}), report.py
    core/                   # config.py (settings, signal weights), enums.py, logging.py (JSON logs, request id)
    db/                     # base.py, session.py, models.py
    schemas/                # analysis.py (AnalysisResult), entities.py
    services/
      extractors.py         # URLs, UPI IDs, upi:// URIs, phones, amounts, sensitive-info mentions
      rules.py              # weighted rule engine
      upi.py                # UPI ID + upi:// URI analysis
      qr.py                 # QR decode
      url_intel.py          # link expansion (SSRF-safe), RDAP domain age, Safe Browsing
      cache.py              # url_cache table + in-request memory cache
      reputation.py         # community-reported entities (one query for all entities)
      knowledge_base.py     # parses data/scam_patterns/*.md (frontmatter + sections)
      embeddings.py         # local fastembed wrapper (background load, fails soft)
      rag.py                # pgvector retrieval -> pattern_similarity signal
      scoring.py            # combines signals -> final score + breakdown
      explain.py            # template explanations/advice (used when the LLM is off or fails)
      pipeline.py           # the steps: extract_step, run_checks (concurrent), finish
      agent/
        graph.py            # LangGraph: extract -> run_checks -> reason (LLM) -> finalize
        nodes.py            # graph nodes (thin wrappers over pipeline.py)
        state.py            # AnalysisState, AnalysisContext
        llm.py              # GroqReasoner: retries, fallback model, output validation, LRU+TTL cache
        prompts.py          # system prompt (injection defences, Hindi style, identifier rule)
      # planned: classifier.py (ONNX inference), ocr.py (screenshot -> text)
  alembic/
  data/
    scam_patterns/          # markdown knowledge-base docs (scam + genuine patterns)
    datasets/               # raw + processed training data (gitignored if large)
  ml/                       # eval_retrieval.py; Colab notebooks later
  scripts/                  # ingest_patterns.py (embed KB into pgvector), seed_reported.py,
                            # download_model.py (build step: fastembed model into the cache dir)
  tests/
    conftest.py             # make_client (no DB), make_db_client (rolled-back DB), fake DNS
    fakes.py                # FakeSession, InMemoryReputation, FakeEmbedder, FakeReasoner, ...
    examples.py             # 36 labelled messages shared by scoring/API/agent tests
render.yaml                 # Render Blueprint (free native-Python web service, rootDir backend)
.github/workflows/ci.yml    # ruff + fast pytest on push/PR
```

## Conventions

- Every service function is pure where possible and unit-tested.
- Every analysis returns the same `AnalysisResult` shape:
  `risk_score (0-100)`, `verdict (safe|suspicious|scam)`, `scam_type`, `red_flags[]`,
  `signal_breakdown[]` (source, score, weight, detail), `explanation_en`, `explanation_hi`, `advice[]`, `similar_patterns[]`.
- The LLM explains; it does not decide alone. Final score = weighted combination of rules, classifier, reputation/URL intel, and LLM judgement. Weights live in config.
- LLM output is validated before use: schema, no invented contact details, and identifiers
  (UPI IDs, URLs, phone numbers) in `explanation_hi` exactly as in the message, never
  transliterated. Invalid → retry once → template explanations.
- All external calls have timeouts and fail soft: if Groq/Safe Browsing/the database is down, return a result from the remaining signals and note the missing signal.
- Network checks (url_intel, reputation, pattern retrieval) run concurrently in `pipeline.run_checks`.
  Analyses are saved to Supabase in a background task after the response is sent; the id is
  generated up front. A failed save is logged and `GET /analysis/{id}` then returns 404.
- Secrets only in `.env` (never committed). Provide `.env.example`.
- Deployment: Render free tier (512 MB RAM), native Python via uv, one uvicorn worker. The
  embedding model needs ~560 MB, so production runs with `PATTERN_SIGNAL_ENABLED=false`.
  Migrations run as the last build step (pre-deploy is paid-only), so they must stay
  backward compatible with the running code. `/health` must stay free of DB/network calls.
- Every error response is `{"error": {"code", "message"}}` (raise `app.api.errors.ApiError`);
  new abusable routes get a `rate_limit(...)` dependency. Tests build apps with
  `create_app(settings)`; rate limits are off in tests unless a test turns them on.
- Commands (from `backend/`, prefix with `uv run`):
  - run: `uvicorn app.main:app --reload`
  - migrate: `alembic upgrade head`; load the knowledge base: `python -m scripts.ingest_patterns`
  - lint: `ruff check . && ruff format --check .`
- Tests. Markers `db` and `llm` are deselected by default (`addopts` in `pyproject.toml`):
  - `pytest -q`: fast suite, no database, no network, no Groq (a few seconds). API tests use
    `tests/fakes.py` (in-memory session, reputation, retriever, `FakeReasoner`).
  - `pytest -q -m db`: tests against the real Supabase DB (writes rolled back; slow, ~2 min).
  - `pytest -q -m llm`: tests that call the real Groq API (uses quota).
  - `pytest -q -m ""`: everything.
  - A new test that touches the DB must be marked `@pytest.mark.db`; one that calls Groq, `@pytest.mark.llm`.

## Frontend

- `frontend/`: Next.js 16 (App Router, Turbopack), TypeScript, Tailwind CSS v4, ESLint, npm.
  Runtime deps are only `next`, `react`, `lucide-react` and `motion`. Ask before adding more.
  Next 16 changed a lot: check `frontend/node_modules/next/dist/docs/` before using an API.
- Design: neo-brutalist. Every token (colours, fonts, type scale, shadows) lives in
  `app/globals.css` `@theme`. Verdict colours (`safe`/`suspicious`/`scam`) are for verdicts only;
  the accent is indigo. Body text is 17px. Design for a 375px phone first, with no horizontal scroll,
  visible focus states, and `prefers-reduced-motion` respected (`lib/useReducedMotion.ts`;
  motion's own hook causes a hydration mismatch).
- `NEXT_PUBLIC_API_URL` goes in `frontend/.env.local` (copy `.env.local.example`).
  `NEXT_PUBLIC_SITE_URL` sets the absolute Open Graph URLs.
- Commands (from `frontend/`): `npm run dev`, `npm run build`, `npm run lint`.

```
frontend/
  app/            # layout.tsx (fonts, metadata), page.tsx (landing), check/ (checker),
                  # r/[id]/ (shared result), globals.css (tokens), icon.svg, opengraph-image.tsx
  components/
    ui/           # Button, Card, Badge, SectionHeading, Container
    site/         # Navbar, Footer, Logo, GitHubIcon, WarmUp
    landing/      # Hero, DemoCard, WhatWeCheck, HowItWorks, CommonScams, TrustStrip, FinalCta
    check/        # Checker (state, API calls), InputPanel (tabs), fields, examples, loading/error
    result/       # ResultPanel and its parts (verdict + gauge, highlighted input, breakdown,
                  # report, share), SharedResult (/r/[id])
  lib/            # api.ts (typed client, ApiError), types.ts (mirrors backend schemas),
                  # errors.ts (friendly messages), highlight.ts (evidence -> original text),
                  # labels.ts, examples.ts, image.ts, useExplanationLang.ts, site.ts, cn.ts,
                  # useReducedMotion.ts
```

## Scope (v1): UPI and link fraud only

Focus on: (1) "receive money" UPI / collect-request scams, (2) QR code scams, (3) "sent by mistake" refund scams, (4) phishing links (fake KYC/account block, electricity bill, e-challan, parcel/customs), (5) task-based job scams, (6) fake customer care numbers.
Out of scope for now (later versions): OTP/Aadhaar fraud, SIM swap, digital arrest, loan apps, investment scams, deepfakes, voice calls. Don't build features for these yet.
