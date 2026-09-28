# Development

How to run Kavach locally, test it and lint it. For deploying, see [DEPLOYMENT.md](DEPLOYMENT.md);
for the classifier's metrics, see [EVALUATION.md](EVALUATION.md).

## Prerequisites (Windows)

- Python 3.11+
- [uv](https://docs.astral.sh/uv/): `powershell -ExecutionPolicy ByPass -c "irm https://astral.sh/uv/install.ps1 | iex"`
- A free [Supabase](https://supabase.com) project and a free [Groq](https://console.groq.com) API key
- Node.js 22+ and npm (frontend only)

## Setup

```powershell
cd backend
uv sync                      # creates .venv and installs runtime + dev dependencies
Copy-Item .env.example .env  # then edit .env with your real values
```

`DATABASE_URL`: in Supabase, go to **Project Settings → Database → Connection string → Session pooler**.
Paste it as-is. The app switches it to the `asyncpg` driver and percent-encodes special
characters in the password.

Then create the tables and load the scam-pattern knowledge base:

```powershell
uv run alembic upgrade head
uv run python -m scripts.ingest_patterns   # embeds data/scam_patterns/*.md into pgvector
```

The first ingest (or the first app start) downloads the embedding model
(`paraphrase-multilingual-MiniLM-L12-v2`, ~240 MB on disk) into `backend/.cache/fastembed`.
Re-run the ingest after editing the docs. It only re-embeds docs that changed and deletes
rows whose file was removed. Check retrieval quality with `uv run python -m ml.eval_retrieval`.

## Run

### Backend

```powershell
cd backend
uv run uvicorn app.main:app --reload
```

Check it at http://127.0.0.1:8000/health. That endpoint answers instantly and touches nothing:
`{"status": "ok", "env": "dev"}`. To check the database, use http://127.0.0.1:8000/health/db,
which returns `{"status": "ok", "db": "ok", "env": "dev"}`. If the database can't be reached,
`db` holds the error and the status is still 200. In prod the error shows only its type.

Every `/analyze/*` call runs the LangGraph agent (extract → checks → LLM → scoring). The LLM
step uses Groq (`GROQ_API_KEY`; models in `GROQ_MODEL` / `GROQ_FALLBACK_MODEL`) and only
explains: its risk is a low-weight signal that can never make a result a scam on its own.
Add `?explain=false` to skip it (template explanations, no Groq quota used).
Interactive API docs: http://127.0.0.1:8000/docs

To skip the `uv run` prefix, activate the venv once per shell with `.\.venv\Scripts\Activate.ps1`.

### Frontend

```powershell
cd frontend
Copy-Item .env.local.example .env.local   # set NEXT_PUBLIC_API_URL (e.g. http://127.0.0.1:8000)
npm install
npm run dev                               # http://localhost:3000
```

In dev the backend allows `http://localhost:3000` through CORS by default.
`NEXT_PUBLIC_SITE_URL` sets the absolute Open Graph URLs.

## Test and lint

### Backend

```powershell
cd backend
uv run pytest -q              # fast tests only: no database, no network (a few seconds)
uv run pytest -q -m db        # only the tests that hit the real database (Supabase, ~2 min)
uv run pytest -q -m llm       # only the tests that call the real Groq API (uses quota)
uv run pytest -q -m ""        # everything
uv run ruff check .
uv run ruff format --check .
```

Tests that touch the database are marked `@pytest.mark.db` and are skipped by default.
Their writes happen inside a transaction that is always rolled back. Other API tests use
an in-memory session, reputation store and pattern retriever with a fake embedder
(`tests/fakes.py`). No test does real DNS or HTTP. The `db` suite also loads the real
embedding model and checks that the 36 labelled examples keep their verdicts.

### Frontend

```powershell
cd frontend
npm run lint
npm run build
```

## Without uv

```powershell
cd backend
python -m venv .venv
.\.venv\Scripts\Activate.ps1
pip install fastapi "uvicorn[standard]" pydantic pydantic-settings "sqlalchemy[asyncio]" asyncpg alembic pgvector httpx python-dotenv python-multipart fastembed pyyaml langgraph groq limits pillow zxing-cpp pytest pytest-asyncio respx "qrcode[pil]" ruff
uvicorn app.main:app --reload
```

## Classifier data and training

Datasets, splits, anonymization and training commands are documented in
[backend/data/datasets/README.md](../backend/data/datasets/README.md). The trained model is
`backend/models/classifier.json`; results are in [EVALUATION.md](EVALUATION.md).

## CI

[`.github/workflows/ci.yml`](../.github/workflows/ci.yml) runs on every push and pull request:

- **backend:** `ruff check`, `ruff format --check` and the fast pytest suite. That suite needs
  no database, no network and no secrets, since the `db` and `llm` tests are deselected.
  uv's download cache is keyed on `backend/uv.lock`.
- **frontend:** `npm ci`, `npm run lint` and `npm run build` on Node 22.
