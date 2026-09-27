# Kavach — AI scam detector for Indian users

FastAPI backend that analyzes suspicious messages, links, UPI IDs, QR codes and screenshots
and returns an explainable scam verdict. See [CLAUDE.md](CLAUDE.md) for architecture and constraints.

## Prerequisites (Windows)

- Python 3.11+
- [uv](https://docs.astral.sh/uv/): `powershell -ExecutionPolicy ByPass -c "irm https://astral.sh/uv/install.ps1 | iex"`
- A free [Supabase](https://supabase.com) project and a free [Groq](https://console.groq.com) API key

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

```powershell
cd backend
uv run uvicorn app.main:app --reload
```

Check it at http://127.0.0.1:8000/health. The response should be:

```json
{"status": "ok", "db": "ok", "env": "dev"}
```

If the database can't be reached, `db` holds the error message and the endpoint still returns 200.
Interactive API docs: http://127.0.0.1:8000/docs

To skip the `uv run` prefix, activate the venv once per shell with `.\.venv\Scripts\Activate.ps1`.

## Test and lint

```powershell
cd backend
uv run pytest -q              # fast tests only: no database, no network (a few seconds)
uv run pytest -q -m db        # only the tests that hit the real database (Supabase, ~1 min)
uv run pytest -q -m ""        # everything
uv run ruff check .
uv run ruff format --check .
```

Tests that touch the database are marked `@pytest.mark.db` and are skipped by default.
Their writes happen inside a transaction that is always rolled back. Other API tests use
an in-memory session, reputation store and pattern retriever with a fake embedder
(`tests/fakes.py`). No test does real DNS or HTTP. The `db` suite also loads the real
embedding model and checks that the 36 labelled examples keep their verdicts.

## Without uv

```powershell
cd backend
python -m venv .venv
.\.venv\Scripts\Activate.ps1
pip install fastapi "uvicorn[standard]" pydantic pydantic-settings "sqlalchemy[asyncio]" asyncpg alembic pgvector httpx python-dotenv fastembed pyyaml pytest pytest-asyncio ruff
uvicorn app.main:app --reload
```
