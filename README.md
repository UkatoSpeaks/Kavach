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

## Test and lint

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

## Without uv

```powershell
cd backend
python -m venv .venv
.\.venv\Scripts\Activate.ps1
pip install fastapi "uvicorn[standard]" pydantic pydantic-settings "sqlalchemy[asyncio]" asyncpg alembic pgvector httpx python-dotenv python-multipart fastembed pyyaml langgraph groq limits pillow zxing-cpp pytest pytest-asyncio respx "qrcode[pil]" ruff
uvicorn app.main:app --reload
```

## Production behaviour

Set `ENV=prod` (or `ENV=production`). Every setting is listed in `backend/.env.example`.

- **Rate limits** apply per client IP and are kept in memory, so they reset on restart.
  All `/analyze/*` routes share `RATE_LIMIT_ANALYZE` (default `10/minute`). `/report` has
  its own limit, `RATE_LIMIT_REPORT` (default `5/minute`). Over the limit, the API returns
  429 with a `Retry-After` header.
  Behind Render's proxy the client IP is taken from `X-Forwarded-For` (`TRUSTED_PROXY_HOPS=2`).
  The app never uses the leftmost entry, because a client can forge it.
- **Limits:** text up to 5000 characters (422), JSON bodies up to 64 KB (413), images up to
  5 MB (413).
- **Errors** always come back as `{"error": {"code": "...", "message": "..."}}`. Validation
  errors (422) also include `details: [{field, message}]`. In prod, a 500 says only
  "Internal server error". The full traceback goes to the logs.
- **Security headers** on every response: `X-Content-Type-Options: nosniff`,
  `X-Frame-Options: DENY`, `Referrer-Policy: no-referrer`.
- **CORS:** only origins listed in `CORS_ORIGINS` (comma-separated) are allowed. None are
  allowed by default, except `http://localhost:3000` in dev.
- **Docs:** `/docs`, `/redoc` and `/openapi.json` are off in prod unless `ENABLE_DOCS=true`.
- **Memory:** `PATTERN_SIGNAL_ENABLED=false` skips the embedding model (see below). The
  pattern-similarity signal is then reported as unavailable. Its weight is only 0.05, so the
  other signals carry the score.

### Memory (measured locally, Windows, Python 3.12, one uvicorn worker)

| | after startup | after 20 analyses |
|---|---|---|
| `PATTERN_SIGNAL_ENABLED=true` (model loaded) | ~680 MB RSS | ~690 MB RSS |
| `PATTERN_SIGNAL_ENABLED=false` | ~116 MB RSS | ~123 MB RSS |

The ONNX model accounts for about 560 MB of that, including the onnxruntime import. Turning
off onnxruntime's memory arena and using a single thread didn't change it. The free Render
instance has 512 MB, so `render.yaml` sets `PATTERN_SIGNAL_ENABLED=false`. To bring the
signal back, move to an instance with at least 1 GB of RAM or switch to a smaller or
quantized embedding model. A new model needs a migration if its dimension changes, plus a
re-run of `scripts.ingest_patterns`.

## Deploy to Render (free, no Docker)

`render.yaml` in the repository root is a Render Blueprint. It defines one free native-Python
web service. Render detects `backend/uv.lock` and installs dependencies with uv. On every
deploy, the build does three things:

1. `uv sync --frozen --no-dev`: installs the locked runtime dependencies with Python
   3.12.12 (`PYTHON_VERSION`).
2. `python -m scripts.download_model`: downloads the embedding model into
   `backend/.cache/fastembed`, which ships with the build, so a cold start never downloads
   240 MB. This step is skipped while `PATTERN_SIGNAL_ENABLED=false`.
3. `alembic upgrade head`: migrates Supabase.

The service then starts with
`uvicorn app.main:app --host 0.0.0.0 --port $PORT --no-proxy-headers`, and Render checks
`GET /health`.

### Steps

1. **Push the repository to GitHub.** It must include `render.yaml`,
   `.github/workflows/ci.yml`, `backend/uv.lock` and `backend/.python-version`.
2. **Check `region` in `render.yaml` before the first deploy.** It can't be changed later.
   It is `singapore`, which is right if your Supabase project is in Mumbai or Singapore. To
   find your Supabase region, open Supabase → Project Settings → General, or look at the
   pooler host (`aws-0-<region>.pooler.supabase.com`). If the project is in the US, use
   `oregon`, `ohio` or `virginia`. If it is in the EU, use `frankfurt`.
3. **Create the service from the Blueprint.** In the [Render dashboard](https://dashboard.render.com),
   click **New → Blueprint**, connect your GitHub account if asked, and pick this repository.
   Render reads `render.yaml` and shows one web service, `kavach-api` (free plan).
4. **Enter the secrets** when Render asks for them. These are the `sync: false` variables:
   - `DATABASE_URL`: in Supabase, click **Connect** → **Session pooler** and copy the URI.
     It looks like
     `postgresql://postgres.<ref>:<password>@aws-0-<region>.pooler.supabase.com:5432/postgres`.
     Paste it with your real password. Don't use the "Direct connection" string: it is
     IPv6-only and Render can't reach it.
   - `GROQ_API_KEY`: from https://console.groq.com/keys. If you leave it empty, the API
     still works with template explanations.
   - `SAFE_BROWSING_API_KEY`: optional. Leave it empty to skip that check.

   Every other variable already has a value in `render.yaml`. To change one later, go to
   the service → **Environment**, edit it, then **Save, rebuild and deploy**.
5. **Click Apply** and wait for the first build. It takes a few minutes, mostly for
   `uv sync`. The build fails, and nothing is deployed, if the dependencies can't be
   installed, the model can't be downloaded, or the migration fails. In that case, check
   `DATABASE_URL` first.
6. **Check the deploy.** Open the service URL shown in the dashboard
   (`https://kavach-api-xxxx.onrender.com`):
   - `https://<url>/health` should return `{"status":"ok","env":"prod"}`.
   - `https://<url>/health/db` should return `"db":"ok"`.
   - To run an analysis (PowerShell):
     ```powershell
     Invoke-RestMethod -Method Post -Uri "https://<url>/analyze/text" -ContentType "application/json" -Body '{"text": "Aapke account me 2000 cashback aaya hai, UPI PIN dalein"}'
     ```
7. **Knowledge base.** The scam-pattern rows are already in Supabase if you ran
   `scripts.ingest_patterns` locally. The deployed app doesn't use them while
   `PATTERN_SIGNAL_ENABLED=false`.

### Logs and later deploys

- **Logs:** open the service → **Logs**. There is one JSON line per request (`method`,
  `path`, `status`, `duration_ms`, `request_id`). Every response carries the same id in its
  `X-Request-ID` header, so you can search the logs for it. Useful searches:
  `"level": "ERROR"`, `rate limited`, `could not save analysis`.
- **Build and migration output:** open the service → **Events**, then click a deploy to see
  its build log.
- **No shell:** the free plan has no shell access. Run one-off commands, such as
  `alembic downgrade` or `scripts.ingest_patterns`, from your machine against the same
  `DATABASE_URL`.
- **Later deploys:** every push to the default branch that touches `backend/**` or
  `render.yaml` deploys automatically once CI passes (`autoDeployTrigger: checksPass`). To
  deploy by hand, use **Manual Deploy → Deploy latest commit**.

### Why migrations run in the build

Render's pre-deploy command, which would be the natural place for migrations, is only
available on paid plans. On the free plan the choices are the build or the start command.
The build is the safer of the two:

- **Start command:** the service sleeps when idle, so migrations would run on every wake-up.
  That adds a Supabase round trip to an already slow cold start. It would also stop the app
  from starting whenever the database is unreachable, even though the API is designed to
  keep working without it.
- **Build:** the migration runs once per deploy, as the last build step. If it fails, the
  deploy fails and the previous version keeps serving. The catch is that the migration runs
  while the old version is still live, and it stays applied if the new version then fails
  its health check. So every migration must stay compatible with the code that's running.
  Add columns and tables first (nullable or with defaults), and drop or rename them only in
  a later deploy.

### Choices worth knowing

- **uv, not pip:** Render supports uv natively when `uv.lock` is in the root directory, and
  `--frozen` installs exactly the locked versions that CI tests. `UV_PYTHON_DOWNLOADS=never`
  forces uv to use Render's Python 3.12.12, which ships with the build. A Python that uv
  downloaded itself would not ship. If uv ever gives you trouble on Render, the fallback is
  to generate `requirements.txt` with
  `uv export --frozen --no-dev --no-hashes -o requirements.txt`, set the build command to
  `pip install -r requirements.txt && python -m scripts.download_model && alembic upgrade head`,
  and change the start command to plain `uvicorn ...`.
- **`--no-proxy-headers`:** uvicorn's `--proxy-headers` with `--forwarded-allow-ips='*'` takes
  the leftmost `X-Forwarded-For` entry. Render's proxy appends to the header instead of
  replacing it, so a client could put any IP there and dodge the rate limit. The app reads
  the header itself instead: the client is the second entry from the right, because Render
  sends `<client>, <Cloudflare edge>`.
- **One worker:** the rate limits and the LLM cache live in memory, and 512 MB leaves no room
  for a second process.

### Cold starts

A free instance goes to sleep after 15 minutes without traffic. **The first request after
that takes about 30–60 seconds** while Render starts the instance. The request is held until
the instance is up; it is not dropped. Clients, including the future WhatsApp bot, should use
a timeout of at least 60 seconds. Requests after that are fast. `/health` does no database or
network work, so Render's health checks are cheap.

This is the trade-off of the free plan. The project deliberately doesn't use keep-alive
pings to prevent it.

## CI

`.github/workflows/ci.yml` runs on every push and pull request: `ruff check`,
`ruff format --check` and the fast pytest suite. That suite needs no database, no network
and no secrets, since the `db` and `llm` tests are deselected. uv's download cache is keyed
on `backend/uv.lock`.

## Known limitations

- **DNS rebinding when following redirects:** before following a short link, the app
  resolves each hop and refuses private or loopback addresses. httpx then resolves the name
  again to connect. A hostile DNS server with a very short TTL could answer "public" to the
  check and "private" to the connection. This matters less on Render, where the instance has
  no private services of ours to reach. The fix is to connect to the IP that was checked
  (with the right SNI and Host header) instead of resolving twice.
- **Groq free-tier limits:** the free tier has small per-minute token limits (about 8k
  tokens per minute for the gpt-oss models, reasoning tokens included) and daily request caps. When the main model is rate limited, the app
  switches to `GROQ_FALLBACK_MODEL` and then to template explanations. Scores and verdicts
  never depend on Groq. Under load, expect more template explanations. Repeated messages hit
  the in-process LLM cache.
- **Cold starts:** about 30–60 seconds for the first request after 15 idle minutes (see
  above). The in-memory LLM cache and the rate-limit counters are lost on every sleep or
  deploy.
- **Rate limits are per instance:** they are in memory. That's fine for a single free
  instance, but they would need shared storage (Postgres) if the service ever runs more than
  one instance.
- **Supabase region latency:** each analysis makes several database round trips (URL cache,
  reputation, background save). If Render and Supabase are in different regions, each trip
  adds about 100–250 ms. Keep them in the same region (see step 2).
- **No classifier yet:** the `classifier` signal is always unavailable, and its weight (0.25)
  is spread over the other signals until the ONNX model is trained. The pattern-similarity
  signal is also off on the free instance, for memory reasons.
- **Supabase free projects pause** after about a week without activity. `/health/db` then
  reports an error, and analyses carry on without reputation, cache and saving until you
  restore the project in the Supabase dashboard.
