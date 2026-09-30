# Deployment

Kavach runs entirely on free tiers: the FastAPI backend on **Render**, the Next.js frontend on
**Vercel**, and the database on **Supabase** (Postgres + pgvector). No Docker. For local
setup, see [DEVELOPMENT.md](DEVELOPMENT.md).

- [Production behaviour](#production-behaviour)
- [Memory](#memory-measured-locally-windows-python-312-one-uvicorn-worker)
- [Deploy the backend to Render](#deploy-the-backend-to-render-free-no-docker)
- [Deploy the frontend to Vercel](#deploy-the-frontend-to-vercel)
- [Cold starts](#cold-starts)
- [Known limitations](#known-limitations)

## Production behaviour

Set `ENV=prod` (or `ENV=production`). Every setting is listed in `backend/.env.example`.

- **Rate limits** apply per client IP and are kept in memory, so they reset on restart.
  All `/analyze/*` routes share `RATE_LIMIT_ANALYZE` (default `10/minute`). `/report` has
  its own limit, `RATE_LIMIT_REPORT` (default `5/minute`). Over the limit, the API returns
  429 with a `Retry-After` header.
  Behind Render's proxy the client IP is taken from `X-Forwarded-For` (`TRUSTED_PROXY_HOPS=2`).
  The app never uses the leftmost entry, because a client can forge it.
- **Limits:** text up to 5000 characters (422), JSON bodies up to 64 KB (413), images up to
  5 MB (413). `/analyze/screenshot` takes PNG, JPEG or WEBP; anything else is a 422
  (`unsupported_image`), and so is an image with no readable text (`no_text_found`).
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
- **Screenshots** are read by the Groq vision model `GROQ_VISION_MODEL` (`qwen/qwen3.8-27b`,
  the only vision-capable model on the free tier as of 2026-09). One phone screenshot costs
  about 1.3k–1.9k tokens of the model's free 8k tokens/minute (Groq's limits are per model,
  so this budget is separate from the explanation model's): about four screenshots a minute.
  A 429 falls through to the next tier. The local
  OCR fallback (RapidOCR) is off on Render (`LOCAL_OCR_ENABLED=false`, see Memory), so when
  the vision call fails the route returns 503 `ocr_unavailable`. The image itself is never
  stored or logged; only the extracted text is saved with the analysis. OCR time is in the
  saved `latency_ms` (`ocr`, `ocr.groq_vision` / `ocr.local`, `qr`) and in the
  `screenshot read` log line.

## Memory (measured locally, Windows, Python 3.12, one uvicorn worker)

| | after startup | after 20 analyses |
|---|---|---|
| `PATTERN_SIGNAL_ENABLED=true` (model loaded) | ~680 MB RSS | ~690 MB RSS |
| `PATTERN_SIGNAL_ENABLED=false`, `CLASSIFIER_ENABLED=false` | ~120 MB RSS | ~122 MB RSS |
| `PATTERN_SIGNAL_ENABLED=false`, classifier on (the Render setup) | ~134 MB RSS | ~136 MB RSS (peak 153 MB while loading) |
| same + local OCR, Latin only (`LOCAL_OCR_DEVANAGARI=false`), 20 screenshots | ~134 MB RSS | ~226 MB RSS (peak 405 MB) |
| same + local OCR with Devanagari (the local default), 20 screenshots | ~135 MB RSS | ~247 MB RSS (peak 441 MB) |

The classifier rows come from `uv run python -m scripts.measure_memory [--no-classifier]`
(the real app and route, `POST /analyze/text?explain=false`, no database or network). The
classifier costs about 14 MB, plus ~30 MB for a moment while its JSON is parsed at startup.

The OCR rows come from `uv run python -m scripts.measure_memory --screenshots
[--no-devanagari]`: generated 1080×1400 phone screenshots posted to
`/analyze/screenshot?explain=false` with the vision model off, so each one goes through the
local OCR. It loads on the first screenshot, not at startup. Once loaded it holds ~90 MB
(~110 MB with the Devanagari models), and while it reads an image the process peaks at
~405–441 MB (Windows peak working set; the detector's memory grows with the pixel count,
which is why the local OCR reads at 1024 px on the long side). Only one image is read at a
time. A peak of ~440 MB leaves too little of the free instance's 512 MB for a concurrent
request and Python's own growth, so `render.yaml` sets `LOCAL_OCR_ENABLED=false` and
screenshots rely on Groq vision there. On an instance with 1 GB, turn it on.
Measured on Windows; Linux RSS is usually a little lower, but check `/health` and the
Render metrics before relying on it.

The embedding (ONNX) model accounts for about 560 MB of the first row, including the
onnxruntime import. Turning
off onnxruntime's memory arena and using a single thread didn't change it. The free Render
instance has 512 MB, so `render.yaml` sets `PATTERN_SIGNAL_ENABLED=false`. To bring the
signal back, move to an instance with at least 1 GB of RAM or switch to a smaller or
quantized embedding model. A new model needs a migration if its dimension changes, plus a
re-run of `scripts.ingest_patterns`.

## Deploy the backend to Render (free, no Docker)

[`render.yaml`](../render.yaml) in the repository root is a Render Blueprint. It defines one free native-Python
web service. Render detects `backend/uv.lock` and installs dependencies with uv. On every
deploy, the build does three things:

1. `uv sync --frozen --no-dev`: installs the locked runtime dependencies with Python
   3.12.12 (`PYTHON_VERSION`).
2. `python -m scripts.download_model`: downloads the embedding model into
   `backend/.cache/fastembed` and the local OCR's Devanagari models (~10 MB) into
   `backend/.cache/rapidocr`, which ship with the build, so a cold start never downloads
   them. Each is skipped while its feature is off (`PATTERN_SIGNAL_ENABLED=false`,
   `LOCAL_OCR_ENABLED=false`), which is the case in `render.yaml`.
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
   - A screenshot (curl, any shell): `curl -F "image=@shot.png" https://<url>/analyze/screenshot`
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

## Deploy the frontend to Vercel

The frontend is a standard Next.js app in `frontend/`, deployed on Vercel's free (Hobby) plan.

1. In [Vercel](https://vercel.com/new), import the GitHub repository.
2. Set **Root Directory** to `frontend`. Vercel detects Next.js; keep the default build
   command (`npm run build`) and install command.
3. Add the environment variables (see `frontend/.env.local.example`):
   - `NEXT_PUBLIC_API_URL`: the Render service URL, e.g. `https://kavach-api-xxxx.onrender.com`.
   - `NEXT_PUBLIC_SITE_URL`: the site's public URL, used for absolute Open Graph URLs.

   Only `NEXT_PUBLIC_*` values reach the browser; never put secrets here.
4. Deploy, then **allow the site's origin on the backend**: in Render → the service →
   **Environment**, set `CORS_ORIGINS` to the Vercel URL (comma-separated if there are several,
   e.g. a custom domain too) and save. Without it, the browser blocks every API call.
   `CORS_ORIGINS` is deliberately not in `render.yaml`, because a Blueprint value would
   override the dashboard.

Every push to the default branch redeploys the frontend; pull requests get preview URLs
(add a preview's origin to `CORS_ORIGINS` if you want it to reach the API).

## Cold starts

A free instance goes to sleep after 15 minutes without traffic. **The first request after
that takes about 30–60 seconds** while Render starts the instance. The request is held until
the instance is up; it is not dropped. Clients, including the future WhatsApp bot, should use
a timeout of at least 60 seconds. Requests after that are fast. `/health` does no database or
network work, so Render's health checks are cheap.

This is the trade-off of the free plan. The project deliberately doesn't use keep-alive
pings to prevent it.

## Known limitations

- **Screenshots when Groq vision is unavailable:** on Render the local OCR is off (memory), so
  a vision 429 or outage means 503 for screenshots. Where the local OCR runs, it reads
  English and Hinglish screenshots almost perfectly (CER ~0.003 on synthetic screenshots)
  but Devanagari poorly (CER ~0.35; see `ml/reports/*_screenshots.md`), so Hindi screenshots
  can come back "safe" when the vision model was skipped.
- **DNS rebinding when following redirects:** before following a short link, the app
  resolves each hop and refuses private or loopback addresses. httpx then resolves the name
  again to connect. A hostile DNS server with a very short TTL could answer "public" to the
  check and "private" to the connection. This matters less on Render, where the instance has
  no private services of ours to reach. The fix is to connect to the IP that was checked
  (with the right SNI and Host header) instead of resolving twice.
- **Groq free-tier limits:** the free tier has small per-minute token limits (about 8k
  tokens per minute for the gpt-oss models, reasoning tokens included) and daily request
  caps. When the main model is rate limited, the app switches to `GROQ_FALLBACK_MODEL` and
  then to template explanations. Scores and verdicts never depend on Groq. Under load,
  expect more template explanations. Repeated messages hit the in-process LLM cache.
- **Cold starts:** about 30–60 seconds for the first request after 15 idle minutes (see
  above). The in-memory LLM cache and the rate-limit counters are lost on every sleep or
  deploy.
- **Rate limits are per instance:** they are in memory. That's fine for a single free
  instance, but they would need shared storage (Postgres) if the service ever runs more than
  one instance.
- **Supabase region latency:** each analysis makes several database round trips (URL cache,
  reputation, background save). If Render and Supabase are in different regions, each trip
  adds about 100–250 ms. Keep them in the same region (see step 2).
- **Classifier coverage:** the classifier learned mostly from public, largely non-Indian
  smishing reports. It still rates some genuine Indian transactional messages as likely
  scams (a UPI debit alert 0.72, a food-delivery update 0.68, an SBI "visit your branch for
  KYC" reminder 0.86), which is why it only counts from 0.9 (see
  [EVALUATION.md](EVALUATION.md)). The pattern-similarity signal is off on the free
  instance, for memory reasons.
- **Supabase free projects pause** after about a week without activity. `/health/db` then
  reports an error, and analyses carry on without reputation, cache and saving until you
  restore the project in the Supabase dashboard.
