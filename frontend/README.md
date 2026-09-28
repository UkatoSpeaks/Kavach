# Kavach frontend

Next.js (App Router) + TypeScript + Tailwind CSS v4. Talks to the Kavach FastAPI backend.

```bash
cp .env.local.example .env.local   # set NEXT_PUBLIC_API_URL
npm install
npm run dev     # http://localhost:3000
npm run build
npm run lint
```

Design tokens (colours, fonts, type scale, shadows) live in `app/globals.css`. Setup and deployment: [docs/DEVELOPMENT.md](../docs/DEVELOPMENT.md) and [docs/DEPLOYMENT.md](../docs/DEPLOYMENT.md#deploy-the-frontend-to-vercel).
