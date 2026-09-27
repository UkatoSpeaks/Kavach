/** Client for the Kavach FastAPI backend (see backend/app/schemas for response shapes). */

export const API_URL = (
  process.env.NEXT_PUBLIC_API_URL ?? "https://kavach-api-mib4.onrender.com"
).replace(/\/+$/, "");

let warmedUp = false;

/**
 * Wake the free Render server (it sleeps when idle) while the user reads the page.
 * Fire-and-forget: one request per page load, never throws, never shows an error.
 * `no-cors` means the request is sent without needing CORS headers; we ignore the response.
 */
export function warmUp(): void {
  if (warmedUp || typeof window === "undefined") return;
  warmedUp = true;
  fetch(`${API_URL}/health`, { mode: "no-cors", cache: "no-store", keepalive: true }).catch(
    () => {},
  );
}
