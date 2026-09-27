"use client";

import { useEffect } from "react";
import { preconnect } from "react-dom";
import { API_URL, warmUp } from "@/lib/api";

/** Pings the backend once on mount so the sleeping Render server starts waking up. */
export function WarmUp() {
  // Emits <link rel="preconnect"> in the server HTML, so DNS/TLS are ready before the ping.
  preconnect(API_URL);
  useEffect(() => warmUp(), []);
  return null;
}
