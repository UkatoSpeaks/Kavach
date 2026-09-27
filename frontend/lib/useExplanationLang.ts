"use client";

import { useCallback, useSyncExternalStore } from "react";

export type Lang = "en" | "hi";

const KEY = "kavach.lang";
const listeners = new Set<() => void>();
// This page's choice; also covers browsers where localStorage throws (private mode).
let chosen: Lang | null = null;

function read(): Lang {
  if (chosen) return chosen;
  try {
    return window.localStorage.getItem(KEY) === "hi" ? "hi" : "en";
  } catch {
    return "en";
  }
}

function subscribe(onChange: () => void) {
  listeners.add(onChange);
  const onStorage = (e: StorageEvent) => {
    if (e.key !== KEY) return;
    chosen = null; // changed in another tab
    onChange();
  };
  window.addEventListener("storage", onStorage);
  return () => {
    listeners.delete(onChange);
    window.removeEventListener("storage", onStorage);
  };
}

/** The explanation language, remembered in localStorage (English during hydration). */
export function useExplanationLang(): [Lang, (lang: Lang) => void] {
  const lang = useSyncExternalStore(subscribe, read, () => "en" as const);
  const setLang = useCallback((next: Lang) => {
    chosen = next;
    try {
      window.localStorage.setItem(KEY, next);
    } catch {
      // Not remembered across visits, but still switched for this page.
    }
    listeners.forEach((l) => l());
  }, []);
  return [lang, setLang];
}
