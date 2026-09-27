/**
 * Find each red flag's evidence in the original text, so it can be highlighted in place.
 *
 * Evidence comes from the backend's normalized text (extractors.clean_text: invisible
 * characters removed, NFKC, Devanagari digits to ASCII, whitespace collapsed, lower-cased),
 * and can join pieces ("refund … 9876543210") or carry a note ("x.top (imitates 'sbi')").
 * We normalize the original the same way while remembering where each normalized character
 * came from, search there, and map the match back to the original.
 */

import type { RedFlag } from "./types";

// Same set as the backend's _INVISIBLE_RE.
const INVISIBLE =
  /[­͏؜ᅟᅠ᠎​-‏‪-‮⁠-⁤⁦-⁩ㅤ﻿ﾠ]/;
const DEVANAGARI_DIGITS = "०१२३४५६७८९";

type Normalized = { text: string; origin: number[] };

/** Normalize `text`; origin[i] is the index in `text` that normalized char i came from. */
function normalizeWithMap(text: string): Normalized {
  let out = "";
  const origin: number[] = [];
  let lastWasSpace = true; // also trims leading whitespace
  let i = 0;
  for (const ch of text) {
    const start = i;
    i += ch.length;
    if (INVISIBLE.test(ch)) continue;
    if (/\s/.test(ch)) {
      if (!lastWasSpace) {
        out += " ";
        origin.push(start);
        lastWasSpace = true;
      }
      continue;
    }
    const digit = DEVANAGARI_DIGITS.indexOf(ch);
    const norm = digit >= 0 ? String(digit) : ch.normalize("NFKC").toLowerCase();
    for (let k = 0; k < norm.length; k++) origin.push(start);
    out += norm;
    lastWasSpace = false;
  }
  return { text: out, origin };
}

function normalize(text: string): string {
  return normalizeWithMap(text).text.trimEnd();
}

/** The searchable pieces of one evidence string. */
export function evidencePieces(evidence: string): string[] {
  return evidence
    .split(/\s*(?:…|\.\.\.)\s*/)
    .map((p) => p.replace(/\s*\([^()]*\)\s*$/, "").trim())
    .map(normalize)
    .filter((p) => p.length >= 2);
}

function escapeRegExp(s: string): string {
  return s.replace(/[.*+?^${}()|[\]\\]/g, "\\$&");
}

/** [start, end) in normalized text, or null. Tolerates a missing URL scheme and phone spacing. */
function findPiece(haystack: string, piece: string): [number, number] | null {
  const at = haystack.indexOf(piece);
  if (at >= 0) return [at, at + piece.length];

  // The backend adds http:// to links written without a scheme.
  const bare = piece.replace(/^https?:\/\//, "").replace(/^www\./, "");
  if (bare !== piece && bare.length >= 4) {
    const i = haystack.indexOf(bare);
    if (i >= 0) return [i, i + bare.length];
  }

  // Phone numbers: +919876543210 in the evidence, "98765 43210" or "98765-43210" in the text.
  const digits = piece.replace(/\D/g, "");
  if (/^[+\d\s-]+$/.test(piece) && digits.length >= 10) {
    const pattern = digits.slice(-10).split("").join("[\\s-]?");
    const m = new RegExp(pattern).exec(haystack);
    if (m) return [m.index, m.index + m[0].length];
  }

  // Whitespace differences that survived normalization (e.g. around punctuation).
  const loose = piece.split(/\s+/).map(escapeRegExp).join("\\s*");
  const m = new RegExp(loose).exec(haystack);
  return m ? [m.index, m.index + m[0].length] : null;
}

export type Segment = {
  text: string;
  /** Indexes into the flags array of the flags that cover this segment. */
  flags: number[];
};

export type HighlightResult = {
  segments: Segment[];
  /** Flags with evidence that couldn't be found in the text, or with no evidence at all. */
  unlocated: number[];
};

/** Split `text` into plain and highlighted segments for the flags' evidence. */
export function highlightEvidence(text: string, flags: RedFlag[]): HighlightResult {
  const { text: norm, origin } = normalizeWithMap(text);
  const ranges: { start: number; end: number; flag: number }[] = [];
  const unlocated: number[] = [];

  flags.forEach((flag, index) => {
    const pieces = flag.evidence ? evidencePieces(flag.evidence) : [];
    let found = false;
    for (const piece of pieces) {
      const hit = findPiece(norm, piece);
      if (!hit) continue;
      const [s, e] = hit;
      const start = origin[s];
      const lastChar = origin[e - 1];
      // End after the whole original character (surrogate pairs).
      const end = lastChar + (text.codePointAt(lastChar)! > 0xffff ? 2 : 1);
      ranges.push({ start, end, flag: index });
      found = true;
    }
    if (!found) unlocated.push(index);
  });

  const cuts = new Set<number>([0, text.length]);
  for (const r of ranges) {
    cuts.add(r.start);
    cuts.add(r.end);
  }
  const points = [...cuts].sort((a, b) => a - b);
  const segments: Segment[] = [];
  for (let i = 0; i < points.length - 1; i++) {
    const [a, b] = [points[i], points[i + 1]];
    const covering = [
      ...new Set(ranges.filter((r) => r.start <= a && r.end >= b).map((r) => r.flag)),
    ];
    const prev = segments.at(-1);
    if (prev && prev.flags.length === 0 && covering.length === 0) prev.text += text.slice(a, b);
    else segments.push({ text: text.slice(a, b), flags: covering });
  }
  return { segments, unlocated };
}
