"use client";

import { motion } from "motion/react";
import { usePrefersReducedMotion } from "@/lib/useReducedMotion";

// Semicircle of radius R centred on (CX, CY), from the left end (score 0) to the right (100).
const R = 80;
const CX = 100;
const CY = 100;
const ARC = `M ${CX - R} ${CY} A ${R} ${R} 0 0 1 ${CX + R} ${CY}`;

function pointAt(score: number, radius: number) {
  const angle = Math.PI * (1 - score / 100);
  return { x: CX + radius * Math.cos(angle), y: CY - radius * Math.sin(angle) };
}

type ScoreGaugeProps = {
  score: number;
  /** CSS colour of the filled part (the verdict colour). */
  color: string;
  /** Score thresholds to mark on the dial. */
  ticks?: number[];
  className?: string;
};

/** Risk score out of 100 as a semicircle gauge; the fill animates in unless motion is reduced. */
export function ScoreGauge({ score, color, ticks = [35, 70], className }: ScoreGaugeProps) {
  const reduced = usePrefersReducedMotion();
  const value = Math.max(0, Math.min(100, score)) / 100;

  return (
    <svg
      viewBox="0 0 200 118"
      role="img"
      aria-label={`Risk score ${score} out of 100`}
      className={className}
    >
      {/* Track with an ink outline */}
      <path d={ARC} fill="none" stroke="var(--color-ink)" strokeWidth={26} />
      <path d={ARC} fill="none" stroke="var(--color-card)" strokeWidth={21} />
      <motion.path
        d={ARC}
        fill="none"
        stroke={color}
        strokeWidth={21}
        initial={reduced ? false : { pathLength: 0 }}
        animate={{ pathLength: value }}
        transition={{ duration: 1.1, ease: [0.22, 1, 0.36, 1], delay: 0.15 }}
        style={{ pathLength: reduced ? value : undefined }}
      />
      {ticks.map((t) => {
        const a = pointAt(t, R - 13);
        const b = pointAt(t, R + 13);
        return (
          <line
            key={t}
            x1={a.x}
            y1={a.y}
            x2={b.x}
            y2={b.y}
            stroke="var(--color-ink)"
            strokeWidth={2.5}
          />
        );
      })}
      <text
        x={CX}
        y={CY - 6}
        textAnchor="middle"
        className="fill-ink font-display font-extrabold"
        fontSize={46}
      >
        {score}
      </text>
      <text x={CX} y={CY + 16} textAnchor="middle" className="fill-ink-muted font-semibold" fontSize={14}>
        out of 100
      </text>
    </svg>
  );
}
