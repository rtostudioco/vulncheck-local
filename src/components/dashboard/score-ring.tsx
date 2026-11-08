"use client";

/**
 * VulnCheck Local — SVG donut score ring.
 * Emerald arc on a graphite track; band colors:
 * ≥90 emerald, 65–89 amber, 40–64 orange, <40 red.
 */

import { cn } from "@/lib/utils";

interface ScoreRingProps {
  score: number | null;
  grade?: string | null;
  size?: number;
  className?: string;
}

export function ScoreRing({ score, grade, size = 150, className }: ScoreRingProps) {
  const stroke = 10;
  const center = size / 2;
  const radius = (size - stroke) / 2;
  const circumference = 2 * Math.PI * radius;
  const clamped = score == null ? 0 : Math.max(0, Math.min(100, score));
  const arc = (circumference * clamped) / 100;

  const bandClass =
    score == null
      ? "stroke-muted-foreground/40"
      : score >= 90
        ? "stroke-emerald-500"
        : score >= 65
          ? "stroke-amber-500"
          : score >= 40
            ? "stroke-orange-500"
            : "stroke-red-500";
  const textClass =
    score == null
      ? "fill-muted-foreground"
      : score >= 90
        ? "fill-emerald-500"
        : score >= 65
          ? "fill-amber-500"
          : score >= 40
            ? "fill-orange-500"
            : "fill-red-500";

  return (
    <svg
      width={size}
      height={size}
      viewBox={`0 0 ${size} ${size}`}
      role="img"
      aria-label={`Security posture score ${score ?? "unavailable"} of 100${grade ? `, grade ${grade}` : ""}`}
      className={cn("shrink-0", className)}
    >
      <circle
        cx={center}
        cy={center}
        r={radius}
        fill="none"
        strokeWidth={stroke}
        className="stroke-muted"
      />
      <circle
        cx={center}
        cy={center}
        r={radius}
        fill="none"
        strokeWidth={stroke}
        strokeLinecap="round"
        strokeDasharray={`${arc} ${circumference - arc}`}
        transform={`rotate(-90 ${center} ${center})`}
        className={cn("transition-[stroke-dasharray] duration-500", bandClass)}
      />
      <text
        x={center}
        y={grade ? center - 4 : center}
        textAnchor="middle"
        dominantBaseline="central"
        fontSize={size * 0.24}
        fontWeight={600}
        className={cn("font-mono tabular-nums", textClass)}
      >
        {score == null ? "—" : Math.round(score)}
      </text>
      {grade ? (
        <text
          x={center}
          y={center + 22}
          textAnchor="middle"
          dominantBaseline="central"
          fontSize={size * 0.115}
          className="fill-muted-foreground font-medium uppercase tracking-widest"
        >
          Grade {grade}
        </text>
      ) : null}
    </svg>
  );
}
