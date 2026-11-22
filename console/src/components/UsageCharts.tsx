"use client";
import { tr } from "@/lib/i18n";
import { useState } from "react";
import { n } from "@/lib/api";

export interface Slice { key: string; label: string; value: number; color: string; hint?: string }

/** A total in the middle, its parts around it. Every part is also listed with its number, so color is never the only key. */
export function Donut({ slices, total, caption }: { slices: Slice[]; total: number; caption: string }) {
  const [hover, setHover] = useState<string | null>(null);
  const R = 70, W = 22, C = 2 * Math.PI * R;
  let offset = 0;
  const shown = slices.filter((s) => s.value > 0);
  return (
    <div className="donut">
      <svg viewBox="0 0 200 200" width={200} height={200} role="img" aria-label={`${caption}: ${n(total)}`}>
        <circle cx={100} cy={100} r={R} fill="none" stroke="var(--muted)" strokeWidth={W} />
        {shown.map((s) => {
          const len = total ? (s.value / total) * C : 0;
          // A hairline gap between parts, so neighbours never merge.
          const el = <circle key={s.key} cx={100} cy={100} r={R} fill="none" stroke={s.color} strokeWidth={hover === s.key ? W + 6 : W} strokeDasharray={`${Math.max(len - 1.5, 0.5)} ${C}`} strokeDashoffset={-offset} transform="rotate(-90 100 100)" onMouseEnter={() => setHover(s.key)} onMouseLeave={() => setHover(null)} style={{ transition: "stroke-width .15s" }}><title>{`${s.label}: ${n(s.value)}`}</title></circle>;
          offset += len;
          return el;
        })}
        <text x={100} y={98} textAnchor="middle" className="donut-total">{compact(total)}</text>
        <text x={100} y={120} textAnchor="middle" className="donut-caption">{caption}</text>
      </svg>
      <ul className="donut-legend">
        {slices.map((s) => (
          <li key={s.key} onMouseEnter={() => setHover(s.key)} onMouseLeave={() => setHover(null)} className={hover === s.key ? "on" : ""}>
            <i style={{ background: s.color }} aria-hidden />
            <span className="min-w-0 flex-1"><span className="block">{s.label}</span>{s.hint && <span className="block text-[12px] text-muted-foreground">{s.hint}</span>}</span>
            <b className="tabular-nums">{n(s.value)}</b>
            <span className="w-12 text-right text-[12px] text-muted-foreground tabular-nums">{total ? `${Math.round((s.value / total) * 100)}%` : "0%"}</span>
          </li>
        ))}
      </ul>
    </div>
  );
}

export function compact(v: number) {
  if (v >= 1_000_000) return `${(v / 1_000_000).toFixed(v >= 10_000_000 ? 0 : 1)}m`;
  if (v >= 10_000) return `${Math.round(v / 1000)}k`;
  if (v >= 1000) return `${(v / 1000).toFixed(1)}k`;
  return String(v);
}

export interface BarSeries { key: string; label: string; color: string }

/** One bar per day, stacked by series. Days with nothing still get a slot, so gaps are visible as gaps. */
export function DailyBars({ days, series }: { days: { day: string; values: Record<string, number> }[]; series: BarSeries[] }) {
  const [tip, setTip] = useState<number | null>(null);
  const W = 560, H = 210, L = 40, B = 24, T = 10;
  const totals = days.map((d) => series.reduce((s, x) => s + (d.values[x.key] ?? 0), 0));
  const max = niceMax(Math.max(1, ...totals));
  const slot = (W - L) / Math.max(days.length, 1);
  const bw = Math.max(Math.min(slot * 0.62, 34), 3);
  const y = (v: number) => T + (H - T - B) * (1 - v / max);
  const every = Math.ceil(days.length / 8);
  return (
    <div className="relative">
      <svg viewBox={`0 0 ${W} ${H}`} className="block w-full" role="img" aria-label={tr("Operations per day")}>
        {[0, 0.5, 1].map((f) => (
          <g key={f}>
            <line x1={L} x2={W} y1={y(max * f)} y2={y(max * f)} stroke="var(--border)" />
            <text x={L - 8} y={y(max * f) + 4} textAnchor="end" className="axis">{compact(max * f)}</text>
          </g>
        ))}
        {days.map((d, i) => {
          let acc = 0;
          const x = L + i * slot + (slot - bw) / 2;
          return (
            <g key={d.day} onMouseEnter={() => setTip(i)} onMouseLeave={() => setTip(null)}>
              <rect x={L + i * slot} y={T} width={slot} height={H - T - B} fill={tip === i ? "var(--accent)" : "transparent"} opacity={0.5} />
              {series.map((s) => {
                const v = d.values[s.key] ?? 0;
                if (!v) return null;
                const top = y(acc + v), h = y(acc) - top;
                acc += v;
                return <rect key={s.key} x={x} y={top} width={bw} height={Math.max(h - 1, 1)} rx={2} fill={s.color} />;
              })}
              {i % every === 0 && <text x={L + i * slot + slot / 2} y={H - 6} textAnchor="middle" className="axis">{short(d.day)}</text>}
            </g>
          );
        })}
      </svg>
      {tip !== null && (
        <div className="bar-tip" style={{ left: `${((L + tip * slot + slot / 2) / W) * 100}%` }}>
          <b>{short(days[tip]!.day)}</b>
          {series.map((s) => <div key={s.key} className="row small"><i style={{ background: s.color }} className="inline-block size-2 rounded-sm" />{s.label}<b className="ml-auto tabular-nums">{n(days[tip]!.values[s.key] ?? 0)}</b></div>)}
        </div>
      )}
      <div className="row mt-1 gap-4 text-[12.5px] text-muted-foreground">{series.map((s) => <span key={s.key} className="row gap-1.5"><i style={{ background: s.color }} className="inline-block size-2.5 rounded-sm" />{s.label}</span>)}</div>
    </div>
  );
}

const short = (iso: string) => new Date(iso).toLocaleDateString("en-NG", { day: "2-digit", month: "short", timeZone: "UTC" });
function niceMax(v: number) {
  const p = 10 ** Math.floor(Math.log10(v));
  for (const m of [1, 2, 2.5, 5, 10]) if (m * p >= v) return m * p;
  return 10 * p;
}
