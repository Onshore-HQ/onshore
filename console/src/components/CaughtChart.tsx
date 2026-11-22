"use client";
import { tr } from "@/lib/i18n";
import { ShieldCheck } from "lucide-react";
import { useMemo, useState } from "react";
import { n } from "@/lib/api";
import { compact } from "./UsageCharts";

// Color follows the entity, never its rank; everything else folds into Other.
const SERIES: { key: string; label: string; color: string }[] = [
  { key: "bvn", label: "BVN", color: "var(--series-1)" },
  { key: "nuban", label: "Account number", color: "var(--series-2)" },
  { key: "phone_ng", label: "Phone", color: "var(--series-3)" },
  { key: "nin", label: "NIN", color: "var(--series-4)" },
  { key: "card_pan", label: "Card", color: "var(--series-5)" },
  { key: "email", label: "Email", color: "var(--series-6)" },
  { key: "person_name", label: "Name", color: "var(--series-7)" },
  { key: "other", label: "Other", color: "var(--series-other)" },
];
const KNOWN = new Set(SERIES.map((s) => s.key));

interface Row { day: string; entity_type: string; destination: string; n: number }

const W = 760, H = 210, L = 44, B = 22, T = 8, GAP = 2;

function dayLabel(iso: string) {
  return new Date(iso).toLocaleDateString("en-NG", { day: "2-digit", month: "short", timeZone: "UTC" });
}

export function CaughtChart({ rows, customNames = {} }: { rows: Row[]; customNames?: Record<string, string> }) {
  const [groupCustom, setGroupCustom] = useState(false);
  const customKeys = useMemo(() => [...new Set(rows.map((r) => r.entity_type).filter((e) => e.startsWith("c_")))].sort(), [rows]);
  // Color follows the entity by name, so it does not move as others come and go.
  const series = useMemo(() => {
    const colorFor = (slug: string) => `var(--series-${([...slug].reduce((h, c) => (h * 31 + c.charCodeAt(0)) >>> 0, 7) % 7) + 1})`;
    const custom = groupCustom
      ? (customKeys.length ? [{ key: "custom", label: tr("All custom"), color: "var(--primary)" }] : [])
      : customKeys.map((k) => ({ key: k, label: customNames[k] ?? k, color: colorFor(k) }));
    return [...SERIES.slice(0, -1), ...custom, SERIES[SERIES.length - 1]!];
  }, [customKeys, customNames, groupCustom]);
  const [view, setView] = useState<"chart" | "table">("chart");
  const [tip, setTip] = useState<{ x: number; y: number; day: string; items: [string, string, number][]; total: number } | null>(null);
  const [destination, setDestination] = useState("");
  const destinations = useMemo(() => [...new Set(rows.map((r) => r.destination).filter(Boolean))], [rows]);

  const days = useMemo(() => {
    const out: { day: string; values: Record<string, number>; total: number }[] = [];
    const today = new Date();
    for (let i = 13; i >= 0; i--) {
      const d = new Date(Date.UTC(today.getUTCFullYear(), today.getUTCMonth(), today.getUTCDate() - i));
      out.push({ day: d.toISOString().slice(0, 10), values: {}, total: 0 });
    }
    for (const r of rows) {
      if (destination && r.destination !== destination) continue;
      const slot = out.find((d) => d.day === new Date(r.day).toISOString().slice(0, 10));
      if (!slot) continue;
      const key = r.entity_type.startsWith("c_") ? (groupCustom ? "custom" : r.entity_type) : KNOWN.has(r.entity_type) ? r.entity_type : "other";
      slot.values[key] = (slot.values[key] ?? 0) + Number(r.n);
      slot.total += Number(r.n);
    }
    return out;
  }, [rows, destination, groupCustom]);

  const present = series.filter((s) => days.some((d) => d.values[s.key]));
  const max = Math.max(1, ...days.map((d) => d.total));
  const nice = (() => {
    const p = 10 ** Math.floor(Math.log10(max));
    return [1, 2, 5, 10].map((m) => m * p).find((v) => v >= max) ?? max;
  })();
  const plotH = H - B - T;
  const barW = Math.min(34, (W - L) / days.length - 8);
  const step = (W - L) / days.length;

  return (
    <div className="stack" style={{ gap: 8 }}>
      <div className="spread">
        <div className="row">
          {customKeys.length > 0 && <label className="row small"><input type="checkbox" checked={groupCustom} onChange={(e) => setGroupCustom(e.target.checked)} />{tr("All custom")}</label>}
          {destinations.length > 0 && (
            <select aria-label={tr("Destination")} value={destination} onChange={(e) => setDestination(e.target.value)}>
              <option value="">{tr("All destinations")}</option>
              {destinations.map((d) => <option key={d}>{d}</option>)}
            </select>
          )}
        </div>
        <div className="tabs compact">
          <button type="button" className={view === "chart" ? "on" : ""} onClick={() => setView("chart")}>{tr("Chart")}</button>
          <button type="button" className={view === "table" ? "on" : ""} onClick={() => setView("table")}>{tr("Table")}</button>
        </div>
      </div>
      {view === "chart" && present.length === 0 ? (
        <div className="empty-chart"><span className="tile teal" aria-hidden><ShieldCheck className="size-[18px]" /></span><div className="font-medium text-foreground">{tr("Nothing detected in the last 14 days")}</div><div className="max-w-[52ch]">{tr("Connect your logs in watch-only mode to see what is leaving. It only counts, so it changes nothing.")}</div></div>
      ) : view === "chart" ? (
        <>
          <svg viewBox={`0 0 ${W} ${H}`} width="100%" role="img" aria-label={tr("Identifiers detected per day by type")} onPointerLeave={() => setTip(null)}>
            {[0, 0.5, 1].map((f) => {
              const y = T + plotH - f * plotH;
              return (
                <g key={f}>
                  <line x1={L} x2={W} y1={y} y2={y} stroke="var(--border)" strokeWidth={1} />
                  <text x={L - 6} y={y + 4} textAnchor="end" fontSize={11} fill="var(--muted-foreground)">{compact(nice * f)}</text>
                </g>
              );
            })}
            {days.map((d, i) => {
              const x = L + i * step + (step - barW) / 2;
              let y = T + plotH;
              const stack = present.filter((s) => d.values[s.key]);
              return (
                <g key={d.day}>
                  {stack.map((s, si) => {
                    const h = Math.max(1, ((d.values[s.key] ?? 0) / nice) * plotH - (si < stack.length - 1 ? GAP : 0));
                    y -= h;
                    const top = si === stack.length - 1;
                    const rect = top
                      ? <path d={`M${x},${y + h} V${y + Math.min(4, h)} Q${x},${y} ${x + Math.min(4, barW / 2)},${y} H${x + barW - Math.min(4, barW / 2)} Q${x + barW},${y} ${x + barW},${y + Math.min(4, h)} V${y + h} Z`} fill={s.color} />
                      : <rect x={x} y={y} width={barW} height={h} fill={s.color} />;
                    y -= top ? 0 : GAP;
                    return <g key={s.key}>{rect}</g>;
                  })}
                  {(i % 2 === 1 || days.length < 8) && <text x={x + barW / 2} y={H - 6} textAnchor="middle" fontSize={11} fill="var(--muted-foreground)">{dayLabel(d.day)}</text>}
                  <rect
                    x={L + i * step} y={T} width={step} height={plotH} fill="transparent" tabIndex={0}
                    aria-label={tr("{0}: {1} detections", { 0: dayLabel(d.day), 1: d.total })}
                    onPointerMove={(e) => setTip({ x: e.clientX, y: e.clientY, day: d.day, total: d.total, items: stack.map((s) => [s.label, s.color, d.values[s.key] ?? 0]) })}
                    onFocus={(e) => { const r = e.currentTarget.getBoundingClientRect(); setTip({ x: r.right, y: r.top + 40, day: d.day, total: d.total, items: stack.map((s) => [s.label, s.color, d.values[s.key] ?? 0]) }); }}
                    onBlur={() => setTip(null)}
                  />
                </g>
              );
            })}
          </svg>
          {present.length >= 2 && (
            <div className="legend">{present.map((s) => <span key={s.key}><i style={{ background: s.color }} />{s.label}</span>)}</div>
          )}
          {present.length === 1 && <div className="legend"><span><i style={{ background: present[0]!.color }} />{present[0]!.label}</span></div>}
          {tip && (
            <div className="chart-tip" style={{ left: Math.min(tip.x + 14, window.innerWidth - 170), top: tip.y + 10 }}>
              <div className="muted" style={{ marginBottom: 3 }}>{dayLabel(tip.day)}</div>
              {tip.items.length === 0 && <div className="muted">{tr("No detections")}</div>}
              {tip.items.map(([label, color, v]) => (
                <div key={label}><span><i style={{ background: color, marginRight: 5, verticalAlign: 3 }} />{label}</span><b>{n(v)}</b></div>
              ))}
              {tip.items.length > 1 && <div style={{ borderTop: "1px solid var(--border)", marginTop: 3, paddingTop: 3 }}><span>{tr("Total")}</span><b>{n(tip.total)}</b></div>}
            </div>
          )}
        </>
      ) : (
        <div className="tablewrap" style={{ maxHeight: 280 }}>
          <table>
            <thead><tr><th>{tr("Day")}</th>{series.map((s) => <th key={s.key} className="num">{s.label}</th>)}<th className="num">{tr("Total")}</th></tr></thead>
            <tbody>
              {days.map((d) => (
                <tr key={d.day}><td>{dayLabel(d.day)}</td>{series.map((s) => <td key={s.key} className="num">{n(d.values[s.key])}</td>)}<td className="num"><b>{n(d.total)}</b></td></tr>
              ))}
            </tbody>
          </table>
        </div>
      )}
    </div>
  );
}

export function Sparkline({ points }: { points: { day: string; count: number }[] }) {
  const w = 120, h = 28;
  if (points.length === 0) return <span className="small faint">{tr("No detections yet")}</span>;
  const max = Math.max(1, ...points.map((p) => Number(p.count)));
  const total = points.reduce((s, p) => s + Number(p.count), 0);
  const pts = points.map((p, i) => `${points.length === 1 ? w / 2 : (i / (points.length - 1)) * (w - 4) + 2},${h - 3 - (Number(p.count) / max) * (h - 6)}`).join(" ");
  return (
    <span className="row small muted" title={tr("{0} detections in 14 days", { 0: n(total) })}>
      <svg width={w} height={h} role="img" aria-label={tr("{0} detections in 14 days", { 0: total })}>
        <polyline points={pts} fill="none" stroke="var(--series-1)" strokeWidth={2} strokeLinecap="round" strokeLinejoin="round" />
      </svg>
      {n(total)}
    </span>
  );
}
