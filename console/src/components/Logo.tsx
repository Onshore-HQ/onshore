/** The Onshore mark, the same as the website's: a dome over the horizon. `light` is for dark backgrounds. */
export function LogoMark({ light, size = 26, className = "" }: { light?: boolean; size?: number; className?: string }) {
  const ink = light ? "#fff" : "#0a1424";
  const line = light ? "#6cc2ff" : "#2574de";
  return (
    <svg width={size} height={size} viewBox="0 0 32 32" aria-hidden className={`shrink-0 ${className}`}>
      <path d="M16 3a13 13 0 0 1 13 13H3A13 13 0 0 1 16 3Z" fill={ink} />
      <path d="M3 20h26M8 25h16" stroke={line} strokeWidth="2.8" />
    </svg>
  );
}

export function Logo({ light, size = 26 }: { light?: boolean; size?: number }) {
  return (
    <span className="inline-flex items-center gap-2" style={{ color: light ? "#fff" : "#0a1424" }}>
      <LogoMark light={light} size={size} />
      <span style={{ fontSize: size * 0.86, letterSpacing: "-0.04em", fontWeight: 500, lineHeight: 1 }}>onshore</span>
    </span>
  );
}
