export function Logo() {
  return (
    <span style={{ display: "inline-flex", alignItems: "center", gap: 8 }}>
      <svg width="24" height="24" viewBox="0 0 32 32" aria-hidden>
        <path d="M16 3a13 13 0 0 1 13 13H3A13 13 0 0 1 16 3Z" fill="currentColor" />
        <path d="M3 20h26M8 25h16" stroke="#2574de" strokeWidth="2.8" />
      </svg>
      <span style={{ fontSize: 20, letterSpacing: "-0.04em", fontWeight: 500 }}>onshore</span>
      <span style={{ fontSize: 12, fontWeight: 500, padding: "2px 7px", borderRadius: 999, background: "rgba(37,116,222,.12)", color: "#1b5fbf" }}>Docs</span>
    </span>
  );
}
