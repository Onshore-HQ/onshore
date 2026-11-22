import { COUNTRIES, LAWS } from "../lib/countries.js";

/** Every country with a built-in pack: its data types with examples, and the laws setup suggests. */
export function CountryTable() {
  return (
    <div style={{ overflowX: "auto" }}>
      <table>
        <thead><tr><th>Country</th><th>Pack</th><th>Data types, with made-up examples</th><th>Laws setup suggests</th><th>Time zone and formats</th></tr></thead>
        <tbody>
          {COUNTRIES.map((c) => (
            <tr key={c.code}>
              <td><code>{c.code}</code> {c.name}</td>
              <td>{c.pack}</td>
              <td>{c.types.map(([n, v]) => <div key={n}>{n}: <code>{v}</code></div>)}</td>
              <td>{c.laws.length ? c.laws.map((l) => <div key={l}><a href={LAWS[l].source} target="_blank" rel="noreferrer">{LAWS[l].name}</a></div>) : "None by default"}</td>
              <td><div>{c.zone}</div><code>{c.format}</code></td>
            </tr>
          ))}
        </tbody>
      </table>
    </div>
  );
}

/** Every law in the catalogue with what it adds and its source. */
export function LawTable() {
  return (
    <div style={{ overflowX: "auto" }}>
      <table>
        <thead><tr><th>Law</th><th>Suggested for</th><th>What it adds in Onshore</th><th>Source</th></tr></thead>
        <tbody>
          {Object.entries(LAWS).map(([id, l]) => {
            const where = COUNTRIES.filter((c) => c.laws.includes(id)).map((c) => c.name);
            return (
              <tr key={id}>
                <td>{l.name}</td>
                <td>{where.length ? where.join(", ") : id === "dora" ? "Financial firms in the EU" : "By sector"}</td>
                <td>{l.effect}</td>
                <td><a href={l.source} target="_blank" rel="noreferrer">Source</a></td>
              </tr>
            );
          })}
        </tbody>
      </table>
    </div>
  );
}
