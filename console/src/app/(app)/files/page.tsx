"use client";
import { tr } from "@/lib/i18n";
import { useEffect, useState } from "react";
import { Badge, ErrorLine, Page } from "@/components/ui";
import { control, useLoad } from "@/lib/api";

function save(blob: Blob, name: string) {
  const url = URL.createObjectURL(blob);
  const a = document.createElement("a");
  a.href = url;
  a.download = name;
  a.click();
  URL.revokeObjectURL(url);
}

export default function Files() {
  const vaults = useLoad<{ vaults: { id: string; name: string }[] }>(() => control("/v1/vaults"));
  const [vault, setVault] = useState("");
  const [purpose, setPurpose] = useState("");
  const [file, setFile] = useState<File | null>(null);
  const [busy, setBusy] = useState(false);
  const [error, setError] = useState<string | null>(null);
  const [result, setResult] = useState<{ findings: Record<string, number>; low: boolean; transcript?: string } | null>(null);
  const list = vaults.value?.vaults ?? [];
  useEffect(() => { if (!vault && list[0]) setVault(list[0].id); }, [list, vault]);
  return (
    <Page title={tr("Redact a file")} sub={tr("Upload a PDF, image, recording or text file, and download a copy with sensitive data removed. Onshore keeps nothing. PDFs come back as pictures of their pages, so no hidden text survives.")}>
      <div className="card" style={{ maxWidth: 620 }}>
        <label className="field"><span>{tr("Vault, for policy and audit")}</span><select value={vault} onChange={(e) => setVault(e.target.value)}>{list.map((v) => <option key={v.id} value={v.id}>{v.name}</option>)}</select></label>
        <label className="field"><span>{tr("Purpose or ticket ID")}</span><input value={purpose} onChange={(e) => setPurpose(e.target.value)} /></label>
        <label className="field"><span>{tr("File, up to 64 MB")}</span><input type="file" onChange={(e) => setFile(e.target.files?.[0] ?? null)} /></label>
        <div className="row"><button className="primary" disabled={!file || !vault || purpose.trim().length < 3 || busy} onClick={async () => {
          setBusy(true); setError(null); setResult(null);
          try {
            const res = await fetch(`/api/proxy/files/${vault}/redact`, { method: "POST", headers: { "x-rv-console": "1", "x-rv-purpose": purpose, "content-type": "application/octet-stream" }, body: file });
            if (!res.ok) { const d = await res.json().catch(() => ({})); throw new Error(d.error?.message ?? "the file could not be redacted"); }
            const findings = JSON.parse(res.headers.get("x-rv-findings") ?? "{}");
            const low = res.headers.get("x-rv-low-confidence") === "true";
            const type = res.headers.get("content-type") ?? "";
            let transcript: string | undefined;
            if (type.includes("application/json")) {
              const d = await res.json();
              transcript = d.transcript;
              save(new Blob([Uint8Array.from(atob(d.audio_wav), (c) => c.charCodeAt(0))], { type: "audio/wav" }), "redacted.wav");
            } else {
              save(await res.blob(), `redacted-${file!.name}`);
            }
            setResult({ findings, low, transcript });
          } catch (e) { setError(e instanceof Error ? e.message : "failed"); } finally { setBusy(false); }
        }}>{busy ? tr("Working…") : tr("Redact and download")}</button></div>
        <ErrorLine error={error} />
        {result && (
          <div className="stack" style={{ gap: 6 }}>
            {result.low && <div className="note warn">{tr("The text could not be read with confidence. A person should check this file: a clean result here does not mean it is clean.")}</div>}
            <div className="row">{Object.keys(result.findings).length === 0 ? <Badge>{tr("nothing found")}</Badge> : Object.entries(result.findings).map(([k, v]) => <Badge key={k} tone="info">{k}: {v}</Badge>)}</div>
            {result.transcript && <pre className="pre">{result.transcript}</pre>}
          </div>
        )}
      </div>
      <p className="small muted" style={{ marginTop: 10 }}>{tr("Detection reads text only. It does not remove faces, signatures or stamps from a KYC image.")}</p>
    </Page>
  );
}
