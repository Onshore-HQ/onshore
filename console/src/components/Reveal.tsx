"use client";
import { tr } from "@/lib/i18n";
import { useEffect, useState } from "react";
import { data } from "@/lib/api";
import { DecisionBadge, ErrorLine, Modal } from "./ui";

const HIDE_AFTER_SECONDS = 30;

/** A reveal takes a click and a stated purpose, is watermarked, and hides itself. */
export function RevealButton({ vaultId, token, viewer, label }: { vaultId: string; token: string; viewer: string; label: string }) {
  const [open, setOpen] = useState(false);
  const [purpose, setPurpose] = useState("");
  const [result, setResult] = useState<{ value: string; decision: string; policy: string } | null>(null);
  const [left, setLeft] = useState(HIDE_AFTER_SECONDS);
  const [error, setError] = useState<string | null>(null);
  const [busy, setBusy] = useState(false);

  useEffect(() => {
    if (!result) return;
    setLeft(HIDE_AFTER_SECONDS);
    const t = setInterval(() => setLeft((s) => s - 1), 1000);
    return () => clearInterval(t);
  }, [result]);

  const close = () => {
    setOpen(false);
    setResult(null);
    setPurpose("");
    setError(null);
  };
  useEffect(() => {
    if (result && left <= 0) close();
  }, [left, result]);

  const reveal = async () => {
    setBusy(true);
    setError(null);
    try {
      const r = await data<{ results: { decision: string; value?: string; policy: string; error?: { message: string; code: string } }[] }>(`/v1/vaults/${vaultId}/detokenize`, { body: { items: [{ token }], purpose, continue_on_error: true } });
      const item = r.results[0]!;
      if (item.error) setError(item.error.code === "rate_limited" ? "You have reached your reveal limit for this hour." : tr("A policy denied this ({0}).", { 0: item.policy }));
      else setResult({ value: item.value ?? "", decision: item.decision, policy: item.policy });
    } catch (e) {
      setError(e instanceof Error ? e.message : "failed");
    } finally {
      setBusy(false);
    }
  };

  return (
    <>
      <button className="desktop-only" onClick={() => setOpen(true)}>{tr("Reveal")}</button>
      {open && (
        <Modal title={tr("Reveal {0}", { 0: label })} onClose={close}>
          {result ? (
            <>
              <div className="reveal">
                {result.value}
                <span className="watermark">{viewer} · {new Date().toLocaleString(undefined, { timeZoneName: "short" })}</span>
              </div>
              <div className="spread small muted">
                <span className="row"><DecisionBadge value={result.decision} /> {result.policy}</span>
                <span>{tr("Hides in")} {left}s</span>
              </div>
              <div className="row" style={{ justifyContent: "flex-end" }}><button onClick={close}>{tr("Hide now")}</button></div>
            </>
          ) : (
            <>
              <p className="muted">{tr("This reveal is recorded with your name, network and purpose.")}</p>
              <label className="field">
                <span>{tr("Purpose or ticket ID")}</span>
                <input autoFocus value={purpose} maxLength={500} onChange={(e) => setPurpose(e.target.value)} placeholder={tr("Ticket 88213: failed transfer")} />
              </label>
              <ErrorLine error={error} />
              <div className="row" style={{ justifyContent: "flex-end" }}>
                <button onClick={close}>{tr("Cancel")}</button>
                <button className="primary" disabled={purpose.trim().length < 3 || busy} onClick={reveal}>{tr("Reveal value")}</button>
              </div>
            </>
          )}
        </Modal>
      )}
    </>
  );
}
