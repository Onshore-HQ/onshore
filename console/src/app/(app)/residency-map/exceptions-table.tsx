"use client";
import { tr } from "@/lib/i18n";
import Link from "next/link";
import { useState } from "react";
import { useMe } from "@/components/Shell";
import { Badge, TypedConfirm } from "@/components/ui";
import { Button } from "@/components/ui/button";
import { Table, TableBody, TableCell, TableHead, TableHeader, TableRow } from "@/components/ui/table";
import { control, day } from "@/lib/api";
import { Person } from "@/lib/people";
import { MAP_APPROVE } from "./shared";

export interface Exception { id: string; reason: string; compensating_controls: string | null; requested_by: string; approved_by: string | null; approved_at: string | null; expires_at: string; status: string }

export function ExceptionsTable({ rows, reload, flowColumn }: { rows: (Exception & { flow_id?: string; source_name?: string; dest_name?: string })[]; reload: () => void; flowColumn?: boolean }) {
  const me = useMe();
  const canApprove = (me?.roles ?? []).some((r) => MAP_APPROVE.includes(r));
  const [approve, setApprove] = useState<string | null>(null);
  const [revoke, setRevoke] = useState<string | null>(null);
  return (
    <>
      <div className="data-table"><Table><TableHeader><TableRow>{flowColumn && <TableHead>{tr("Flow")}</TableHead>}<TableHead>{tr("Reason")}</TableHead><TableHead>{tr("Compensating controls")}</TableHead><TableHead>{tr("Requested by")}</TableHead><TableHead>{tr("Approved by")}</TableHead><TableHead>{tr("Expires")}</TableHead><TableHead>{tr("Status")}</TableHead><TableHead /></TableRow></TableHeader>
        <TableBody>{rows.map((e) => (
          <TableRow key={e.id}>
            {flowColumn && <TableCell><Link className="underline" href={`/residency-map/flows/${e.flow_id}`}>{e.source_name} → {e.dest_name}</Link></TableCell>}
            <TableCell className="max-w-[260px]">{e.reason}</TableCell><TableCell className="max-w-[200px]">{e.compensating_controls ?? tr("None given")}</TableCell><TableCell><Person id={e.requested_by} /></TableCell>
            <TableCell>{e.approved_by ? <><Person id={e.approved_by} /><div className="text-[12px] text-muted-foreground">{day(e.approved_at)}</div></> : tr("Not yet")}</TableCell><TableCell className="whitespace-nowrap">{day(e.expires_at)}</TableCell>
            <TableCell><Badge tone={e.status === "active" ? "warn" : e.status === "pending" ? "info" : ""}>{e.status === "active" ? tr("In force") : e.status[0]!.toUpperCase() + e.status.slice(1)}</Badge></TableCell>
            <TableCell>{canApprove && <span className="row">{e.status === "pending" && e.requested_by !== me?.id && <Button size="sm" onClick={() => setApprove(e.id)}>{tr("Approve")}</Button>}{(e.status === "pending" || e.status === "active") && <Button size="sm" variant="ghost" onClick={() => setRevoke(e.id)}>{tr("Revoke")}</Button>}</span>}{e.status === "pending" && e.requested_by === me?.id && <span className="text-[12px] text-muted-foreground">{tr("Needs someone else")}</span>}</TableCell>
          </TableRow>
        ))}</TableBody></Table></div>
      {approve && <TypedConfirm title={tr("Approve this exception")} word="approve" onClose={() => setApprove(null)} onConfirm={async () => { await control(`/v1/map/exceptions/${approve}/approve`, { method: "POST" }); reload(); }}>{tr("You accept this risk in your name until it expires. It will appear in the residency report as an accepted risk.")}</TypedConfirm>}
      {revoke && <TypedConfirm title={tr("Revoke this exception")} word="revoke" onClose={() => setRevoke(null)} onConfirm={async () => { await control(`/v1/map/exceptions/${revoke}/revoke`, { method: "POST" }); reload(); }}>{tr("The flow goes back to its real status at once.")}</TypedConfirm>}
    </>
  );
}

