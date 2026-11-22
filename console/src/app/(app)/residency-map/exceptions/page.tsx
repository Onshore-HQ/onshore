"use client";
import { tr } from "@/lib/i18n";
import { ArrowLeft } from "lucide-react";
import Link from "next/link";
import { useState } from "react";
import { FilterSelect } from "@/components/table-tools";
import { Empty, Loading } from "@/components/ui";
import { Button } from "@/components/ui/button";
import { control, useLoad } from "@/lib/api";
import { Exception, ExceptionsTable } from "../exceptions-table";
import { MapFrame } from "../shared";

function Register({ vault }: { vault: string }) {
  const [status, setStatus] = useState("");
  const [window, setWindow] = useState("");
  const qs = new URLSearchParams({ vault_id: vault, ...(status ? { status } : {}), ...(window ? { expiring_days: window } : {}) }).toString();
  const r = useLoad<{ exceptions: (Exception & { flow_id: string; source_name: string; dest_name: string })[] }>(() => control(`/v1/map/exceptions?${qs}`), [qs]);
  return (
    <div className="grid gap-3">
      <div className="row flex-wrap">
        <FilterSelect label={tr("Status")} all={tr("Any status")} value={status} onChange={setStatus} options={[["pending", tr("Pending")], ["active", tr("In force")], ["expired", tr("Expired")], ["revoked", tr("Revoked")]]} />
        <FilterSelect label={tr("Expiring")} all={tr("Any expiry")} value={window} onChange={setWindow} options={[["14", tr("Within 14 days")], ["30", tr("Within 30 days")], ["90", tr("Within 90 days")]]} />
      </div>
      <Loading error={r.error} loading={r.loading && !r.value} />
      {r.value && (r.value.exceptions.length === 0 ? <Empty title={tr("No exceptions match")}>{tr("An exception accepts a risk on one flow for a limited time. Request one from the flow’s page.")}</Empty> : <ExceptionsTable rows={r.value.exceptions} reload={r.reload} flowColumn />)}
    </div>
  );
}

export default function Exceptions() {
  return (
    <MapFrame title={tr("Exceptions")} sub={tr("Every accepted risk, who approved it and when it ends. An exception never makes a flow look safe without saying so.")} actions={() => <Button variant="outline" size="sm" asChild><Link href="/residency-map"><ArrowLeft /> {tr("Back to the map")}</Link></Button>}>
      {(vault) => <Register key={vault} vault={vault} />}
    </MapFrame>
  );
}
