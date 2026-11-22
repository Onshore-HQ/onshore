"use client";
import { tr } from "@/lib/i18n";
import { ShownOnce } from "@/components/ui";

export interface AccountLink { emailed: boolean; token?: string; reason?: string; message?: string }

/** Without email, or when it fails, the admin gets the link to pass on themselves. */
export function InviteLink({ token, message, what }: { token: string; message?: string; what: string }) {
  return (
    <>
      {message ? <div className="note bad small">{tr("The email didn't go:")} {message}</div> : <div className="note small">{tr("Email isn't set up, so nothing was sent. You can set it up in")} <a href="/settings?tab=email">{tr("Settings")}</a>.</div>}
      <p className="muted">{what} {tr("Send it somewhere only they can read.")}</p>
      <ShownOnce items={[{ label: "Link", value: `${window.location.origin}/account#token=${token}` }]} />
    </>
  );
}
