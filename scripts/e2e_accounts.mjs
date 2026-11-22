// Email, invitations and every way back into an account. Run from e2e.mjs, or alone with e2e_step2_alone.mjs.
import crypto from "node:crypto";
import net from "node:net";

/** The smallest mail server that works: it keeps what it is sent, for the tests to read. */
export function mailCatcher(port) {
  const inbox = [];
  const server = net.createServer((sock) => {
    let data = false, buf = "", msg = "";
    sock.write("220 catcher ESMTP\r\n");
    sock.on("error", () => {});
    sock.on("data", (d) => {
      buf += d.toString("latin1");
      for (;;) {
        if (data) {
          const end = buf.indexOf("\r\n.\r\n");
          // The end marker can arrive split across packets, so keep everything until it is whole.
          if (end < 0) return;
          msg = buf.slice(0, end); buf = buf.slice(end + 5); data = false;
          inbox.push(msg.replace(/=\r\n/g, "").replace(/=3D/g, "=")); msg = "";
          sock.write("250 ok\r\n");
          continue;
        }
        const nl = buf.indexOf("\r\n");
        if (nl < 0) return;
        const line = buf.slice(0, nl); buf = buf.slice(nl + 2);
        if (/^DATA/i.test(line)) { data = true; sock.write("354 go\r\n"); }
        else if (/^QUIT/i.test(line)) { sock.write("221 bye\r\n"); sock.end(); }
        else sock.write("250 ok\r\n");
      }
    });
  });
  return new Promise((r) => server.listen(port, "0.0.0.0", () => r({ inbox, close: () => server.close() })));
}

const tokenIn = (m) => /account#token=([\w-]+)/.exec(m)?.[1];

export async function runAccounts({ control, check, section, totp, sleep, sh, COMPOSE, adminToken, adminEmail, otherToken }) {
  section("Email and account recovery");
  const CATCH = 18985;
  const mail = await mailCatcher(CATCH);
  const waitMail = async (test, ms = 8000) => { const t0 = Date.now(); for (;;) { const m = mail.inbox.find(test); if (m) return m; if (Date.now() - t0 > ms) return null; await sleep(150); } };
  const to = (addr) => (m) => m.toLowerCase().includes(`to: ${addr}`);
  const uniq = crypto.randomBytes(3).toString("hex");
  const mailBody = { host: "host.docker.internal", port: CATCH, tls_mode: "none", from_address: "onshore@e2e.example.ng", from_name: "Onshore E2E", console_url: "https://localhost:8443", alerts_enabled: false };
  const ADMIN = adminToken();
  const nextStep = async (secret, offset = 0) => { await sleep(Math.max(0, 30000 - (Date.now() % 30000)) + 200); return totp(secret, offset); };

  // ---- Without email: an invitation still works, as a link to pass on.
  const noMailEmail = `nomail-${uniq}@e2e.example.ng`;
  const nm = await control("/v1/principals", { token: ADMIN, body: { kind: "user", display_name: "No Mail", email: noMailEmail, roles: ["engineer"], invite: true } });
  check("without email, an invitation returns a link to pass on, and no temporary password", nm.json.invite?.emailed === false && nm.json.invite.token?.length > 20 && !nm.json.temporary_password, nm.text);
  const people0 = await control("/v1/principals", { token: ADMIN });
  check("the person shows as invited", people0.json.principals.find((p) => p.id === nm.json.id)?.invite_pending === true);
  const rv = await control(`/v1/principals/${nm.json.id}/invite/revoke`, { token: ADMIN, method: "POST" });
  check("an invitation can be cancelled", rv.json.revoked === 1);
  check("a cancelled link no longer works", (await control("/v1/auth/account-link/check", { body: { token: nm.json.invite.token } })).status === 400);

  // ---- Settings
  check("only an admin can set up email", (await control("/v1/settings/mail", { token: otherToken(), method: "PUT", body: mailBody })).status === 403);
  check("a password can't be saved without a secure connection", (await control("/v1/settings/mail", { token: ADMIN, method: "PUT", body: { ...mailBody, username: "u", password: "p" } })).status === 400);
  check("email links must use https", (await control("/v1/settings/mail", { token: ADMIN, method: "PUT", body: { ...mailBody, console_url: "http://evil.example" } })).status === 400);
  const hostile = async (host, port) => {
    await control("/v1/settings/mail", { token: ADMIN, method: "PUT", body: { ...mailBody, host, port } });
    return control("/v1/settings/mail/test", { token: ADMIN, method: "POST" });
  };
  for (const [host, port, name] of [["postgres", 5432, "the database"], ["keys", 8200, "the key service"], ["127.0.0.1", 8081, "this container"], ["169.254.169.254", 80, "a cloud metadata address"]]) {
    const r = await hostile(host, port);
    check(`the mail setting can't reach ${name}`, r.status === 400 && /belongs to this installation|could not be found/.test(r.json?.error?.message ?? ""), r.text);
  }
  const closed = await hostile("host.docker.internal", 1);
  check("a failed test says what to check, without echoing the server", closed.status === 400 && /could not be reached/.test(closed.json?.error?.message ?? ""), closed.text);
  const saved = await control("/v1/settings/mail", { token: ADMIN, method: "PUT", body: mailBody });
  check("email settings save", saved.status === 200, saved.text);
  const test = await control("/v1/settings/mail/test", { token: ADMIN, method: "POST" });
  check("a test email arrives", test.status === 200 && Boolean(await waitMail((m) => m.includes("Email from Onshore is working"))), test.text);
  const got = await control("/v1/settings/mail", { token: ADMIN });
  check("the settings show it as working", Boolean(got.json.verified_at) && got.json.has_password === false && !("password_enc" in got.json));

  // ---- Invitation
  const email = `invited-${uniq}@e2e.example.ng`;
  const inv = await control("/v1/principals", { token: ADMIN, body: { kind: "user", display_name: "Ify Invited", email, roles: ["admin"], invite: true } });
  check("an invitation is emailed, and its link isn't returned to the admin", inv.json.invite?.emailed === true && !inv.json.invite.token, inv.text);
  const invMail = await waitMail(to(email));
  const invToken = tokenIn(invMail ?? "");
  check("the email holds a link to this console, with the token after the #", Boolean(invToken) && invMail.includes("https://localhost:8443/account#token="));
  const stored = sh(`${COMPOSE} exec -T postgres psql -U rv rv -At -c "SELECT token_hash FROM control.account_tokens WHERE principal_id='${inv.json.id}'"`).trim();
  check("only a hash of the link is stored", stored.length === 64 && !stored.includes(invToken ?? "x"));
  const chk = await control("/v1/auth/account-link/check", { body: { token: invToken } });
  check("the link identifies the person", chk.json?.email === email && chk.json.kind === "invite");
  check("a short password is refused", (await control("/v1/auth/account-link/redeem", { body: { token: invToken, password: "short" } })).status === 400);
  const pw1 = `first-${crypto.randomBytes(8).toString("hex")}`;
  check("the invitation sets a password", (await control("/v1/auth/account-link/redeem", { body: { token: invToken, password: pw1 } })).status === 200);
  check("the link works once", (await control("/v1/auth/account-link/redeem", { body: { token: invToken, password: pw1 + "x" } })).status === 400);
  const twice = await control("/v1/principals/" + inv.json.id + "/invite", { token: ADMIN, method: "POST" });
  check("someone who accepted can't be invited again", twice.status === 400);
  const e1 = await control("/v1/auth/login", { body: { email, password: pw1 } });
  check("after accepting, sign-in goes on to set up two-factor", e1.json?.step === "enrol_totp", e1.text);
  const secret = e1.json.secret;
  const d1 = await control("/v1/auth/login", { body: { email, password: pw1, totp: totp(secret) } });
  const codes = d1.json?.recovery_codes ?? [];
  check("the first full sign-in gives ten recovery codes, once", d1.json?.step === "done" && codes.length === 10 && new Set(codes).size === 10, d1.text);
  const IFY = d1.json.access_token;

  // ---- Recovery codes
  const badCode = await control("/v1/auth/login", { body: { email, password: pw1, recovery_code: "aaaa-bbbb-cccc-dddd" } });
  check("a wrong recovery code is refused", badCode.status === 401);
  const wrongPw = await control("/v1/auth/login", { body: { email, password: "wrong-password-1", recovery_code: codes[0] } });
  check("a recovery code doesn't replace the password", wrongPw.status === 401);
  const rc = await control("/v1/auth/login", { body: { email, password: pw1, recovery_code: codes[0] } });
  check("a recovery code signs in, and says how many are left", rc.json?.step === "done" && rc.json.recovery_codes_left === 9 && Boolean(rc.json.access_token), rc.text);
  check("no new codes are issued by using one", !rc.json?.recovery_codes);
  check("a recovery code works once", (await control("/v1/auth/login", { body: { email, password: pw1, recovery_code: codes[0] } })).status === 401);
  check("the owner is told by email", Boolean(await waitMail((m) => to(email)(m) && m.includes("recovery code"))));
  check("settings shows the count left", (await control("/v1/auth/security", { token: IFY })).json?.recovery_codes_left === 9);
  check("new codes need the password", (await control("/v1/auth/recovery-codes", { token: IFY, body: { password: "wrong-password-1" } })).status === 401);
  const fresh = await control("/v1/auth/recovery-codes", { token: IFY, body: { password: pw1 } });
  check("new codes replace the old ones", fresh.json?.recovery_codes?.length === 10 && (await control("/v1/auth/login", { body: { email, password: pw1, recovery_code: codes[1] } })).status === 401);

  // ---- A new authenticator
  check("a new authenticator needs the password", (await control("/v1/auth/mfa/replace", { token: IFY, body: { password: "wrong-password-1" } })).status === 401);
  const rep = await control("/v1/auth/mfa/replace", { token: IFY, body: { password: pw1 } });
  check("a new authenticator can be started", Boolean(rep.json?.secret), rep.text);
  check("it needs a valid code from the new app", (await control("/v1/auth/mfa/replace/confirm", { token: IFY, body: { totp: totp(secret) === totp(rep.json.secret) ? "000000" : totp(secret) } })).status === 401);
  const oldStill = await control("/v1/auth/login", { body: { email, password: pw1, totp: await nextStep(secret) } });
  check("the old app keeps working until the new one is proven", oldStill.json?.step === "done", oldStill.text);
  const conf = await control("/v1/auth/mfa/replace/confirm", { token: oldStill.json.access_token, body: { totp: totp(rep.json.secret) } });
  check("confirming switches apps and gives new codes", conf.json?.recovery_codes?.length === 10, conf.text);
  const newSecret = rep.json.secret;
  check("the old app stops working", (await control("/v1/auth/login", { body: { email, password: pw1, totp: await nextStep(secret) } })).status === 401);

  // ---- Forgot password
  const before = mail.inbox.length;
  const unknown = await control("/v1/auth/forgot", { body: { email: `nobody-${uniq}@e2e.example.ng` } });
  const known = await control("/v1/auth/forgot", { body: { email } });
  check("forgot password gives the same answer for any address", unknown.status === 200 && known.status === 200 && unknown.text === known.text);
  const resetMail = await waitMail((m, i) => to(email)(m) && m.includes("choose a new password"));
  check("the reset link arrives", Boolean(resetMail));
  check("an unknown address gets no email", !mail.inbox.slice(before).some(to(`nobody-${uniq}@e2e.example.ng`)));
  await control("/v1/auth/forgot", { body: { email } });
  await sleep(1500);
  check("asking again within minutes doesn't flood the inbox", mail.inbox.filter((m) => to(email)(m) && m.includes("choose a new password")).length === 1);
  const pw2 = `second-${crypto.randomBytes(8).toString("hex")}`;
  const redeemed = await control("/v1/auth/account-link/redeem", { body: { token: tokenIn(resetMail), password: pw2 } });
  check("the link sets a new password", redeemed.status === 200, redeemed.text);
  check("the old password stops working", (await control("/v1/auth/login", { body: { email, password: pw1 } })).status === 401);
  const afterReset = await control("/v1/auth/login", { body: { email, password: pw2 } });
  check("a reset link doesn't get past two-factor", afterReset.json?.step === "totp_required" && !afterReset.json.access_token, afterReset.text);
  check("sessions from before the reset end", (await control("/v1/me", { token: IFY })).status === 401);
  check("the owner is told their password changed", Boolean(await waitMail((m) => to(email)(m) && m.includes("password was just changed"))));
  const tok3 = sh(`${COMPOSE} exec -T postgres psql -U rv rv -At -c "UPDATE control.account_tokens SET expires_at=now()-interval '1 second', used_at=NULL, revoked_at=NULL WHERE principal_id='${inv.json.id}' AND kind='password_reset' RETURNING 1"`);
  check("an expired link is refused", tok3.includes("1") && (await control("/v1/auth/account-link/check", { body: { token: tokenIn(resetMail) } })).status === 400);
  sh(`${COMPOSE} exec -T postgres psql -U rv rv -c "UPDATE control.account_tokens SET used_at=now() WHERE principal_id='${inv.json.id}' AND kind='password_reset'"`);

  // ---- An admin acting for someone else
  const ify2 = await control("/v1/auth/login", { body: { email, password: pw2, totp: await nextStep(newSecret) } });
  const IFY2 = ify2.json?.access_token;
  check("a person with the new password and app signs in", Boolean(IFY2), ify2.text);
  const me = (await control("/v1/me", { token: ADMIN })).json;
  check("a non-admin can't reset someone's password", (await control(`/v1/principals/${inv.json.id}/reset-password`, { token: otherToken(), method: "POST" })).status === 403);
  check("a non-admin can't reset someone's two-factor", (await control(`/v1/principals/${inv.json.id}/reset-mfa`, { token: otherToken(), method: "POST" })).status === 403);
  check("an admin can't reset their own password this way", (await control(`/v1/principals/${me.id}/reset-password`, { token: ADMIN, method: "POST" })).status === 400);
  check("an admin can't reset their own two-factor this way", (await control(`/v1/principals/${me.id}/reset-mfa`, { token: ADMIN, method: "POST" })).status === 400);
  const ar = await control(`/v1/principals/${inv.json.id}/reset-password`, { token: ADMIN, method: "POST" });
  check("an admin reset emails a link", ar.json?.emailed === true, ar.text);
  check("the old password stops at once", (await control("/v1/auth/login", { body: { email, password: pw2 } })).status === 401);
  check("the person is signed out", (await control("/v1/me", { token: IFY2 })).status === 401);
  await sleep(1000);
  const arMails = mail.inbox.filter((m) => to(email)(m) && m.includes("choose a new password"));
  const pw3 = `third-${crypto.randomBytes(8).toString("hex")}`;
  check("that link sets a password", (await control("/v1/auth/account-link/redeem", { body: { token: tokenIn(arMails.at(-1)), password: pw3 } })).status === 200);
  const mf = await control(`/v1/principals/${inv.json.id}/reset-mfa`, { token: ADMIN, method: "POST" });
  check("an admin can reset two-factor, and the person is told", mf.json?.notified === true && Boolean(await waitMail((m) => to(email)(m) && m.includes("two-factor was reset"))), mf.text);
  check("they set it up again at next sign-in", (await control("/v1/auth/login", { body: { email, password: pw3 } })).json?.step === "enrol_totp");

  // ---- Everyone locked out
  const rec = sh(`${COMPOSE} run --rm --no-deps -T migrate admin-recover -email ${email} -reason "E2E lockout drill"`);
  const recTok = tokenIn(rec);
  check("the operator command makes a one-time link", Boolean(recTok), rec);
  let refused = false;
  try { sh(`${COMPOSE} run --rm --no-deps -T migrate admin-recover -email nobody@e2e.example.ng -reason "E2E lockout drill"`); } catch { refused = true; }
  check("it refuses anyone who isn't an active admin", refused);
  const pw4 = `fourth-${crypto.randomBytes(8).toString("hex")}`;
  check("that link sets a password", (await control("/v1/auth/account-link/redeem", { body: { token: recTok, password: pw4 } })).status === 200);
  check("and clears two-factor, for fresh setup", (await control("/v1/auth/login", { body: { email, password: pw4 } })).json?.step === "enrol_totp");

  const events = (await control("/v1/audit-events?limit=200", { token: adminToken() })).json?.events ?? [];
  const actions = new Set(events.map((e) => e.action));
  for (const a of ["mail_configure", "invite_accept", "password_reset_by_admin", "mfa_reset_by_admin", "mfa_replace", "recovery_codes_replace", "admin_recovery_issued"]) check(`the audit log records ${a}`, actions.has(a));
  const dump = JSON.stringify(events);
  check("no password or link reaches the audit log", ![pw1, pw2, pw3, pw4, recTok, invToken, ...codes].some((x) => dump.includes(x)));

  // ---- Alert digest
  await control("/v1/settings/mail", { token: adminToken(), method: "PUT", body: { ...mailBody, alerts_enabled: true } });
  sh(`${COMPOSE} exec -T postgres psql -U rv rv -c "INSERT INTO events.alerts(id,tenant_id,kind,detail,event_at) SELECT gen_random_uuid(), tenant_id, 'map_e2e_probe', '{}'::jsonb, now() FROM control.principals WHERE id='${me.id}'"`);
  const digest = await waitMail((m) => /new alert/.test(m) && m.includes("residency map change"), 15000);
  check("new alerts are emailed to admins", Boolean(digest));
  const stamp = () => sh(`${COMPOSE} exec -T postgres psql -U rv rv -At -c "SELECT emailed_at FROM events.alerts WHERE kind='map_e2e_probe'"`).trim();
  const first = stamp();
  await sleep(4000);
  check("each alert is emailed once", first !== "" && stamp() === first);
  check("the digest holds no customer data", (digest ?? "").includes("holds no customer data"));

  // Leave the rest of the run without email, as it found it.
  await control("/v1/settings/mail", { token: adminToken(), method: "DELETE" });
  check("email can be removed", (await control("/v1/settings/mail", { token: adminToken() })).json?.configured === false);
  mail.close();
}
