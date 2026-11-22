// Passkeys and security keys (WebAuthn) as the second factor, in place of the
// six-digit code. Phishing-resistant: the browser signs only for this site's origin.

import {
  generateAuthenticationOptions, generateRegistrationOptions, verifyAuthenticationResponse, verifyRegistrationResponse,
  type AuthenticationResponseJSON, type AuthenticatorTransport, type RegistrationResponseJSON,
} from "@simplewebauthn/server";
import { db, newId } from "./lib.js";
import { publicOrigin } from "./identity.js";

const rpID = () => process.env.RV_HOST ?? "localhost";
const TTL_MS = 5 * 60_000;

async function putChallenge(principalId: string, kind: "passkey_register" | "passkey_login", challenge: string) {
  await db.auth_challenges.deleteMany({ where: { OR: [{ principal_id: principalId, kind }, { expires_at: { lt: new Date() } }] } });
  await db.auth_challenges.create({ data: { id: newId("ch"), principal_id: principalId, kind, challenge, expires_at: new Date(Date.now() + TTL_MS) } });
}

/** Takes the pending challenge, once, whether or not what follows succeeds. */
async function takeChallenge(principalId: string, kind: "passkey_register" | "passkey_login"): Promise<string | null> {
  const row = await db.auth_challenges.findFirst({ where: { principal_id: principalId, kind } });
  if (!row) return null;
  await db.auth_challenges.delete({ where: { id: row.id } });
  return row.expires_at > new Date() ? row.challenge : null;
}

export async function hasPasskeys(principalId: string) {
  return (await db.webauthn_credentials.count({ where: { principal_id: principalId } })) > 0;
}

export async function registrationOptions(p: { id: string; email: string | null; display_name: string }) {
  const existing = await db.webauthn_credentials.findMany({ where: { principal_id: p.id } });
  const options = await generateRegistrationOptions({
    rpName: "Onshore", rpID: rpID(),
    userName: p.email ?? p.id, userDisplayName: p.display_name, userID: new TextEncoder().encode(p.id),
    attestationType: "none",
    excludeCredentials: existing.map((c) => ({ id: c.id, transports: c.transports as AuthenticatorTransport[] })),
    authenticatorSelection: { residentKey: "preferred", userVerification: "preferred" },
  });
  await putChallenge(p.id, "passkey_register", options.challenge);
  return options;
}

export async function finishRegistration(principalId: string, response: RegistrationResponseJSON, name: string): Promise<boolean> {
  const challenge = await takeChallenge(principalId, "passkey_register");
  if (!challenge) return false;
  let v;
  try {
    v = await verifyRegistrationResponse({ response, expectedChallenge: challenge, expectedOrigin: publicOrigin(), expectedRPID: rpID(), requireUserVerification: false });
  } catch {
    return false;
  }
  if (!v.verified || !v.registrationInfo) return false;
  const c = v.registrationInfo.credential;
  if (await db.webauthn_credentials.findUnique({ where: { id: c.id } })) return false;
  await db.webauthn_credentials.create({ data: { id: c.id, principal_id: principalId, public_key: Buffer.from(c.publicKey), counter: BigInt(c.counter), transports: c.transports ?? [], name: name.slice(0, 60) } });
  return true;
}

export async function loginOptions(principalId: string) {
  const creds = await db.webauthn_credentials.findMany({ where: { principal_id: principalId } });
  const options = await generateAuthenticationOptions({ rpID: rpID(), allowCredentials: creds.map((c) => ({ id: c.id, transports: c.transports as AuthenticatorTransport[] })), userVerification: "preferred" });
  await putChallenge(principalId, "passkey_login", options.challenge);
  return options;
}

export async function verifyLogin(principalId: string, response: AuthenticationResponseJSON): Promise<boolean> {
  const challenge = await takeChallenge(principalId, "passkey_login");
  if (!challenge) return false;
  const cred = await db.webauthn_credentials.findFirst({ where: { id: response.id, principal_id: principalId } });
  if (!cred) return false;
  let v;
  try {
    v = await verifyAuthenticationResponse({
      response, expectedChallenge: challenge, expectedOrigin: publicOrigin(), expectedRPID: rpID(), requireUserVerification: false,
      credential: { id: cred.id, publicKey: new Uint8Array(cred.public_key), counter: Number(cred.counter), transports: cred.transports as AuthenticatorTransport[] },
    });
  } catch {
    return false;
  }
  if (!v.verified) return false;
  await db.webauthn_credentials.update({ where: { id: cred.id }, data: { counter: BigInt(v.authenticationInfo.newCounter), last_used_at: new Date() } });
  return true;
}
