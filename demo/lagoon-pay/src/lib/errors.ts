import * as Sentry from "@sentry/node";
import { state } from "./config";
import { checkFlow, cleanText } from "./onshore";

let started = false;
export function initSentry() {
  if (started) return;
  started = true;
  Sentry.init({
    dsn: process.env.SENTRY_DSN || "http://public@127.0.0.1:4200/1",
    tracesSampleRate: 0,
    defaultIntegrations: false,
    // After the fix: the hook tokenizes the event before it leaves, and checks what is about to be sent.
    beforeSend: async (event) => {
      const { config, onshore } = state();
      if (!config.sentry_hook || !onshore) return event;
      for (const v of event.exception?.values ?? []) if (v.value) v.value = await cleanText(v.value);
      if (event.message) event.message = await cleanText(event.message);
      if (event.extra) event.extra = JSON.parse(await cleanText(JSON.stringify(event.extra)));
      if (onshore.flows.sentry) await checkFlow(onshore.flows.sentry, JSON.stringify(event.exception?.values ?? [])).catch(() => undefined);
      return event;
    },
  });
}
/** The second deliberate mistake: the exception message carries the account number and amount. */
export function reportTransferFailure(account: string, amount: number, customerRef: string) {
  const err = new Error(`Transfer failed: could not credit account ${account} with ₦${amount.toLocaleString("en-NG")} for ${customerRef}`);
  err.name = "TransferFailed";
  Sentry.captureException(err);
}
