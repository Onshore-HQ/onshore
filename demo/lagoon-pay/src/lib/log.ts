import { logs, SeverityNumber } from "@opentelemetry/api-logs";
import { db } from "./db";

/** The first deliberate mistake: payloads logged at info level. Log lines leave through OpenTelemetry. */
export async function info(line: string) { return write("INFO", SeverityNumber.INFO, line); }
export async function error(line: string) { return write("ERROR", SeverityNumber.ERROR, line); }
async function write(level: string, severityNumber: SeverityNumber, line: string) {
  logs.getLogger("lagoon-pay").emit({ severityText: level, severityNumber, body: line });
  try { await db.opsLine.create({ data: { level, line } }); } catch { /* the ops view is a convenience */ }
}
