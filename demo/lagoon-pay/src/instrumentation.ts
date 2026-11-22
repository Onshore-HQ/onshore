export async function register() {
  if (process.env.NEXT_RUNTIME !== "nodejs") return;
  const { logs } = await import("@opentelemetry/api-logs");
  const { LoggerProvider, BatchLogRecordProcessor } = await import("@opentelemetry/sdk-logs");
  const { OTLPLogExporter } = await import("@opentelemetry/exporter-logs-otlp-http");
  const { Resource } = await import("@opentelemetry/resources");
  const provider = new LoggerProvider({ resource: new Resource({ "service.name": "lagoon-pay" }) });
  provider.addLogRecordProcessor(new BatchLogRecordProcessor(new OTLPLogExporter({ url: process.env.OTLP_LOGS_URL ?? "http://127.0.0.1:4318/v1/logs" }), { scheduledDelayMillis: 1000 }));
  logs.setGlobalLoggerProvider(provider);
  const { initSentry } = await import("./lib/errors");
  initSentry();
}
