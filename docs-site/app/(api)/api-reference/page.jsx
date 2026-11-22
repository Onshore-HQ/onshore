import Script from "next/script";
import { Logo } from "../../../components/Logo";

// Scalar's standalone viewer, served from this site (copied at build time by
// scripts/copy-scalar.mjs) so the reference works without a CDN.
const config = {
  sources: [
    { title: "Data API", slug: "data-api", url: "/openapi/data-api.yaml", default: true },
    { title: "Control API", slug: "control-api", url: "/openapi/control-api.yaml" },
    { title: "SCIM 2.0", slug: "scim", url: "/openapi/scim.yaml" },
  ],
  theme: "default",
  layout: "modern",
  hideClientButton: false,
  defaultHttpClient: { targetKey: "node", clientKey: "fetch" },
  hiddenClients: { c: true, clojure: true, objc: true, ocaml: true, r: true, swift: false },
  customCss: ":root { --scalar-color-accent: #2f7fd8; }",
  metaData: { title: "Onshore API reference" },
  showDeveloperTools: "never",
  agent: { disabled: true },
  documentDownloadType: "both",
  persistAuth: false,
};

export default function ApiReference() {
  return (
    <>
      <header className="rv-api-bar">
        <a href="/"><Logo /></a>
        <span>API reference</span>
        <a className="rv-back" href="/developers/">Developer guides</a>
      </header>
      <div id="rv-api-ref" />
      <Script src="/scalar/standalone.js" strategy="afterInteractive" id="scalar-load" />
      <Script id="scalar-init" strategy="afterInteractive">
        {`(function start(){ if (!window.Scalar) return setTimeout(start, 50); window.Scalar.createApiReference('#rv-api-ref', ${JSON.stringify(config)}); })();`}
      </Script>
    </>
  );
}
