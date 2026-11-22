// Copies Scalar's standalone viewer and the API specs into public/, so the API
// reference works offline and from the static export without a CDN.
import { copyFileSync, mkdirSync } from "node:fs";
const here = new URL("..", import.meta.url).pathname;
mkdirSync(here + "public/scalar", { recursive: true });
copyFileSync(here + "node_modules/@scalar/api-reference/dist/browser/standalone.js", here + "public/scalar/standalone.js");
mkdirSync(here + "public/openapi", { recursive: true });
for (const [from, to] of [["openapi.yaml", "data-api.yaml"], ["control-openapi.yaml", "control-api.yaml"], ["scim-openapi.yaml", "scim.yaml"]]) {
  copyFileSync(here + "../docs/" + from, here + "public/openapi/" + to);
}
console.log("copied Scalar and 3 specs");
