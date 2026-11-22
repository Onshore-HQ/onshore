// Wraps the console's visible English text in t(), and lists every string for the
// dictionaries. Safe to re-run: text already inside t() is left alone.
//
//   node scripts/i18n-wrap.mjs            wrap and write src/lib/i18n/strings.json
//   node scripts/i18n-wrap.mjs --check    only list strings missing from fr.json
import fs from "node:fs";
import path from "node:path";
import { createRequire } from "node:module";
const require = createRequire(import.meta.url);
const { ts } = require("@ts-morph/common");

const ROOT = path.resolve(path.dirname(new URL(import.meta.url).pathname), "..");
const SRC = path.join(ROOT, "src");
const check = process.argv.includes("--check");

// Props whose string values people read. Others (className, href, value, id…) are code.
const TEXT_PROPS = new Set(["title", "sub", "placeholder", "aria-label", "label", "hint", "alt", "all", "why", "cta", "text", "description", "body", "help", "empty", "confirmLabel", "word"]);
// Object keys whose values are sentences shown to people, when the object is built in a component.
const TEXT_KEYS = new Set(["why", "text", "hint", "sub", "title", "description", "help", "detail", "body", "cta", "label", "empty"]);
const SKIP_FILES = [/components\/ui\//, /lib\/i18n/, /\.d\.ts$/];
const ENTITIES = { "&rsquo;": "’", "&lsquo;": "‘", "&ldquo;": "“", "&rdquo;": "”", "&amp;": "&", "&lt;": "<", "&gt;": ">", "&nbsp;": " ", "&quot;": "\"", "&apos;": "'", "&mdash;": "—", "&ndash;": "–", "&hellip;": "…", "&middot;": "·", "&times;": "×", "&rarr;": "→" };
const decode = (s) => s.replace(/&[a-z]+;/g, (m) => ENTITIES[m] ?? m);
const isText = (s) => /[A-Za-z]{2}/.test(s) && !/^[a-z0-9_./:-]+$/.test(s.trim());

function files(dir) {
  return fs.readdirSync(dir, { withFileTypes: true }).flatMap((d) => {
    const p = path.join(dir, d.name);
    if (d.isDirectory()) return files(p);
    return /\.tsx$/.test(d.name) && !SKIP_FILES.some((r) => r.test(p)) ? [p] : [];
  });
}

const all = new Set();
let changed = 0;
for (const file of files(SRC)) {
  const src = fs.readFileSync(file, "utf8");
  const sf = ts.createSourceFile(file, src, ts.ScriptTarget.Latest, true, ts.ScriptKind.TSX);
  const edits = [];
  const insideT = (n) => { for (let p = n.parent; p; p = p.parent) if (ts.isCallExpression(p) && (p.expression.getText(sf) === "t" || p.expression.getText(sf) === "tr")) return true; return false; };
  const visit = (n) => {
    if (ts.isJsxText(n)) {
      const raw = n.getText(sf);
      const core = raw.trim();
      if (core && isText(core) && !core.includes("{") ) {
        const start = n.getStart(sf) + raw.indexOf(core);
        const text = decode(core.replace(/\s+/g, " "));
        all.add(text);
        edits.push([start, start + core.length, `{tr(${JSON.stringify(text)})}`]);
      }
    } else if (ts.isJsxAttribute(n) && n.initializer && ts.isStringLiteral(n.initializer) && TEXT_PROPS.has(n.name.getText(sf))) {
      const v = n.initializer.text;
      if (isText(v)) { all.add(v); edits.push([n.initializer.getStart(sf), n.initializer.getEnd(), `{tr(${JSON.stringify(v)})}`]); }
    } else if (ts.isStringLiteral(n) && !insideT(n)) {
      // Text chosen in an expression: {busy ? "Creating…" : "Create"}, {x ?? "None yet"}.
      const p = n.parent;
      const inJsx = (() => { for (let q = p; q; q = q.parent) { if (ts.isJsxExpression(q)) return true; if (ts.isJsxAttribute(q) || ts.isCallExpression(q) || ts.isFunctionLike(q)) return false; } return false; })();
      const attr = (() => { for (let q = p; q; q = q.parent) if (ts.isJsxAttribute(q)) return q.name.getText(sf); return null; })();
      const choice = ts.isConditionalExpression(p) ? p.whenTrue === n || p.whenFalse === n : ts.isBinaryExpression(p) ? (p.operatorToken.kind === ts.SyntaxKind.QuestionQuestionToken || p.operatorToken.kind === ts.SyntaxKind.BarBarToken) && p.right === n : ts.isJsxExpression(p);
      const word = !attr && inJsx && ts.isConditionalExpression(p) && /^[a-z][a-z ]+[a-z]$/.test(n.text) && n.text.length > 2;
      if (choice && (inJsx || (attr && TEXT_PROPS.has(attr))) && (!attr || TEXT_PROPS.has(attr)) && (isText(n.text) || word)) {
        all.add(n.text);
        edits.push([n.getStart(sf), n.getEnd(), `tr(${JSON.stringify(n.text)})`]);
      }
    }
    if ((ts.isTemplateExpression(n) || ts.isNoSubstitutionTemplateLiteral(n)) && !insideT(n) && !ts.isTaggedTemplateExpression(n.parent) && visibleTemplate(n)) {
      const parts = ts.isNoSubstitutionTemplateLiteral(n) ? [n.text] : [n.head.text, ...n.templateSpans.map((sp) => sp.literal.text)];
      const statics = parts.join(" ");
      // A lone lowercase token such as role:… or redacted-… is an identifier, not a sentence.
      const identifier = /^[a-z][a-z0-9:-]*$/.test(statics.replace(/\s+/g, ""));
      if (/[A-Za-z]{3,}/.test(statics) && !identifier && !/[\/_=<>{}|\\]|--|\.\w|^\s*[?&#]/.test(statics)) {
        if (ts.isNoSubstitutionTemplateLiteral(n)) {
          all.add(n.text);
          edits.push([n.getStart(sf), n.getEnd(), `tr(${JSON.stringify(n.text)})`]);
        } else {
          let key = n.head.text;
          n.templateSpans.forEach((sp, i) => { key += `{${i}}` + sp.literal.text; });
          const vars = n.templateSpans.map((sp, i) => `${i}: ${sp.expression.getText(sf)}`).join(", ");
          all.add(key);
          edits.push([n.getStart(sf), n.getEnd(), `tr(${JSON.stringify(key)}, { ${vars} })`]);
          return; // its expressions are moved as a whole
        }
      }
    }
    if (ts.isStringLiteral(n) && !insideT(n) && ts.isPropertyAssignment(n.parent) && n.parent.initializer === n && TEXT_KEYS.has(n.parent.name.getText(sf)) && /^[A-Z]/.test(n.text) && n.text.includes(" ") && inFunction(n)) {
      all.add(n.text);
      edits.push([n.getStart(sf), n.getEnd(), `tr(${JSON.stringify(n.text)})`]);
    }
    if (ts.isStringLiteral(n) && ts.isCallExpression(n.parent) && n.parent.expression.getText(sf) === "plural" && n.parent.arguments.indexOf(n) > 0) {
      all.add(n.text);
      edits.push([n.getStart(sf), n.getEnd(), `tr(${JSON.stringify(n.text)})`]);
    }
    // A label in an array written inside the markup: {[["org", "Organisation"], …].map(…)}
    if (ts.isStringLiteral(n) && ts.isArrayLiteralExpression(n.parent) && !insideT(n) && /^[A-Z]/.test(n.text) && isText(n.text) && inMarkup(n)) {
      all.add(n.text);
      edits.push([n.getStart(sf), n.getEnd(), `tr(${JSON.stringify(n.text)})`]);
    }
    ts.forEachChild(n, visit);
  };
  // Text a person sees: not a URL, a class, a key or an argument to code that talks to servers.
  const CODE_CALLS = /^(control|data|api|fetch|router\.(push|replace)|encodeURIComponent|console\.\w+|localStorage\.\w+|sessionStorage\.\w+|JSON\.parse|RegExp|setTimeout|setInterval|new URL|URL|clsx|cn)$/;
  const CODE_ATTRS = new Set(["className", "href", "src", "key", "style", "id", "htmlFor", "value", "name", "type", "role", "download", "accept", "pattern", "autoComplete"]);
  function visibleTemplate(n) {
    for (let p = n.parent; p; p = p.parent) {
      if (ts.isJsxAttribute(p)) return !CODE_ATTRS.has(p.name.getText(sf)) && !p.name.getText(sf).startsWith("data-") && !p.name.getText(sf).startsWith("aria-describedby");
      if (ts.isCallExpression(p)) { const c = p.expression.getText(sf); if (CODE_CALLS.test(c) || c.endsWith(".join") || c.endsWith(".split")) return false; }
      if (ts.isNewExpression(p) && /URL|RegExp|Date|Error/.test(p.expression.getText(sf))) return false;
      if (ts.isPropertyAssignment(p) && /^(key|id|href|url|path|className|value|query)$/.test(p.name.getText(sf))) return false;
      if (ts.isImportDeclaration(p) || ts.isExportDeclaration(p)) return false;
      if (ts.isBinaryExpression(p) && [ts.SyntaxKind.EqualsEqualsEqualsToken, ts.SyntaxKind.ExclamationEqualsEqualsToken].includes(p.operatorToken.kind)) return false;
      if (ts.isSourceFile(p)) return true;
    }
    return true;
  }
  // Evaluated when a component renders, so the language is known; a module-level table is not.
  function inFunction(n) { for (let p = n.parent; p; p = p.parent) { if (ts.isFunctionLike(p)) return true; if (ts.isSourceFile(p)) return false; } return false; }
  function inMarkup(n) {
    for (let p = n.parent; p; p = p.parent) { if (ts.isJsxExpression(p)) return true; if (ts.isFunctionLike(p) || ts.isSourceFile(p)) return false; }
    return false;
  }
  visit(sf);
  if (check || edits.length === 0) continue;
  let out = src;
  for (const [s, e, r] of edits.sort((a, b) => b[0] - a[0])) out = out.slice(0, s) + r + out.slice(e);
  if (!/import \{[^}]*\btr\b[^}]*\} from "@\/lib\/i18n"/.test(out)) {
    const lines = out.split("\n");
    const at = lines[0].includes("use client") ? 1 : 0;
    lines.splice(at, 0, 'import { tr } from "@/lib/i18n";');
    out = lines.join("\n");
  }
  fs.writeFileSync(file, out);
  changed++;
}

// Strings already wrapped by hand or by an earlier run.
for (const file of [...files(SRC), path.join(SRC, "lib/labels.ts"), path.join(SRC, "lib/help.ts")]) {
  for (const m of fs.readFileSync(file, "utf8").matchAll(/\btr?\("((?:[^"\\]|\\.)*)"/g)) all.add(JSON.parse(`"${m[1]}"`));
}
// Lookup tables whose values are translated where they are shown.
for (const rel of ["lib/labels.ts", "lib/help.ts", "lib/nav.ts", "components/AuthLayout.tsx"]) {
  const f = path.join(SRC, rel);
  const sf = ts.createSourceFile(f, fs.readFileSync(f, "utf8"), ts.ScriptTarget.Latest, true, ts.ScriptKind.TSX);
  const walk = (n) => {
    if (ts.isStringLiteral(n) && (ts.isPropertyAssignment(n.parent) && n.parent.initializer === n || ts.isArrayLiteralExpression(n.parent)) && isText(n.text)) all.add(n.text);
    ts.forEachChild(n, walk);
  };
  walk(sf);
}
const strings = [...all].sort();
const fr = JSON.parse(fs.readFileSync(path.join(SRC, "lib/i18n/fr.json"), "utf8"));
const missing = strings.filter((s) => !(s in fr));
if (!check) fs.writeFileSync(path.join(SRC, "lib/i18n/strings.json"), JSON.stringify(strings, null, 1) + "\n");
console.log(`${changed} files changed, ${strings.length} strings, ${strings.length - missing.length} translated into French, ${missing.length} not yet`);
if (check && process.argv.includes("--list")) console.log(missing.join("\n"));
// --strict fails the build when a string has no French entry yet.
if (process.argv.includes("--strict") && missing.length > 0) process.exit(1);
