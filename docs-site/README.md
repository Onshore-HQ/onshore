# Onshore documentation

The public docs for Onshore, at docs.onshorevault.com. Nextra 4 (Next.js), exported as static files with Pagefind search.

```sh
npm install
npm run dev        # http://localhost:4120
npm run build      # writes out/ and the search index
npm run preview    # serves out/ on port 4120
```

- Pages are MDX in `content/`, ordered by each folder's `_meta.js`.
- `<Shot>` frames a screenshot; `<Cards>`, `<Ent />` and `<Early />` are in `components/`.
- The country table reads `lib/countries.js`, a copy of `website/src/lib/countries.ts`, itself from `control-api/src/catalog.ts`. Change them together.
- `zod` is pinned to 4.1.13 in `overrides`: newer zod breaks Nextra 4.6.1's layout validation.

## Screenshots

`scripts/screenshots.mjs` signs in to a local install with the demo loaded, takes every screenshot into `public/screenshots/`, and removes its test data afterwards. Highlights are a single blue outline, added only where a step needs one.

```sh
PLAYWRIGHT_MODULE=/path/to/playwright/index.mjs CHROME=/path/to/chrome node scripts/screenshots.mjs [names…]
```

The Enterprise sign-in shots (`identity`) need the control API running with `RV_CLOUD=1`; restart it without afterwards.

Before changing a claim, check `docs/known-gaps.md`: the docs must not promise more than it says.
