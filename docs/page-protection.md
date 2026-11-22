# Page protection

A checkout or KYC page can be emptied by one compromised third-party script. This keeps a list of the scripts that run on your sensitive pages, and tells you when that list or a script's contents changes. It supports the script inventory, authorisation and change-detection work in PCI DSS 6.4.3 and 11.6.1. **It has not been assessed against that standard, and using it does not make a page compliant.**

## Three signals

| Signal | Sees | Weakness |
| --- | --- | --- |
| **Browser report**, a `Content-Security-Policy-Report-Only` header | Everything the browser loads or runs, including inline code. Malicious script cannot switch it off from inside the page | You must set a header. Browsers may trim an address to its origin after a redirect, and some extensions or networks block reports |
| **Watcher**, `/embed/rv-watch.js` | Scripts loaded or added while the page runs | It runs on the same page as a hostile script, which could interfere with it, or remove it |
| **Server scan**, every 15 minutes and on demand | Script tags in the page's HTML, and each approved file's SHA-256 | Only what an unauthenticated request gets. **It misses pages behind a login and scripts added at run time. A targeted attacker could serve the scanner a clean copy** |

Use the header first. The watcher adds detail, and the scan catches a third party changing a file nobody re-approved.

## Using it

1. **Protect a page** in the console, then send the report-only header it shows. Nothing is blocked.
2. Browse the page. Scripts appear as **Needs a decision**.
3. **Approve or reject** each one, with a written reason. Approving records the file's hash as its baseline.
4. Once the list is right, use the enforcing header it shows. **This blocks anything not approved, so try it on a staging page first.** Your own inline code will need a nonce.

## What you are told

Each of these raises an alert and sends a webhook event:

| Event | When |
| --- | --- |
| `page.script_new` | A script not seen before on this page |
| `page.script_changed` | An approved file's contents changed. It loses its approval until someone looks again |
| `page.script_rejected_seen` | A rejected script ran again, at most hourly |

An alert of kind `page_report_flood` means the hourly limit below was hit.

## What is stored

Addresses only. A query string or fragment is dropped, and a path segment holding ten or more digits or an `@` becomes `[removed]`. **A shorter value in a path cannot be told from a file name, and stays.** The address of the page sending a report is checked and not stored. Nothing fetched by the scan is stored except a hash.

The watcher reads script addresses and nothing else: no form fields, cookies or page text.

## Limits

- **Reports cannot be authenticated.** A browser sends them, so the key in the page is public. Anyone with it can send made-up scripts. They can add to the list, and cannot approve anything. Reports must name the page's own origin, but a forger can claim that too.
- **A flood can hide a real script.** After 50 new scripts in an hour, or 500 on a page, further new scripts are dropped until the hour passes or someone clears the list, and the flood alert fires. An attacker who knows this could flood first and then load their script. The server scan is not subject to reports, but it shares the same list limits.
- **This detects; it blocks only if you turn on the enforcing header.** Between a script appearing and someone acting, it can run.
- **Inline code is one entry.** All inline code on a page appears as `inline`, with no way to tell one block from another.
- **Files over 5 MB and files behind a redirect are not hashed.** The script's row says so.
- A script served differently per visitor can change without a new hash. The scan sees only its own copy.
