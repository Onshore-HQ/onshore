# Secure components

Collect or show a BVN, NIN, account number or custom entity inside a frame on your own site. Your page and your servers get a token back, and never see the value. A leak on your side then has no identifier to expose.

The frame and its script are served by your own install, not by a third party, so this keeps the same residency position as the rest of the product.

## Set up

1. In **Vaults**, open **Secure components** and list the exact sites allowed to host the frame, such as `https://app.example.ng`. With no list, this is off. Wildcards are refused. `http://localhost` is allowed on sandbox vaults only.
2. Make sure the service account you will use is allowed the action by policy: `tokenize` to collect, `detokenize` to reveal.

## Collect

On your server, mint a single-use client token:

```
POST /v1/vaults/v_live_ng01/client-tokens
{ "kind": "collect", "origin": "https://app.example.ng", "fields": ["bvn"], "subject_ref": "cust_1042", "ttl_seconds": 120 }

{ "client_token": "rvct_…", "expires_at": "2026-11-03T12:02:00Z" }
```

On your page:

```html
<script src="https://vault.example.ng/embed/rv.js"></script>
<div id="bvn"></div>
<button id="save">Save</button>
<script>
  const form = Onshore.collect({
    vault: "v_live_ng01",
    clientToken,                       // from your server
    labels: { bvn: "Your BVN" },
    theme: { accent: "#0f5c46", radius: "8px" },
  });
  form.on("change", (e) => { save.disabled = !e.complete; });
  form.mount("#bvn");

  save.onclick = async () => {
    const tokens = await form.submit(); // { bvn: "tok_bvn_…" }
    // Send the token to your server. The value never came through this page.
  };
</script>
```

A format mistake shows inside the frame and does not use up the token, so the person can correct it. `submit()` rejects with `err.fields` naming the fields, never their contents.

## Reveal

```
POST /v1/vaults/v_live_ng01/client-tokens
{ "kind": "reveal", "origin": "https://app.example.ng", "tokens": ["tok_bvn_…"],
  "purpose": "Support ticket 7", "on_behalf_of": "agent ada", "bind_ip": "102.89.1.1" }
```

```js
Onshore.reveal({ vault, clientToken, labels: { 0: "BVN" }, hideAfter: 30 }).mount("#value");
```

The value shows inside the frame only, and is hidden again after `hideAfter` seconds (30 by default, up to 300). Your page learns only which decision was made, such as `masked` or `plaintext`.

**You decide who may ask.** The vault does not know your end users. Your server must check that this person may see this record before it mints a token. Policy applies to the principal that minted the token, and the audit log records your `purpose` and `on_behalf_of`.

## Events

| Event | Component | Carries |
| --- | --- | --- |
| `ready` | Collect | |
| `change` | Collect | `complete`: every field is filled in |
| `enter` | Collect | The person pressed Enter |
| `invalid` | Collect | `fields`: which to correct |
| `complete` | Collect | `tokens` |
| `revealed` | Reveal | `decisions` |
| `hidden` | Reveal | |
| `error` | Both | `code` |

## What protects the value

- **The frame is a different origin**, so your page's script cannot read what is typed or shown, even if your page is compromised.
- **Client tokens are capabilities.** Single use, 2 minutes by default and 10 at most, tied to one origin and to named fields or tokens. Only a hash is stored.
- **Policy is checked again when the token is used,** against the browser's address. Suspending the service account, revoking its keys, changing a policy or removing the site all stop tokens already issued.
- **An `approved network` policy rule applies to the browser,** not to your server, because that is who sees the value. A service account's IP allowlist applies when minting.
- **The frame's page allows only its own script and stylesheet,** and only your listed sites can frame it.
- **Styling is a short list of checked values:** `color`, `muted`, `background`, `inputBackground`, `border`, `accent`, `error`, `radius`, `fontSize` and `font` (`serif` or `mono`). Free-form CSS could read what is typed.

## What it does not protect against

- **A stolen reveal token used outside a browser.** A compromised page holds the token before the frame does, and browser checks do not bind `curl`. Set `bind_ip` to the person's address to close this, unless their address changes often, as it can on mobile networks.
- **A compromised page pretending to be the form.** It can draw its own fake input beside or instead of the frame. Page Protection would help here; it is not built.
- **Keyloggers and malware on the person's device,** and anyone reading their screen.
- **Your own logic.** A wrong authorization check on your server reveals the wrong record.

## Limits

- Browser only. There are no React Native, iOS or Android components yet, and a mobile WebView has not been tested.
- A collect token covers up to 10 fields, and a reveal token up to 20 tokens.
- Collecting cards is out of scope: a card number is refused, as it is everywhere else in the vault.
