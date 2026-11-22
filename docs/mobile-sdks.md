# Mobile SDKs

iOS (`sdks/ios`), Android (`sdks/android`) and React Native (`sdks/react-native`) collect and show values in an app, using the same single-use client tokens as the web components.

**No SDK holds a credential.** Never put a service account key in an app: anything in an app can be extracted. Your server mints a client token and hands it to the app.

## Set up

1. In **Vaults > Secure components**, list your app as `rvapp://` and its id, such as `rvapp://ng.kobo.wallet`. Native apps have no web origin, so this names them instead. It is stored in lower case, so use lower case when minting and in the app, even if your bundle id has capitals.
2. On your server, mint a client token for that origin, as for the web:

```
POST /v1/vaults/v_live_ng01/client-tokens
{ "kind": "collect", "origin": "rvapp://ng.kobo.wallet", "fields": ["bvn"], "subject_ref": "cust_1042" }
```

3. Hand the token to the app over your own authenticated API.

### iOS

```swift
let client = SecureClient(baseURL: URL(string: "https://vault.example.ng")!, appOrigin: "rvapp://ng.kobo.wallet")
CollectForm(client: client, clientToken: token, labels: ["bvn": "Your BVN"], onTokens: { tokens in save(tokens["bvn"]) })
RevealView(client: client, clientToken: revealToken, hideAfter: 30)
```

### Android

```kotlin
val client = SecureClient("https://vault.example.ng", "rvapp://ng.kobo.wallet")
val form = CollectView(this, client, token, labels = mapOf("bvn" to "Your BVN"), onTokens = { save(it["bvn"]) })
val shown = RevealView(this, client, revealToken, hideAfterMs = 30_000)
```

`SecureClient` calls block, so call them off the main thread. The views do this for you. There are no runtime dependencies.

### React Native

```tsx
const client = createClient({ baseUrl: "https://vault.example.ng", appOrigin: "rvapp://ng.kobo.wallet" });
<CollectForm client={client} clientToken={token} labels={{ bvn: "Your BVN" }} onTokens={(t) => save(t.bvn)} />
<RevealView client={client} clientToken={revealToken} hideAfter={30} />
```

## What they do

- A form gives your code tokens, with no way to ask it for what was typed. A typo keeps the token, so the person can correct it.
- Autofill, suggestions and the copy menu are off. A revealed value hides after a time you choose and when the app leaves the screen.
- Errors never hold a value. On Android, a `RevealedValue` leaves its value out of `toString`.
- **Android** also sets `FLAG_SECURE` while a form or value is showing, which blocks screenshots and the recent-apps preview, and refuses taps through another app's overlay.
- **iOS** hides a typed value and clears a revealed one when the app stops being active, which keeps them out of the app switcher. The form's field has its edit menu, spell check, suggestions, capitalisation, autofill hint, inline predictions and Writing Tools turned off. **iOS has no way to block a screenshot.** Turning the edit menu off also turns off paste, as on Android.

To pin your server's certificate, pass your own `URLSession` on iOS or `SSLSocketFactory` on Android. React Native needs a native module for that, which this package does not include.

## Weaker than a browser frame

Be straight with customers about this. On the web, the value sits in a cross-origin frame that the host page's JavaScript cannot reach. **An app has no such boundary.**

- **Native:** the value is in your app's process while it is typed. These views keep it out of your code and your logs. Code in your app, such as a hostile third-party library, could walk the view tree and read it.
- **React Native:** all of an app's JavaScript shares one context, so a hostile package in the bundle could reach the component's state. If that matters, collect in a native screen or a `WebView`.
- **The app is not verified.** `rvapp://` is a name, not proof. Anyone holding a client token can use it, whatever they say they are, within its single use and short life. Use `bind_ip` if your server knows the device's address. App Attest and Play Integrity are not used.

## What has been run

| | Ran against a live install | Not run |
| --- | --- | --- |
| **Android** | The client, on an Android 10 emulator (API 29): collect, typo, single use, another app refused, reveal allowed and refused. Unit tests pass | **`CollectView` and `RevealView` compile but were never shown on a screen,** so `FLAG_SECURE`, autofill exclusion and the blocked copy menu are written, not observed. No physical device. Android 7 to 9 and 11 onward not tried |
| **iOS** | The form and reveal views and the client, on an iOS 26.5 simulator (iPhone 16), against a live install, 7 UI tests that tap and type in the real views: typo then token, field settings read back from the real text field, reveal shown and hidden after a time, cleared on leaving the app, refused by policy, another app refused, single use. iOS code also compiles for a real iPhone. The app switcher was checked by looking at its screenshots, since a test cannot read them: the typed value and revealed value did not show | **No physical iPhone,** so nothing has run on arm64 iOS, and Face ID, a real keyboard and its learning were not observed. iOS 15 to 25 not tried, although 15 is the stated minimum. iPad not tried. No autofill hint is set, but whether iOS ever offers one on its own was not observed |
| **React Native** | The client, in Node. Component logic against a stand-in for React Native, 5 tests | **Not run in React Native, Hermes, or on a device.** Types are checked against this package's own small description of the framework, not the real one |

**Before calling any of these ready:** open each in a real app on a real device. Android's tests need `RV_E2E_ANDROID=1` and an AVD named `rv_sdk_test`, or set `RV_E2E_AVD`. iOS's tests run with `scripts/test-ios-sim.sh`, which needs Xcode and a simulator runtime and replaces this project's Compose install. An Intel Mac needs Xcode 26 or earlier: Xcode 27 is Apple silicon only.
