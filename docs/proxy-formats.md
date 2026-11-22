# Proxy formats

The HTTP proxy reads more than JSON, because older bank and verification APIs often use something else. **Whatever it cannot read in full, it does not forward.**

| Body | How it is handled |
| --- | --- |
| JSON | Field rules and detection, as before |
| Forms, `application/x-www-form-urlencoded` | Rules name fields: `$.bvn`, `$.customer.bvn` for `customer[bvn]`, `$.items[*].id` for `items[0][id]`. A repeated field has every value replaced |
| XML and SOAP | Values are edited where they stand, so namespaces, prefixes, order and whitespace arrive as sent. Rules use local names: `$.Envelope.Body.Check.BVN`, and `$.Check.@id` for an attribute. Detection also reads attributes and comments |
| Multipart uploads | Each field and text file is read as a value, and file names are checked. Binary parts follow the file policy |
| Plain text, CSV | Detection only. **A route with field rules refuses it**, since a rule has nothing to name |
| PDF, images, anything binary | The file policy |

What the bytes are decides, not the label. Text labelled `image/png` is read as text, and JSON labelled `text/plain` is read as JSON.

## File policy

| Policy | Effect |
| --- | --- |
| `refuse`, the default | A binary body or part is refused with 415 |
| `redact` | PDFs and images go through the file redactor, and come back flattened with values painted over. **Anything else is refused, and so is a file the OCR could not read with confidence.** Needs the `files` Compose profile. Audio is refused |
| `pass` | Sent unread, and counted as `uninspected`. An admin has to choose this for the route |

A route with no field rules and detection turned off passes everything unread, as it always has.

## Headers and query strings

```json
{ "redact_headers": [{ "header": "X-Customer-BVN", "field": "bvn" }],
  "unredact_headers": [{ "header": "X-Account-Token" }],
  "response_redact_headers": [{ "header": "X-Result-BVN" }],
  "response_unredact_headers": [],
  "dlp_excluded_headers": ["X-Trace-Note"],
  "dlp_excluded_params": ["reference"] }
```

Detection now also reads request headers and every query parameter, not only those named. It skips credentials and plumbing such as `Authorization`, `Content-Type` and `Accept`, unless a rule names them. **This is new behaviour for existing routes:** a value in a header or an unnamed parameter used to pass, and is now replaced. Use the exclusions if a route relies on one.

Rules cannot name framing headers such as `Host` or `Content-Length`, or this product's own `X-RV-` headers. A restored value holding a line break is not written to a header, and the token stays.

## What gets refused, and why

| Refused with 415 | Because |
| --- | --- |
| A `DOCTYPE` in XML | It can define entities the upstream would expand and this cannot see |
| XML that is malformed, not UTF-8, or deeper than 256 levels | It cannot be read in full |
| An XML processing instruction holding something detected | There is nowhere safe to put a token |
| Compressed bodies | They cannot be read, and an unread body must not pass |
| A charset other than UTF-8, ASCII, Latin-1 or Windows-1252, and any NUL byte in text or a form | In UTF-16 or UTF-7, a digit is not the byte it looks like, so a value would pass unseen |
| Base64 or quoted-printable multipart parts, nested multipart | They carry a value past the checks unread |
| A field rule naming a binary part | A rule that cannot be honoured must not be ignored |
| Over 200 parts, or over 10,000 form fields | Bounds on the work a request can cause |

## Things to check on your upstream

- **Forms and multipart are rewritten** in one canonical form, so that an upstream cannot read them differently from how they were checked. An upstream that verifies a signature over the raw body will fail, as it would for any change.
- **Multipart drops everything but the fields:** preamble, epilogue, and part headers other than `Content-Disposition` and `Content-Type`.
- **Non-UTF-8 is refused.** Legacy systems sending Latin-1 XML or forms get a 415.

## Limits

- **Values in a URL path are not checked:** `/customers/22333444558` passes. Rewriting a path would stop the upstream finding the resource. Use a query parameter, or name the route so that it does not carry one.
- **Detection's own limits apply to every format.** A bare number after a word like `ref` or `order` is excused, so `ref="08035556666"` in XML passes, as `{"ref":"08035556666"}` does in JSON, and `?ref=` in a query. See the known gaps. Name the field in a rule if it matters.
- **Parameter and header names are not checked**, only their values.
- **Detection does not run on responses.** Responses get only the rules you name, as before.
- **The console's preview still shows JSON only.** The other formats have no preview screen.
- **The file redactor's limits apply.** See the known gaps for what it has been tried on.
