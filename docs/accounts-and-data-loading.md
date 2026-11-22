# Accounts, email and loading data

## Email

Settings, Email. Onshore sends through your own mail server. There is no Onshore mail service.

- Sent: invitations, password resets, notices about account changes, and alert digests. They hold staff names and links, never customer data.
- A password is refused without a secure connection.
- The mail server may be private, but can't be on Onshore's own networks, loopback or link-local addresses. Error messages never echo the server's replies.

## Getting back in

| Situation | What to do | Two-factor |
| --- | --- | --- |
| Forgot password | "Forgot your password?" on the sign-in page. Needs email | Still needed |
| Forgot password, no email set up | An admin uses Reset password on the person's page, and passes on the link | Still needed |
| Lost phone | "Use a recovery code" at sign-in, then Settings, Sign-in, Set up a new authenticator | A code stands in, once |
| Lost phone and codes | An admin uses Reset two-factor on the person's page | Set up again |
| Every admin locked out | `./rv admin-recover -email <address> -reason "<why>"` on the server | Cleared when the link is used |

Links work once, are stored only as hashes, and sit after the `#`, so they stay out of server logs. Invitations last 7 days, and resets and recovery links an hour. Admin actions need another admin: nobody can do them to themselves. All are in the audit log, and send webhook events. The person is emailed where email is set up.

`rv admin-recover` needs the database credentials, so whoever runs the server can use it. It leaves a permanent audit entry with the reason.

## Copying setup

Settings, Copy setup. Or from a pipeline, with a key from the same page:

```
curl -H "Authorization: Bearer $ONSHORE_KEY" "https://<host>/control/v1/config/export?vault_id=<vault>" -o setup.json
curl -H "Authorization: Bearer $ONSHORE_KEY" -H "content-type: application/json" \
  -d "{\"vault_id\":\"<vault>\",\"dry_run\":true,\"config\":$(cat setup.json)}" "https://<host>/control/v1/config/import"
```

Set `dry_run` to false to apply. The file holds fields, data types, access rules, approved networks and connections. It holds no keys, secrets, people or customer data.

Importing is deliberately cautious:

- Access rules arrive as drafts, and a second person publishes them. Data types arrive as drafts too.
- New connections start as watch only, with new keys.
- A live connection is never redirected, switched to another mode or weakened. These show as "Won't change".
- A field's token type never changes. Existing networks and web API routes aren't changed.
- Nothing is ever deleted.

A key can only do this. It acts as the admin who made it, and stops working if that person loses the role.

Not in the file: webhooks, single sign-on, email settings, people, and the values in value lists.

## Loading existing data

**In the console:** Customer records, Import existing data. Best for smaller files. The file is read in the browser and sent in batches through the normal API. The tab must stay open, and the tokens file exists only in the tab until you download it.

**On a server:** better for large files, and it can carry on after being stopped.

```
rv import -url https://<host> -vault <vault> -sa <service account> -key-id <key id> -key-file <seed file> \
  -file customers.csv -map bvn=bvn,phone=phone -ref customer_id -check
```

Run it first with `-check`, which stores nothing, then without. It writes `customers.csv.tokens.csv` and `customers.csv.errors.csv`. The errors file names rows, columns and problems, never values. Both files are created readable only by you.

Either way, access rules apply and every value goes in the audit log. Running the same file again is safe for fields that give the same token each time. Fields that give a new token each time would store the values twice, and the console warns about this.

Afterwards: replace the values in your database with the tokens, check your systems still work, then delete the original file.
