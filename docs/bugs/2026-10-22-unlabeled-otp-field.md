# Bug: OTP field with an empty label can't be approved or used (2026-10-22)

## What happened

1Password item "Example Co @ Bank" (vault "AI Agents") has a working TOTP. `item fields` lists it like this:

```
{"id": "TOTP_9FCC2DA5B1254F84BC189D2E91B7503E", "label": "", "type": "OTP", "section": "Saved on bank.example.com"}
```

(Bank's login saved it through the 1Password browser extension, and that's how it ended up with no label.)

Every way of reaching it fails:

| Step | Command | Result |
|---|---|---|
| Approve | `request submit --item "Example Co @ Bank" --fields "email,password,one-time password"` | Approved, but `fields_available` was `["email","password"]`, with the OTP missing |
| Approve | `request submit --item "Example Co @ Bank" --fields "otp"` | Approved, but no `fields_available` came back |
| Use | `otp exec --item "Example Co @ Bank" --env V -- …` | `not_found`: "no OTP/MFA/TOTP/2FA field is available in this item" |
| Use | `otp exec --item … --field TOTP_9FCC2DA5B1254F84BC189D2E91B7503E --env V -- …` | Same `not_found` |
| Use | `otp exec --item … --field "Saved on bank.example.com." …` | Same `not_found` |

Control case: "Example Co @ Payments" has an OTP labelled "one-time password". The same flow works there (`otp exec` filled Stripe's 2FA prompt).

Impact: an agent can't finish a Bank login without a human at the browser, even though the TOTP is stored and approved.

## Likely cause (from reading the code, not yet confirmed)

- `internal/opconnect/client.go` `itemFieldValues` builds a `map[label]value` and skips labels for unlabeled fields (`if f.Label == "" { continue }`). An unlabeled OTP is therefore reachable only by its ID key (`TOTP_…`), and the field **type is dropped**.
- `internal/core/fields.go` `ResolveField` matches the OTP aliases (`otp`, `totp`, `mfa`, `2fa`, `onetimepassword`) against **labels only**. `totp_9fcc…` doesn't equal `totp`, so the alias lookup misses the field even though its type is OTP.
- At approval time, the requested fields seem to go through the same resolver. The OTP never resolves, so it's never approved or cached, and even `--field <id>` finds nothing in the cache. Check how `request submit --fields` decides what to cache.

## Expected

- The OTP aliases (and `otp exec` with no `--field`) should resolve to the item's OTP-type field whatever its label, as long as there's exactly one. If there are several, return an ambiguity error that lists the field IDs.
- `--fields`/`--field` given a field ID should work at both approval and use, as the skill docs already say ("Fields can be addressed by label, stable field ID, or `section.label`").
- `section.label` addressing should have some form for unlabeled fields, or the docs should say it doesn't.

## Regression tests to add

- Approve plus `otp exec` on an item whose only OTP field has `label: ""`, addressed by `otp`, by `one-time password`, and by its field ID.
- Two OTP fields with no labels: an alias lookup returns an ambiguity error, and the ID lookup works.
