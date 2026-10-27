Real `GET /api/v1/verify/:token` JSON responses, captured on 2026-10-27 from a
local QRAuth API (throwaway database), one per trust state:

| File | trust_state | Notes |
|---|---|---|
| verify-verified.json | VERIFIED | issuer with a verified domain |
| verify-signed-unverified-issuer.json | SIGNED_UNVERIFIED_ISSUER | valid code, issuer not verified |
| verify-untrusted-lookalike.json | UNTRUSTED | destination resembles a verified domain (`domain_warning`) |
| verify-revoked.json | UNTRUSTED | revoked code: no `destination_url` |
| verify-flagged.json | UNTRUSTED | destination flagged by screening: no `destination_url` |
