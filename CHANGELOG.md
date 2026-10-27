# Changelog

All notable changes to `qrauth/qrauth-php` are documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.1.0/),
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [0.2.0]

### Changed (breaking)

`verify()` results follow the verify API's trust states:

- **New `VerifyResult::$trustState`**, a backed enum `QRAuth\DTO\TrustState`:
  `Verified` (`VERIFIED`), `SignedUnverifiedIssuer` (`SIGNED_UNVERIFIED_ISSUER`)
  and `Untrusted` (`UNTRUSTED`).
- **`VerifyResult::$verified`** is `true` only when `trustState` is `Verified`,
  which requires an issuer verified by QRAuth. An authentic code from an issuer
  QRAuth has not verified returns `verified === false` with
  `TrustState::SignedUnverifiedIssuer`.
- **`VerifyResult::$destinationUrl` is `?string`.** It is `null` on failure
  responses (revoked, expired, scan limit, suspended issuer, flagged
  destination).
- **`Organization`** is now `{ verified: bool, name: ?string, verifiedDomain: ?string }`.
  `name` and `verifiedDomain` are set only when `verified` is `true`. The
  `id`, `slug`, `trustLevel`, `kycStatus` and `domainVerified` properties are
  removed because the API no longer returns them.

### Fixed

- `verify()` parses the current verify response format in all trust states.

### Tests

- Verify tests use real API responses (tests/Fixtures) for all three trust
  states, including revoked and flagged codes.

## [0.1.1]

### Fixed

- **`create()` now serializes `expiresAt` as `Y-m-d\TH:i:s.v\Z` in UTC.**
  The previous format (`Y-m-d\TH:i:s.vP`) emitted a numeric offset
  (`+00:00` / `+03:00`), which the qrauth.io backend's default Zod
  `datetime()` schema rejects with `400 Validation Error`. The datetime
  is now normalized to UTC and emitted with the `Z` suffix.

## [Unreleased]

### Wire-contract alignment with the QRAuth backend

This release rewrites the SDK's HTTP layer to match the actual `qrauth-io/qrauth`
API. Previous releases were built against a contract that did not match what the
deployed backend accepts; in practice almost every method would have failed.
Every change in this section is **breaking** for callers of the previous shape,
but consistent with the upstream zod schemas and route source.

#### Authentication

- **QR primitives now use `X-API-Key`**, not `Authorization: Bearer`. The
  upstream auth middleware reserves `Authorization: Bearer` for user JWTs;
  Bearer-with-API-key returned 401.
- **`verify()` is public** and sends no auth header. The endpoint accepts no
  credentials.
- **`verifyAuthResult()` is public** (signature in body authenticates).
- Auth sessions still use HTTP Basic with `clientId:clientSecret`, plus
  `X-Client-Id` (no functional change).

#### `create()` body

- New signature: `create(destinationUrl, label?, location?, expiresAt?, maxScans?, maxScansPerDevice?)`.
- `destination` → `destinationUrl`.
- `expiresIn` (seconds) → `expiresAt` (`DateTimeInterface`, serialized as ISO 8601).
- `metadata` removed (not a field in the upstream schema).
- `tenantId` no longer sent in the body — derived from the API key.
- New optional `maxScans` and `maxScansPerDevice` fields.

#### `verify()` query params

- `scannerLat` / `scannerLng` → `clientLat` / `clientLng`.

#### `list()` pagination

- New signature: `list(page?, pageSize?, status?): ListQRCodesResult`.
- Query params: `?limit=&offset=` → `?page=&pageSize=` (page is 1-based).
- Status enum is uppercase: `ACTIVE | EXPIRED | REVOKED`.
- Returns a typed `ListQRCodesResult` with `{items, total, page, pageSize, totalPages}`.

#### `LocationData`

- `radius` → `radiusM`. The DTO accepts both keys when parsing from JSON for
  forward compatibility, but `toArray()` and the constructor now use `radiusM`.

#### `createAuthSession()` body

- Dropped the `tenantId` pin from the previous security branch — `tenantId` is
  not a documented field on this endpoint and the upstream zod schema rejects it.
- Credential-shaped key stripping (`clientId`, `clientSecret`, `apiKey`) is
  retained.
- Documented the actual upstream body fields: `scopes` (`identity | email | organization`),
  `redirectUrl`, `metadata`, `codeChallenge`, `codeChallengeMethod`.

#### DTO rewrites

- **`QRCode`** — accepts both the snake_case create response
  (`verification_url`, `qr_image_url`, `created_at`, `expires_at`,
  `organization_id`) and the camelCase prisma row from list/get-single.
  Replaced strict `tenantId` requirement with optional `organizationId`.
- **`VerifyResult`** — completely new shape:
  `{verified, reason?, organization, destinationUrl, locationMatch, security, warnings, scannedAt}`.
- **`IssuerInfo` deleted, `Organization` added** — `{id, name, slug, trustLevel, kycStatus, domainVerified}`.
- **`LocationMatch`** new — nested `{matched, distanceM, registeredAddress}`.
- **`SecurityInfo`** new — `{signatureValid, proxyDetected, trustScore,
  transparencyLogVerified, algVersion?, algVersionStatus?, pqcProtected?,
  merkleProofValid?, merkleBatchId?}`.
- **`AuthSession`** — `id` field renamed to `sessionId` (the upstream wire
  field). Top-level `qrUrl`, `qrDataUrl`, `token`, `scopes`, `expiresAt`
  surfaced as typed properties. New `scannedAt`, `resolvedAt`, `user`, and
  `signature` typed fields parsed from the poll response. Added the
  `SCANNED` status (the previous DTO was missing it).
- **`AuthSessionResult`** — added `sessionId` (parsed from `session.id`) and
  `signature` fields to mirror the upstream `verify-result` payload.
- **`ListQRCodesResult`** new — paginated envelope DTO.
- **`AuthSession::toClientArray()`** allowlist updated to the real wire
  fields (`token`, `qrUrl`, `qrDataUrl`, `scopes`, `expiresAt`,
  `scannedAt`, `resolvedAt`).

#### Constructor

- `tenantId` parameter retained for back-compat but no longer sent over
  the wire on any endpoint.

### Security

- **`baseUrl` rejects plaintext `http://` against non-loopback hosts** by
  default. Loopback hosts (`localhost`, `127.0.0.1`, `::1`, `*.localhost`)
  remain allowed for local dev/testing. Pass the new constructor argument
  `allowInsecure: true` to opt back in for trusted internal mesh traffic.
  Closes a vector where a misconfigured `baseUrl` would have leaked the
  Bearer / Basic credentials in the clear.
- **`baseUrl` rejects embedded `user:pass@`** to keep credentials off URLs
  (which end up in logs / process listings).
- **Credential constructor arguments reject control characters** (CR, LF,
  NUL, etc.). Guzzle's PSR-7 already rejects CR/LF in header values, but
  this enforces it at the SDK boundary so a non-strict PSR-7 client can't
  weaken the guarantee.
- **`createAuthSession()` pins `tenantId` server-side** and strips
  credential-shaped keys (`tenantId`, `clientId`, `clientSecret`,
  `apiKey`) from the widget-supplied body before forwarding upstream.
  A hostile browser body can no longer use the configured Basic
  credentials against another tenant ID or smuggle a different client
  secret into the request.
- **`ApiException` messages use a templated path** (`/api/v1/verify/{token}`,
  `/api/v1/qrcodes/{token}`, `/api/v1/auth-sessions/{sessionId}`) instead
  of the literal request path. Tokens and session IDs no longer leak into
  exception messages — and therefore into log aggregators that index
  `Throwable::getMessage()`.
- **`AuthSession::toClientArray()` is the new browser-facing view.**
  Replaces the previous "return `$session->raw` to the client" pattern;
  the README now uses it. `raw` is preserved for server-side debugging
  but documented as not-for-the-browser.
- **`getAuthSession()` documents the PKCE-verifier-in-query logging
  hazard.** The upstream contract requires the verifier in the query
  string; the SDK can't fix this, but consumers are now warned in the
  PHPDoc and in the README.

### Added

- **Auth-session API surface** — three new methods for the `<qrauth-login>`
  passwordless flow:
  - `createAuthSession(array $payload): AuthSession` — server-side proxy for
    the widget's session-create call.
  - `getAuthSession(string $sessionId, ?string $codeVerifier = null): AuthSession`
    — server-side proxy for the widget's polling call.
  - `verifyAuthResult(string $sessionId, string $signature): AuthSessionResult`
    — cryptographic verification of a completed session. Sends no
    `Authorization` header; the signature in the body is the trust root.
- **Second credential pair** — optional `clientId` + `clientSecret` constructor
  arguments. Required for auth-session methods (HTTP Basic auth + `X-Client-Id`
  header). Validated as "both or neither" in the constructor.
- **DTO value objects** under `QRAuth\DTO\` — `QRCode`, `VerifyResult`,
  `IssuerInfo`, `LocationData`, `AuthSession`, `AuthSessionResult`,
  `AuthenticatedUser`. All `final`, `readonly`, with defensive `fromArray()`
  parsers that raise `InvalidResponseException` on malformed payloads.
- **Exception hierarchy** under `QRAuth\Exception\` — marker interface
  `QRAuthExceptionInterface` plus `ConfigurationException`,
  `TransportException`, `ApiException` (carries status code + decoded body),
  `InvalidResponseException`.
- **PSR-18 / PSR-17 transport layer** — `httpClient`, `requestFactory`, and
  `streamFactory` are constructor-injectable. Default implementation uses
  Guzzle 7, which already implements all three standards. Deps:
  `psr/http-client`, `psr/http-factory`, `psr/http-message`.
- **Default network safety** — bundled Guzzle client uses `timeout: 10` and
  `connect_timeout: 5` so a hung upstream cannot block a request indefinitely.
- **PHPUnit test suite** — 20 tests, 70 assertions, covering configuration
  validation, both endpoint families, error paths, and shape-defensive
  parsing. Mocked PSR-18 client (`tests/Support/MockHttpClient.php`) keeps
  the suite hermetic.
- **PHPStan configuration** at level 8 (`phpstan.neon.dist`), passing on `src`
  and `tests`.
- **Composer scripts** — `composer test`, `composer stan`.

### Changed

- **`QRAuth\QRAuth` is fully refactored** with strict types, readonly
  properties, constructor property promotion, and PSR-18 transport. The
  public method signatures are source-compatible (named arguments unchanged)
  but the return types are now typed DTOs instead of associative arrays —
  see "Breaking changes" below.
- **`create()` accepts `LocationData`** instead of a raw associative array
  for the `$location` parameter.
- **Tokens are now `rawurlencode`-ed** when interpolated into URL paths in
  `verify()`, `revoke()`, and `getAuthSession()` — closes a path-traversal
  smell where opaque tokens could change a request's URL semantics.
- **`baseUrl` is validated** as a syntactically valid `http(s)` URL in the
  constructor; non-HTTP schemes and malformed URLs raise
  `ConfigurationException` immediately rather than failing in flight.
- **`tenantId` and `apiKey` are required non-empty** at construction time;
  empty values raise `ConfigurationException` instead of producing cryptic
  401s downstream.
- **`User-Agent` header** (`qrauth-php/0.2.0`) is now sent on every request.
- **Error responses** raise `ApiException` (with status code + decoded body)
  instead of leaking raw `GuzzleException`.
- **Malformed JSON responses** raise `InvalidResponseException` instead of
  silently producing a `null`-bearing array. `JSON_THROW_ON_ERROR` is set on
  every decode and encode.

### Breaking changes

- **`create()` returns `QRCode`** instead of `array<string, mixed>`.
- **`verify()` returns `VerifyResult`** instead of `array<string, mixed>`.
- **`list()` returns `array<int, QRCode>`** instead of an untyped array.
  Both flat-array and `{items: [...], total, ...}` paginated envelope
  shapes are accepted from the API.
- **Exceptions are now domain-specific.** Code catching
  `\GuzzleHttp\Exception\GuzzleException` will no longer match SDK errors —
  catch `QRAuth\Exception\QRAuthExceptionInterface` (or the concrete
  subclasses) instead.

These changes affect callers of the previous `0.1.0` scaffolding only;
nothing has been published to Packagist yet under the previous shape.

## [0.1.0] — 2026-04-04

### Added

- Initial scaffolding: `QRAuth` client class with `create`, `verify`,
  `revoke`, `list` methods using `Authorization: Bearer {apiKey}` and
  Guzzle 7 directly.
