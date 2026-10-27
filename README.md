# QRAuth PHP SDK

[![CI](https://github.com/qrauth-io/qrauth-php/actions/workflows/ci.yml/badge.svg)](https://github.com/qrauth-io/qrauth-php/actions/workflows/ci.yml)

The official PHP SDK for [QRAuth](https://qrauth.io) — passwordless QR authentication and signed-QR verification.

[![License: MIT](https://img.shields.io/badge/License-MIT-blue.svg)](LICENSE)

## Requirements

- PHP 8.1+
- Any [PSR-18](https://www.php-fig.org/psr/psr-18/) HTTP client (Guzzle 7 is bundled and used by default)

## Installation

```bash
composer require qrauth/qrauth-php
```

## Endpoint families

| Family            | Endpoints                                                  | Auth                                          |
|-------------------|------------------------------------------------------------|-----------------------------------------------|
| **QR primitives** | `create`, `revoke`, `list`                                 | `apiKey` in `X-API-Key` header                |
| **Verification**  | `verify`                                                   | none (public endpoint)                        |
| **Auth sessions** | `createAuthSession`, `getAuthSession`                      | `clientId` + `clientSecret` (HTTP Basic)      |
| **Session verify**| `verifyAuthResult`                                         | none — signature in body authenticates        |

An organization may configure one or both credential pairs. Calling auth-session methods without `clientId` and `clientSecret` raises `ConfigurationException`.

## Quick start — passwordless login

```php
use QRAuth\QRAuth;

$qrauth = new QRAuth(
    tenantId:     'your-tenant-id',
    apiKey:       'your-api-key',
    clientId:     'your-client-id',
    clientSecret: 'your-client-secret',
);

// 1. The browser's <qrauth-login> widget POSTs the session config to your
//    backend, which forwards it upstream. The SDK strips credential-shaped
//    keys from the body before sending — see "Trust boundary" below.
$session = $qrauth->createAuthSession($_POST);
return response()->json($session->toClientArray());

// 2. The widget polls the session until the user approves on their phone.
//    For PKCE flows, pass the verifier the widget generated:
$polled = $qrauth->getAuthSession($sessionId, $codeVerifier);

// 3. After approval, the widget fires `qrauth:authenticated` with a
//    sessionId + signature. Your callback verifies it server-side:
$result = $qrauth->verifyAuthResult($sessionId, $signature);

if (! $result->valid) {
    abort(401);
}

// $result->user->id    — stable QRAuth user ID, persist this
// $result->user->name  — present if the `identity` scope was granted
// $result->user->email — present if the `email` scope was granted
$user = User::firstOrCreate(
    ['qrauth_user_id' => $result->user->id],
    ['email' => $result->user->email, 'name' => $result->user->name],
);
auth()->login($user);
```

The browser **never talks to qrauth.io directly** for the session-create / poll calls. Your server proxies them so that `clientSecret` is never exposed and CORS is sidestepped. The user-facing approval page (`/a/{token}`) does live on qrauth.io because WebAuthn requires it.

### Trust boundary on the session-create body

`createAuthSession()` accepts the widget's body but strips credential-shaped keys (`clientId`, `clientSecret`, `apiKey`) before forwarding upstream. The widget has no legitimate reason to set these — they belong on the SDK and would let a hostile body smuggle different credentials into the request.

Per the upstream `createAuthSessionSchema`, the supported body fields are:

- `scopes: string[]` — `identity | email | organization`, default `['identity']`
- `redirectUrl?: string` — must match the app's registered allowlist
- `metadata?: Record<string,unknown>`
- `codeChallenge?: string` — PKCE S256 base64url, 43–128 chars
- `codeChallengeMethod?: 'S256'`

Public clients (PKCE flow, `clientId` only — no secret) MUST send `codeChallenge`. Treat the widget's POST body as **untrusted client input**: if you need stricter validation (allowed scopes, allowed redirect URIs), enforce it in your handler before the `createAuthSession()` call.

### Don't forward `$session->raw` to the browser

`AuthSession::$raw` is the unfiltered upstream response, intended for server-side debugging. Use `$session->toClientArray()` in your HTTP handler instead — it returns only the browser-safe shape (`sessionId`, `status`, `token`, `qrUrl`, `qrDataUrl`, `scopes`, `expiresAt`, `scannedAt`, `resolvedAt` when present).

### `getAuthSession` and the PKCE verifier

The polling endpoint takes the PKCE `code_verifier` in the URL query string (per the QRAuth API contract). URLs end up in nginx access logs, reverse-proxy logs, and APM traces — so either drop the query string from logs on this path, or scrub `code_verifier` before persistence. The SDK can't move it server-side without breaking the API.

## Quick start — signed QR for verification

```php
use QRAuth\QRAuth;
use QRAuth\DTO\LocationData;

$qrauth = new QRAuth(tenantId: '...', apiKey: '...');

$qr = $qrauth->create(
    destinationUrl: 'https://example.com/landing',
    label:          'Trade Show 2026',
    location:       new LocationData(lat: 40.7128, lng: -74.0060, radiusM: 100),
    expiresAt:      new DateTimeImmutable('+30 days'),
);

echo $qr->qrImageUrl;        // → embed in marketing assets
echo $qr->verificationUrl;   // → opens on any phone camera
```

To verify a scan server-side:

```php
use QRAuth\DTO\TrustState;

$result = $qrauth->verify(
    token:      $token,
    clientLat:  40.7128,
    clientLng:  -74.0060,
);

switch ($result->trustState) {
    case TrustState::Verified:
        // Authentic, and QRAuth has verified who issued it.
        echo $result->organization->name;        // issuer name
        echo $result->organization->verifiedDomain; // e.g. example.com (may be null)
        break;
    case TrustState::SignedUnverifiedIssuer:
        // Authentic signed code, but the issuer is not verified by QRAuth.
        // No issuer name is returned; show the destination host instead.
        echo parse_url((string) $result->destinationUrl, PHP_URL_HOST);
        break;
    case TrustState::Untrusted:
        // Revoked, expired, flagged, lookalike destination, ...
        echo $result->reason;                    // may be null
        break;
}
```

`$result->verified` is `true` only for `TrustState::Verified`.
`$result->destinationUrl` is `null` on failure responses (revoked, expired,
scan limit, suspended issuer, flagged destination).

## API surface

### `QRAuth::__construct(...)`

| Parameter         | Required | Default                                               |
|-------------------|----------|-------------------------------------------------------|
| `tenantId`        | yes      | — (kept for back-compat; not sent on the wire — the organization is derived from the API key) |
| `apiKey`          | yes      | —                                                     |
| `clientId`        | no       | `null`                                                |
| `clientSecret`    | no       | `null`                                                |
| `baseUrl`         | no       | `https://qrauth.io`                                   |
| `allowInsecure`   | no       | `false` (rejects non-loopback `http://` `baseUrl`)    |
| `httpClient`      | no       | `GuzzleHttp\Client` (10s timeout, 5s connect timeout) |
| `requestFactory`  | no       | Guzzle's `HttpFactory`                                |
| `streamFactory`   | no       | Guzzle's `HttpFactory`                                |

`baseUrl` must be `https://`. An `http://` URL is rejected unless the host is loopback (`localhost`, `127.0.0.1`, `::1`, `*.localhost`) or `allowInsecure: true` is passed — credentials over plaintext is a footgun. `baseUrl` must also not embed `user:pass@` — pass credentials through the constructor instead.

Credential parameters (`tenantId`, `apiKey`, `clientId`, `clientSecret`) are rejected if they contain control characters (CR, LF, NUL, etc.) — defence-in-depth against header injection if a non-strict PSR-7 implementation is injected.

Inject your own PSR-18 client + PSR-17 factories to swap the HTTP stack — useful for tests, custom retry/logging middleware, or environments that prefer a different client.

### QR primitives

```php
$qrauth->create(
    string $destinationUrl,
    ?string $label = null,
    ?LocationData $location = null,
    ?DateTimeInterface $expiresAt = null,
    ?int $maxScans = null,
    ?int $maxScansPerDevice = null,
): QRCode;

$qrauth->verify(
    string $token,
    ?float $clientLat = null,
    ?float $clientLng = null,
): VerifyResult;

$qrauth->revoke(string $token): void;

$qrauth->list(
    ?int $page = null,         // 1-based, default 1
    ?int $pageSize = null,     // default 20, max 100
    ?string $status = null,    // ACTIVE | EXPIRED | REVOKED
): ListQRCodesResult;          // { items: QRCode[], total, page, pageSize, totalPages }
```

### Auth sessions

```php
$qrauth->createAuthSession(array $payload): AuthSession;

$qrauth->getAuthSession(string $sessionId, ?string $codeVerifier = null): AuthSession;

$qrauth->verifyAuthResult(string $sessionId, string $signature): AuthSessionResult;
```

## Exceptions

All SDK exceptions implement `QRAuth\Exception\QRAuthExceptionInterface`. Catch the interface for blanket handling, or branch on the concrete type:

| Exception                    | When                                                          |
|------------------------------|---------------------------------------------------------------|
| `ConfigurationException`     | invalid SDK config (empty creds, malformed `baseUrl`, etc.)  |
| `TransportException`         | DNS / TLS / timeout / connection refused                      |
| `ApiException`               | non-2xx response from QRAuth (carries `statusCode` + `body`)  |
| `InvalidResponseException`   | 2xx with non-JSON, non-object, or shape-incompatible payload  |

```php
use QRAuth\Exception\ApiException;
use QRAuth\Exception\QRAuthExceptionInterface;

try {
    $qrauth->verifyAuthResult($sessionId, $signature);
} catch (ApiException $e) {
    Log::warning('QRAuth API rejected verify-result', [
        'status' => $e->statusCode,
        'error'  => $e->errorCode(),
    ]);
    abort(401);
} catch (QRAuthExceptionInterface $e) {
    Log::error('QRAuth SDK failure', ['exception' => $e]);
    abort(503);
}
```

## Development

```bash
composer install
composer test    # PHPUnit
composer stan    # PHPStan (level 8)
```

## Changelog

See [CHANGELOG.md](CHANGELOG.md).

## License

MIT — see [LICENSE](LICENSE).

## Resources

- [QRAuth docs](https://docs.qrauth.io)
- [API reference](https://docs.qrauth.io/api/overview.html)
- [Issues](https://github.com/qrauth-io/qrauth-php/issues)
