<?php

declare(strict_types=1);

namespace QRAuth;

use GuzzleHttp\Client as GuzzleClient;
use GuzzleHttp\Psr7\HttpFactory as GuzzleHttpFactory;
use JsonException;
use Psr\Http\Client\ClientExceptionInterface;
use Psr\Http\Client\ClientInterface;
use Psr\Http\Message\RequestFactoryInterface;
use Psr\Http\Message\ResponseInterface;
use Psr\Http\Message\StreamFactoryInterface;
use QRAuth\DTO\AuthSession;
use QRAuth\DTO\AuthSessionResult;
use QRAuth\DTO\ListQRCodesResult;
use QRAuth\DTO\LocationData;
use QRAuth\DTO\QRCode;
use QRAuth\DTO\VerifyResult;
use QRAuth\Exception\ApiException;
use QRAuth\Exception\ConfigurationException;
use QRAuth\Exception\InvalidResponseException;
use QRAuth\Exception\TransportException;

/**
 * QRAuth SDK client.
 *
 * The SDK exposes three families of endpoints:
 *
 *  - **QR primitives** — `create`, `revoke`, `list`. Authenticated with
 *    the org API key in the `X-API-Key` header.
 *  - **Verification** — `verify`. Public endpoint, no credential header.
 *  - **Auth sessions** — `createAuthSession`, `getAuthSession`,
 *    `verifyAuthResult`. The first two use HTTP Basic auth with the
 *    app's `clientId` + `clientSecret`; `verifyAuthResult` is public
 *    and authenticates by the cryptographic signature it carries in
 *    its body.
 *
 * The API-key and `clientId`/`clientSecret` credentials are
 * independent — an organization may have one or both. Calling
 * auth-session methods without configuring `clientId` and `clientSecret`
 * raises {@see ConfigurationException}.
 *
 * Transport is fully abstracted behind PSR-18 / PSR-17. The default
 * implementation uses Guzzle 7, which already implements both standards
 * and is the only hard dependency. Tests and applications wanting a
 * different HTTP stack can inject their own client and factories.
 */
class QRAuth
{
    public const DEFAULT_BASE_URL = 'https://qrauth.io';

    public const DEFAULT_TIMEOUT = 10;

    public const DEFAULT_CONNECT_TIMEOUT = 5;

    private const USER_AGENT_PREFIX = 'qrauth-php/0.2.0';

    /**
     * Credential-shaped keys stripped from any widget-supplied
     * {@see createAuthSession()} body before forwarding upstream.
     * The widget has no legitimate reason to set these — they belong on
     * the SDK and should never travel inside an attacker-controlled body.
     */
    private const PRIVILEGED_PAYLOAD_KEYS = ['clientId', 'clientSecret', 'apiKey'];

    private readonly ClientInterface $httpClient;

    private readonly RequestFactoryInterface $requestFactory;

    private readonly StreamFactoryInterface $streamFactory;

    private readonly string $baseUrl;

    private readonly string $apiKey;

    private readonly ?string $basicHeader;

    /**
     * @param string                       $tenantId          Your QRAuth tenant ID. Retained for back-compat; the
     *                                                        organization is now derived server-side from the API key,
     *                                                        so this value is not sent on the wire.
     * @param string                       $apiKey            API key for QR primitives (sent as `X-API-Key` header).
     * @param string|null                  $clientId          Client ID for auth-session endpoints (Basic auth).
     * @param string|null                  $clientSecret      Client secret for auth-session endpoints.
     * @param string                       $baseUrl           API base URL (no trailing slash). Must be `https://`
     *                                                        unless the host is loopback or `allowInsecure` is set.
     * @param bool                         $allowInsecure     Permit a non-loopback `http://` `baseUrl`. Off by
     *                                                        default — credentials over plaintext is a footgun.
     * @param ClientInterface|null         $httpClient        PSR-18 HTTP client. Defaults to a configured Guzzle 7 instance.
     * @param RequestFactoryInterface|null $requestFactory    PSR-17 request factory. Defaults to Guzzle's HttpFactory.
     * @param StreamFactoryInterface|null  $streamFactory     PSR-17 stream factory. Defaults to Guzzle's HttpFactory.
     *
     * @throws ConfigurationException If credentials or `baseUrl` are not valid.
     */
    public function __construct(
        public readonly string $tenantId,
        string $apiKey,
        private readonly ?string $clientId = null,
        ?string $clientSecret = null,
        string $baseUrl = self::DEFAULT_BASE_URL,
        bool $allowInsecure = false,
        ?ClientInterface $httpClient = null,
        ?RequestFactoryInterface $requestFactory = null,
        ?StreamFactoryInterface $streamFactory = null,
    ) {
        if (trim($tenantId) === '') {
            throw new ConfigurationException('`tenantId` must not be empty.');
        }
        if (trim($apiKey) === '') {
            throw new ConfigurationException('`apiKey` must not be empty.');
        }

        // Reject control characters in any credential before they get folded
        // into a header. PSR-7 implementations are required to reject CR/LF in
        // header values, but we can't trust an arbitrary injected client to be
        // strict — keep the check at the construction boundary.
        self::assertNoControlChars('tenantId', $tenantId);
        self::assertNoControlChars('apiKey', $apiKey);
        if ($clientId !== null) {
            self::assertNoControlChars('clientId', $clientId);
        }
        if ($clientSecret !== null) {
            self::assertNoControlChars('clientSecret', $clientSecret);
        }

        self::assertValidBaseUrl($baseUrl, $allowInsecure);

        // Both auth-session credentials must be set together, or both omitted.
        $hasClientId = is_string($clientId) && $clientId !== '';
        $hasClientSecret = is_string($clientSecret) && $clientSecret !== '';
        if ($hasClientId !== $hasClientSecret) {
            throw new ConfigurationException(
                '`clientId` and `clientSecret` must either both be provided or both be omitted.',
            );
        }

        $this->baseUrl = rtrim($baseUrl, '/');
        $this->apiKey = $apiKey;
        $this->basicHeader = $hasClientId
            ? 'Basic '.base64_encode($clientId.':'.$clientSecret)
            : null;

        $factory = new GuzzleHttpFactory();
        $this->httpClient = $httpClient ?? new GuzzleClient([
            'timeout' => self::DEFAULT_TIMEOUT,
            'connect_timeout' => self::DEFAULT_CONNECT_TIMEOUT,
            'http_errors' => false,
        ]);
        $this->requestFactory = $requestFactory ?? $factory;
        $this->streamFactory = $streamFactory ?? $factory;
    }

    // ---------------------------------------------------------------------
    // QR primitives — X-API-Key auth
    // ---------------------------------------------------------------------

    /**
     * Create a new signed QR code.
     *
     * The organization is derived from the API key — there is no `tenantId`
     * field in the request body.
     *
     * @param string             $destinationUrl The URL the QR will redirect to (max 2048 chars).
     * @param string|null        $label          Optional human-readable label (max 200 chars).
     * @param LocationData|null  $location       Optional geofence binding (`{lat, lng, radiusM}`).
     * @param \DateTimeInterface|null $expiresAt Optional expiry. Normalized to UTC and serialized as ISO 8601 with the `Z` suffix (`Y-m-d\TH:i:s.v\Z`) — the qrauth.io backend's default Zod `datetime()` schema rejects numeric offsets.
     * @param int|null           $maxScans       Optional total scan cap.
     * @param int|null           $maxScansPerDevice Optional per-device scan cap.
     */
    public function create(
        string $destinationUrl,
        ?string $label = null,
        ?LocationData $location = null,
        ?\DateTimeInterface $expiresAt = null,
        ?int $maxScans = null,
        ?int $maxScansPerDevice = null,
    ): QRCode {
        $payload = [
            'destinationUrl' => $destinationUrl,
        ];
        if ($label !== null) {
            $payload['label'] = $label;
        }
        if ($location !== null) {
            $payload['location'] = $location->toArray();
        }
        if ($expiresAt !== null) {
            $payload['expiresAt'] = (new \DateTimeImmutable('@'.$expiresAt->getTimestamp()))
                ->setTimezone(new \DateTimeZone('UTC'))
                ->format('Y-m-d\TH:i:s.v\Z');
        }
        if ($maxScans !== null) {
            $payload['maxScans'] = $maxScans;
        }
        if ($maxScansPerDevice !== null) {
            $payload['maxScansPerDevice'] = $maxScansPerDevice;
        }

        $data = $this->sendJson('POST', '/api/v1/qrcodes', $payload, self::AUTH_API_KEY);

        return QRCode::fromArray($data);
    }

    /**
     * Verify a QR code token.
     *
     * Optional `clientLat`/`clientLng` are forwarded to QRAuth so its
     * `location_match` and trust-scoring pipeline can factor in physical
     * proximity. The verify endpoint is **public** — no auth header is
     * sent on this call.
     */
    public function verify(string $token, ?float $clientLat = null, ?float $clientLng = null): VerifyResult
    {
        if (trim($token) === '') {
            throw new ConfigurationException('`token` must not be empty.');
        }

        $query = [];
        if ($clientLat !== null) {
            $query['clientLat'] = (string) $clientLat;
        }
        if ($clientLng !== null) {
            $query['clientLng'] = (string) $clientLng;
        }

        $path = '/api/v1/verify/'.rawurlencode($token);
        $data = $this->sendJson('GET', $path, null, self::AUTH_NONE, $query, '/api/v1/verify/{token}');

        return VerifyResult::fromArray($data);
    }

    /**
     * Revoke a QR code so future verifications fail. Returns 204 on success.
     */
    public function revoke(string $token): void
    {
        if (trim($token) === '') {
            throw new ConfigurationException('`token` must not be empty.');
        }

        $path = '/api/v1/qrcodes/'.rawurlencode($token);
        $this->send('DELETE', $path, null, self::AUTH_API_KEY, pathForLog: '/api/v1/qrcodes/{token}');
    }

    /**
     * List the organization's QR codes.
     *
     * The upstream contract uses `page` (1-based) and `pageSize` query
     * params and returns a flat envelope: `{data, total, page, pageSize, totalPages}`.
     * `status` filters with the uppercase enum (`ACTIVE | EXPIRED | REVOKED`).
     *
     * @param  int|null    $page     1-based page number (default 1).
     * @param  int|null    $pageSize Items per page, max 100 (default 20).
     * @param  string|null $status   `ACTIVE | EXPIRED | REVOKED`.
     * @return ListQRCodesResult
     */
    public function list(?int $page = null, ?int $pageSize = null, ?string $status = null): ListQRCodesResult
    {
        $query = [];
        if ($page !== null) {
            $query['page'] = (string) $page;
        }
        if ($pageSize !== null) {
            $query['pageSize'] = (string) $pageSize;
        }
        if ($status !== null) {
            $query['status'] = $status;
        }

        $data = $this->sendJson('GET', '/api/v1/qrcodes', null, self::AUTH_API_KEY, $query);

        return ListQRCodesResult::fromArray($data);
    }

    // ---------------------------------------------------------------------
    // Auth sessions — Basic auth (create/get) + signature-only (verify)
    // ---------------------------------------------------------------------

    /**
     * Proxy a `<qrauth-login>` web component's session-create call.
     *
     * The widget owns the request body. The SDK forwards it under Basic
     * auth after stripping any credential-shaped keys — the widget has
     * no legitimate reason to set these, and forwarding them blindly
     * would let a hostile body smuggle different credentials into the
     * request.
     *
     * Per the upstream `createAuthSessionSchema`, the body fields are:
     *
     *  - `scopes: string[]`              — `identity | email | organization`, default `['identity']`
     *  - `redirectUrl?: string`          — must match the app's registered allowlist
     *  - `metadata?: Record<string,unknown>`
     *  - `codeChallenge?: string`        — PKCE S256 base64url, 43–128 chars
     *  - `codeChallengeMethod?: 'S256'`
     *
     * Public clients (PKCE flow, `clientId` only) MUST send `codeChallenge`.
     *
     * @param  array<string, mixed> $payload The widget's JSON body.
     * @throws ConfigurationException If `clientId`/`clientSecret` were not configured.
     * @throws ApiException           Non-2xx response from QRAuth.
     * @throws TransportException     Transport-level failure.
     * @throws InvalidResponseException Malformed JSON or missing fields.
     */
    public function createAuthSession(array $payload): AuthSession
    {
        $sanitized = $payload;
        foreach (self::PRIVILEGED_PAYLOAD_KEYS as $key) {
            unset($sanitized[$key]);
        }

        $data = $this->sendJson('POST', '/api/v1/auth-sessions', $sanitized, self::AUTH_BASIC);

        return AuthSession::fromArray($data);
    }

    /**
     * Poll an auth session for its current status.
     *
     * `$codeVerifier` carries the PKCE verifier the widget generated;
     * QRAuth uses it to bind the polling browser to the original session
     * issuer.
     *
     * **Logging hazard:** the upstream contract puts the verifier in the
     * URL query string (`?code_verifier=…`). URLs end up in access logs,
     * reverse-proxy logs, and APM tracing. Either drop access-log query
     * strings on this path or scrub `code_verifier` before persistence —
     * the SDK cannot move it server-side without breaking the API contract.
     *
     * @throws ConfigurationException If `clientId`/`clientSecret` were not configured.
     * @throws ApiException           Non-2xx response from QRAuth.
     * @throws TransportException     Transport-level failure.
     * @throws InvalidResponseException Malformed JSON or missing fields.
     */
    public function getAuthSession(string $sessionId, ?string $codeVerifier = null): AuthSession
    {
        if (trim($sessionId) === '') {
            throw new ConfigurationException('`sessionId` must not be empty.');
        }

        $query = [];
        if ($codeVerifier !== null && $codeVerifier !== '') {
            $query['code_verifier'] = $codeVerifier;
        }

        $path = '/api/v1/auth-sessions/'.rawurlencode($sessionId);
        $data = $this->sendJson(
            'GET',
            $path,
            null,
            self::AUTH_BASIC,
            $query,
            '/api/v1/auth-sessions/{sessionId}',
        );

        return AuthSession::fromArray($data);
    }

    /**
     * Cryptographically verify a completed auth session.
     *
     * Trust-establishing call: only treat the result as authoritative
     * when {@see AuthSessionResult::$valid} is `true`. The signature
     * itself authenticates this call — no Authorization header is sent.
     */
    public function verifyAuthResult(string $sessionId, string $signature): AuthSessionResult
    {
        if (trim($sessionId) === '') {
            throw new ConfigurationException('`sessionId` must not be empty.');
        }
        if (trim($signature) === '') {
            throw new ConfigurationException('`signature` must not be empty.');
        }

        $data = $this->sendJson(
            'POST',
            '/api/v1/auth-sessions/verify-result',
            [
                'sessionId' => $sessionId,
                'signature' => $signature,
            ],
            self::AUTH_NONE,
        );

        return AuthSessionResult::fromArray($data);
    }

    // ---------------------------------------------------------------------
    // Internal HTTP plumbing
    // ---------------------------------------------------------------------

    /**
     * Auth modes for outbound SDK requests.
     *
     * - {@see AUTH_API_KEY}: send `X-API-Key: {apiKey}`. Used by every QR
     *   primitive (`create`, `verify` is actually public but still safe with
     *   the header, `revoke`, `list`).
     * - {@see AUTH_BASIC}: send `Authorization: Basic base64(clientId:clientSecret)`
     *   plus `X-Client-Id`. Used by `createAuthSession`/`getAuthSession`.
     * - {@see AUTH_NONE}: no auth header. Used by the public `verifyAuthResult`
     *   endpoint, which authenticates by the cryptographic signature in its body.
     */
    private const AUTH_API_KEY = 'api-key';

    private const AUTH_BASIC = 'basic';

    private const AUTH_NONE = 'none';

    /**
     * Send a request expecting a JSON object response.
     *
     * `$pathForLog` is the path used in error messages — pass a templated
     * form (`/api/v1/verify/{token}`) when the real path interpolates a
     * sensitive token, so the token never leaks via exception text.
     *
     * @param  array<string, mixed>|null    $payload    Request body, encoded as JSON when present.
     * @param  array<string, string|int>    $query      Query parameters.
     * @return array<string, mixed>                     Decoded response body.
     */
    private function sendJson(
        string $method,
        string $path,
        ?array $payload,
        string $authMode,
        array $query = [],
        ?string $pathForLog = null,
    ): array {
        $response = $this->send($method, $path, $payload, $authMode, $query, $pathForLog);

        return $this->decodeJsonObject($response);
    }

    /**
     * Build, dispatch, and return a raw PSR-7 response — already checked
     * for HTTP-level success.
     *
     * @param array<string, mixed>|null    $payload
     * @param array<string, string|int>    $query
     */
    private function send(
        string $method,
        string $path,
        ?array $payload,
        string $authMode,
        array $query = [],
        ?string $pathForLog = null,
    ): ResponseInterface {
        $url = $this->baseUrl.$path;
        if ($query !== []) {
            $url .= '?'.http_build_query($query);
        }

        $request = $this->requestFactory
            ->createRequest($method, $url)
            ->withHeader('Accept', 'application/json')
            ->withHeader('User-Agent', self::USER_AGENT_PREFIX);

        $request = match ($authMode) {
            self::AUTH_API_KEY => $request->withHeader('X-API-Key', $this->apiKey),
            self::AUTH_BASIC => $request
                ->withHeader('Authorization', $this->requireBasicHeader())
                ->withHeader('X-Client-Id', (string) $this->clientId),
            self::AUTH_NONE => $request,
            default => throw new ConfigurationException(sprintf('Unknown auth mode: %s', $authMode)),
        };

        if ($payload !== null) {
            try {
                $body = json_encode($payload, JSON_THROW_ON_ERROR);
            } catch (JsonException $e) {
                throw new InvalidResponseException('Failed to encode request body as JSON.', previous: $e);
            }
            $request = $request
                ->withHeader('Content-Type', 'application/json')
                ->withBody($this->streamFactory->createStream($body));
        }

        try {
            $response = $this->httpClient->sendRequest($request);
        } catch (ClientExceptionInterface $e) {
            throw new TransportException(
                sprintf('Transport error contacting QRAuth: %s', $e->getMessage()),
                previous: $e,
            );
        }

        $this->assertSuccessful($method, $pathForLog ?? $path, $response);

        return $response;
    }

    /**
     * Raise an {@see ApiException} on any non-2xx response.
     */
    private function assertSuccessful(string $method, string $pathForLog, ResponseInterface $response): void
    {
        $status = $response->getStatusCode();
        if ($status >= 200 && $status < 300) {
            return;
        }

        $body = (string) $response->getBody();
        $decoded = null;
        if ($body !== '') {
            try {
                $decoded = json_decode($body, true, 512, JSON_THROW_ON_ERROR);
            } catch (JsonException) {
                // Non-JSON error body — leave $decoded as null and surface a generic message.
            }
        }

        throw new ApiException(
            statusCode: $status,
            body: is_array($decoded) ? $decoded : null,
            message: sprintf('QRAuth API %s %s returned HTTP %d', $method, $pathForLog, $status),
        );
    }

    /**
     * Decode a JSON object body, raising {@see InvalidResponseException}
     * for any payload that is not a JSON object.
     *
     * @return array<string, mixed>
     */
    private function decodeJsonObject(ResponseInterface $response): array
    {
        $body = (string) $response->getBody();

        if ($body === '') {
            throw new InvalidResponseException('QRAuth returned an empty body where JSON was expected.');
        }

        try {
            $decoded = json_decode($body, true, 512, JSON_THROW_ON_ERROR);
        } catch (JsonException $e) {
            throw new InvalidResponseException('QRAuth returned invalid JSON.', previous: $e);
        }

        if (! is_array($decoded)) {
            throw new InvalidResponseException('QRAuth returned non-object JSON.');
        }

        /** @var array<string, mixed> */
        return $decoded;
    }

    private function requireBasicHeader(): string
    {
        if ($this->basicHeader === null) {
            throw new ConfigurationException(
                'Auth-session methods require `clientId` and `clientSecret` to be configured.',
            );
        }

        return $this->basicHeader;
    }

    /**
     * Validate that `$baseUrl` is a usable QRAuth endpoint:
     *  - syntactically valid URL
     *  - http or https scheme (https required unless loopback or `$allowInsecure`)
     *  - no embedded userinfo (`https://user:pass@host`) — a footgun
     *
     * @throws ConfigurationException
     */
    private static function assertValidBaseUrl(string $url, bool $allowInsecure): void
    {
        if (filter_var($url, FILTER_VALIDATE_URL) === false) {
            throw new ConfigurationException(sprintf('`baseUrl` must be an http(s) URL, got: %s', $url));
        }

        $parts = parse_url($url);
        if (! is_array($parts) || ! isset($parts['scheme'], $parts['host'])) {
            throw new ConfigurationException(sprintf('`baseUrl` must be an http(s) URL, got: %s', $url));
        }

        $scheme = strtolower($parts['scheme']);
        if ($scheme !== 'http' && $scheme !== 'https') {
            throw new ConfigurationException(sprintf('`baseUrl` must be an http(s) URL, got: %s', $url));
        }

        if (isset($parts['user']) || isset($parts['pass'])) {
            throw new ConfigurationException(
                '`baseUrl` must not embed credentials (`user:pass@host`); pass them via the constructor instead.',
            );
        }

        if ($scheme === 'http' && ! $allowInsecure && ! self::isLoopbackHost($parts['host'])) {
            throw new ConfigurationException(sprintf(
                '`baseUrl` uses http:// against a non-loopback host (%s). Use https://, '.
                'or pass `allowInsecure: true` if you genuinely need plaintext (e.g. behind a service mesh).',
                $parts['host'],
            ));
        }
    }

    private static function isLoopbackHost(string $host): bool
    {
        $host = strtolower(trim($host, '[]'));

        return $host === 'localhost'
            || $host === '127.0.0.1'
            || $host === '::1'
            || str_ends_with($host, '.localhost');
    }

    /**
     * @throws ConfigurationException
     */
    private static function assertNoControlChars(string $field, string $value): void
    {
        if (preg_match('/[\x00-\x1F\x7F]/', $value) === 1) {
            throw new ConfigurationException(sprintf(
                '`%s` must not contain control characters (CR, LF, NUL, etc.).',
                $field,
            ));
        }
    }
}
