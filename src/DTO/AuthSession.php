<?php

declare(strict_types=1);

namespace QRAuth\DTO;

use DateTimeImmutable;
use Exception as PhpException;
use QRAuth\Exception\InvalidResponseException;

/**
 * Auth session as returned by `createAuthSession` and `getAuthSession`.
 *
 * The two endpoints return overlapping but not identical shapes:
 *
 *  - `createAuthSession` adds `token`, `qrUrl`, `qrDataUrl` (the URL the
 *    QR encodes), and includes `scopes` + `expiresAt`.
 *  - `getAuthSession` adds `user`, `signature`, `scannedAt`, `resolvedAt`
 *    once the session has been scanned/resolved. `qrUrl`/`token` are
 *    not present here.
 *
 * Both shapes share `sessionId`, `status`, `scopes`, `expiresAt`. The
 * upstream uses `sessionId` (not `id`) on these endpoints — the
 * `verify-result` endpoint uses `id` on the nested session, parsed by
 * {@see AuthSessionResult}.
 *
 * **Do not return `raw` directly to a browser.** It may carry server-
 * internal hints. Use {@see toClientArray()} for the safe browser-facing
 * view.
 *
 * Status transitions: `PENDING → SCANNED → APPROVED | DENIED | EXPIRED`.
 */
final class AuthSession
{
    public const STATUS_PENDING = 'PENDING';

    public const STATUS_SCANNED = 'SCANNED';

    public const STATUS_APPROVED = 'APPROVED';

    public const STATUS_DENIED = 'DENIED';

    public const STATUS_EXPIRED = 'EXPIRED';

    /**
     * Fields {@see toClientArray()} extracts from `raw` and forwards to
     * the browser. `sessionId` and `status` are always included.
     */
    private const CLIENT_SAFE_KEYS = ['token', 'qrUrl', 'qrDataUrl', 'scopes', 'expiresAt', 'scannedAt', 'resolvedAt'];

    /**
     * @param array<int, string>   $scopes Granted scopes (`identity`, `email`, `organization`).
     * @param array<string, mixed> $raw    Full upstream payload — server-only, not for browsers.
     */
    public function __construct(
        public readonly string $sessionId,
        public readonly string $status,
        public readonly array $scopes,
        public readonly DateTimeImmutable $expiresAt,
        public readonly ?string $token,
        public readonly ?string $qrUrl,
        public readonly ?string $qrDataUrl,
        public readonly ?DateTimeImmutable $scannedAt,
        public readonly ?DateTimeImmutable $resolvedAt,
        public readonly ?AuthenticatedUser $user,
        public readonly ?string $signature,
        public readonly array $raw,
    ) {
    }

    /**
     * @param  array<string, mixed> $data
     * @throws InvalidResponseException
     */
    public static function fromArray(array $data): self
    {
        $sessionId = $data['sessionId'] ?? null;
        if (! is_string($sessionId) || $sessionId === '') {
            throw new InvalidResponseException('AuthSession: missing or empty `sessionId`');
        }

        $status = $data['status'] ?? null;
        if (! is_string($status) || $status === '') {
            throw new InvalidResponseException('AuthSession: missing or empty `status`');
        }

        $expiresAtRaw = $data['expiresAt'] ?? null;
        if (! is_string($expiresAtRaw) || $expiresAtRaw === '') {
            throw new InvalidResponseException('AuthSession: missing or empty `expiresAt`');
        }
        try {
            $expiresAt = new DateTimeImmutable($expiresAtRaw);
        } catch (PhpException $e) {
            throw new InvalidResponseException(
                sprintf('AuthSession: `expiresAt` is not a parseable timestamp (%s)', $expiresAtRaw),
                previous: $e,
            );
        }

        $userRaw = $data['user'] ?? null;
        $user = is_array($userRaw) ? AuthenticatedUser::fromArray($userRaw) : null;

        return new self(
            sessionId: $sessionId,
            status: $status,
            scopes: self::parseScopes($data['scopes'] ?? null),
            expiresAt: $expiresAt,
            token: self::optionalString($data, 'token'),
            qrUrl: self::optionalString($data, 'qrUrl'),
            qrDataUrl: self::optionalString($data, 'qrDataUrl'),
            scannedAt: self::optionalTimestamp($data, 'scannedAt'),
            resolvedAt: self::optionalTimestamp($data, 'resolvedAt'),
            user: $user,
            signature: self::optionalString($data, 'signature'),
            raw: $data,
        );
    }

    /**
     * Browser-safe view of the session. Always includes `sessionId` +
     * `status`; adds `token`, `qrUrl`, `qrDataUrl`, `scopes`, `expiresAt`,
     * `scannedAt`, and `resolvedAt` when present in the upstream payload.
     *
     * @return array<string, mixed>
     */
    public function toClientArray(): array
    {
        $out = [
            'sessionId' => $this->sessionId,
            'status' => $this->status,
        ];
        foreach (self::CLIENT_SAFE_KEYS as $key) {
            if (array_key_exists($key, $this->raw)) {
                $out[$key] = $this->raw[$key];
            }
        }

        return $out;
    }

    public function isPending(): bool
    {
        return $this->status === self::STATUS_PENDING;
    }

    public function isScanned(): bool
    {
        return $this->status === self::STATUS_SCANNED;
    }

    public function isApproved(): bool
    {
        return $this->status === self::STATUS_APPROVED;
    }

    public function isDenied(): bool
    {
        return $this->status === self::STATUS_DENIED;
    }

    public function isExpired(): bool
    {
        return $this->status === self::STATUS_EXPIRED;
    }

    /**
     * @param array<string, mixed> $data
     */
    private static function optionalString(array $data, string $key): ?string
    {
        if (! array_key_exists($key, $data) || $data[$key] === null) {
            return null;
        }
        if (! is_string($data[$key]) || $data[$key] === '') {
            return null;
        }

        return $data[$key];
    }

    /**
     * @param array<string, mixed> $data
     */
    private static function optionalTimestamp(array $data, string $key): ?DateTimeImmutable
    {
        $value = $data[$key] ?? null;
        if (! is_string($value) || $value === '') {
            return null;
        }
        try {
            return new DateTimeImmutable($value);
        } catch (PhpException) {
            return null;
        }
    }

    /**
     * @return array<int, string>
     */
    private static function parseScopes(mixed $value): array
    {
        if (! is_array($value)) {
            return [];
        }

        $scopes = [];
        foreach ($value as $scope) {
            if (is_string($scope) && $scope !== '') {
                $scopes[] = $scope;
            }
        }

        return $scopes;
    }
}
