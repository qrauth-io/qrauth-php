<?php

declare(strict_types=1);

namespace QRAuth\DTO;

use DateTimeImmutable;
use Exception as PhpException;
use QRAuth\Exception\InvalidResponseException;

/**
 * Result of {@see \QRAuth\QRAuth::verifyAuthResult()}.
 *
 * **Always check `valid` before trusting any other field.** When
 * `valid` is `false` the signature did not check out (or the session
 * does not exist / has not approved); every other field is set to a
 * safe zero-value (`''`, `null`, `[]`).
 *
 * When `valid` is `true`:
 *
 *  - `sessionId` is the upstream session ID.
 *  - `status`    is `APPROVED` (the only status that can produce
 *                `valid: true`; included for parity with the wire shape).
 *  - `appName`   is the QRAuth-registered app's display name.
 *  - `scopes`    are the granted scopes (`identity`, `email`, `organization`).
 *  - `user`      is non-null and identifies the approved user. `name`/
 *                `email` on the user are populated only when the
 *                corresponding scope was granted.
 *  - `signature` is the canonical approval signature the upstream
 *                cryptographically verified.
 *  - `resolvedAt` is when the user approved on their device.
 */
final class AuthSessionResult
{
    /**
     * @param array<int, string> $scopes
     */
    public function __construct(
        public readonly bool $valid,
        public readonly string $sessionId,
        public readonly string $status,
        public readonly string $appName,
        public readonly ?AuthenticatedUser $user,
        public readonly array $scopes,
        public readonly ?string $signature,
        public readonly ?DateTimeImmutable $resolvedAt,
    ) {
    }

    /**
     * @param  array<string, mixed> $data
     * @throws InvalidResponseException
     */
    public static function fromArray(array $data): self
    {
        if (! array_key_exists('valid', $data) || ! is_bool($data['valid'])) {
            throw new InvalidResponseException('AuthSessionResult: missing or non-boolean `valid`');
        }

        if ($data['valid'] === false) {
            return new self(
                valid: false,
                sessionId: '',
                status: '',
                appName: '',
                user: null,
                scopes: [],
                signature: null,
                resolvedAt: null,
            );
        }

        $session = $data['session'] ?? null;
        if (! is_array($session)) {
            throw new InvalidResponseException('AuthSessionResult: missing `session` object');
        }

        $userData = $session['user'] ?? null;
        $user = is_array($userData) ? AuthenticatedUser::fromArray($userData) : null;

        $sessionId = $session['id'] ?? null;
        if (! is_string($sessionId) || $sessionId === '') {
            throw new InvalidResponseException('AuthSessionResult: missing `session.id`');
        }

        $status = $session['status'] ?? null;
        $appName = $session['appName'] ?? null;
        $signature = $session['signature'] ?? null;

        return new self(
            valid: true,
            sessionId: $sessionId,
            status: is_string($status) ? $status : '',
            appName: is_string($appName) ? $appName : '',
            user: $user,
            scopes: self::parseScopes($session['scopes'] ?? null),
            signature: is_string($signature) && $signature !== '' ? $signature : null,
            resolvedAt: self::parseTimestamp($session['resolvedAt'] ?? null),
        );
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

    private static function parseTimestamp(mixed $value): ?DateTimeImmutable
    {
        if (! is_string($value) || $value === '') {
            return null;
        }

        try {
            return new DateTimeImmutable($value);
        } catch (PhpException) {
            return null;
        }
    }
}
