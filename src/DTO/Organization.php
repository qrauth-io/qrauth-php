<?php

declare(strict_types=1);

namespace QRAuth\DTO;

use QRAuth\Exception\InvalidResponseException;

/**
 * The QR-issuing organization, as returned inside a {@see VerifyResult}.
 *
 * `trustLevel` is a server-computed label derived from the org's KYC
 * state, verification history, and signal mix. Concrete values seen on
 * the wire today include `low`, `medium`, `high` — but the SDK accepts
 * the field as a free-form string so a future enum extension does not
 * break parsing.
 */
final class Organization
{
    public function __construct(
        public readonly string $id,
        public readonly string $name,
        public readonly string $slug,
        public readonly string $trustLevel,
        public readonly string $kycStatus,
        public readonly bool $domainVerified,
    ) {
    }

    /**
     * @param  array<string, mixed> $data
     * @throws InvalidResponseException
     */
    public static function fromArray(array $data): self
    {
        return new self(
            id: self::requireString($data, 'id'),
            name: self::requireString($data, 'name'),
            slug: self::requireString($data, 'slug'),
            trustLevel: self::requireString($data, 'trustLevel'),
            kycStatus: self::requireString($data, 'kycStatus'),
            domainVerified: self::requireBool($data, 'domainVerified'),
        );
    }

    /**
     * @param array<string, mixed> $data
     */
    private static function requireString(array $data, string $key): string
    {
        $value = $data[$key] ?? null;
        if (! is_string($value) || $value === '') {
            throw new InvalidResponseException(sprintf('Organization: missing or empty `%s`', $key));
        }

        return $value;
    }

    /**
     * @param array<string, mixed> $data
     */
    private static function requireBool(array $data, string $key): bool
    {
        $value = $data[$key] ?? null;
        if (! is_bool($value)) {
            throw new InvalidResponseException(sprintf('Organization: missing or non-boolean `%s`', $key));
        }

        return $value;
    }
}
