<?php

declare(strict_types=1);

namespace QRAuth\DTO;

use DateTimeImmutable;
use Exception as PhpException;
use QRAuth\Exception\InvalidResponseException;

/**
 * A QR code returned by {@see \QRAuth\QRAuth::create()} or
 * {@see \QRAuth\QRAuth::list()}.
 *
 * The upstream API uses two different JSON conventions on these
 * endpoints — `create` returns snake_case keys
 * (`verification_url`, `qr_image_url`, `created_at`, `expires_at`,
 * `organization_id`) while `list` returns the full Prisma row in
 * camelCase (`createdAt`, `expiresAt`, `organizationId`, with no
 * `verificationUrl`/`qrImageUrl`). This DTO accepts either shape so
 * the same value object works for both call sites.
 *
 * Required across both shapes: `token`, `signature`, `createdAt`. All
 * other fields are nullable because they may not be present in one of
 * the two response shapes.
 */
final class QRCode
{
    public function __construct(
        public readonly string $token,
        public readonly string $signature,
        public readonly DateTimeImmutable $createdAt,
        public readonly ?DateTimeImmutable $expiresAt,
        public readonly ?string $verificationUrl,
        public readonly ?string $qrImageUrl,
        public readonly ?string $label,
        public readonly ?string $status,
        public readonly ?string $organizationId,
    ) {
    }

    /**
     * @param  array<string, mixed> $data
     * @throws InvalidResponseException
     */
    public static function fromArray(array $data): self
    {
        return new self(
            token: self::requireString($data, 'token'),
            signature: self::requireString($data, 'signature'),
            createdAt: self::requireDate($data, ['createdAt', 'created_at']),
            expiresAt: self::optionalDate($data, ['expiresAt', 'expires_at']),
            verificationUrl: self::optionalString($data, ['verificationUrl', 'verification_url']),
            qrImageUrl: self::optionalString($data, ['qrImageUrl', 'qr_image_url']),
            label: self::optionalString($data, ['label']),
            status: self::optionalString($data, ['status']),
            organizationId: self::optionalString($data, ['organizationId', 'organization_id']),
        );
    }

    /**
     * @param array<string, mixed> $data
     */
    private static function requireString(array $data, string $key): string
    {
        $value = $data[$key] ?? null;
        if (! is_string($value) || $value === '') {
            throw new InvalidResponseException(sprintf('QRCode: missing or empty `%s`', $key));
        }

        return $value;
    }

    /**
     * @param array<string, mixed> $data
     * @param array<int, string>   $keys First match wins.
     */
    private static function optionalString(array $data, array $keys): ?string
    {
        foreach ($keys as $key) {
            if (! array_key_exists($key, $data)) {
                continue;
            }
            $value = $data[$key];
            if ($value === null) {
                return null;
            }
            if (is_string($value) && $value !== '') {
                return $value;
            }
            throw new InvalidResponseException(sprintf('QRCode: `%s` must be a non-empty string', $key));
        }

        return null;
    }

    /**
     * @param array<string, mixed> $data
     * @param array<int, string>   $keys
     */
    private static function requireDate(array $data, array $keys): DateTimeImmutable
    {
        foreach ($keys as $key) {
            if (array_key_exists($key, $data)) {
                return self::parseDate($key, $data[$key]);
            }
        }

        throw new InvalidResponseException(sprintf(
            'QRCode: missing required date field (one of: %s)',
            implode(', ', $keys),
        ));
    }

    /**
     * @param array<string, mixed> $data
     * @param array<int, string>   $keys
     */
    private static function optionalDate(array $data, array $keys): ?DateTimeImmutable
    {
        foreach ($keys as $key) {
            if (! array_key_exists($key, $data)) {
                continue;
            }
            $value = $data[$key];
            if ($value === null) {
                return null;
            }

            return self::parseDate($key, $value);
        }

        return null;
    }

    private static function parseDate(string $key, mixed $value): DateTimeImmutable
    {
        if (! is_string($value) || $value === '') {
            throw new InvalidResponseException(sprintf('QRCode: `%s` must be a non-empty string', $key));
        }
        try {
            return new DateTimeImmutable($value);
        } catch (PhpException $e) {
            throw new InvalidResponseException(
                sprintf('QRCode: `%s` is not a parseable timestamp (%s)', $key, $value),
                previous: $e,
            );
        }
    }
}
