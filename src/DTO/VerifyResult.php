<?php

declare(strict_types=1);

namespace QRAuth\DTO;

use DateTimeImmutable;
use Exception as PhpException;
use QRAuth\Exception\InvalidResponseException;

/**
 * Result of {@see \QRAuth\QRAuth::verify()}.
 *
 * `trustState` is the outcome: {@see TrustState::Verified},
 * {@see TrustState::SignedUnverifiedIssuer} or {@see TrustState::Untrusted}.
 *
 * `verified` is `true` only when `trustState === TrustState::Verified`, which
 * requires an issuer verified by QRAuth. An authentic code from an issuer
 * QRAuth has not verified gives `verified === false` with
 * `trustState === TrustState::SignedUnverifiedIssuer`; check
 * `trustState !== TrustState::Untrusted` to accept both.
 *
 * `organization` names the issuer only for `Verified` results (see
 * {@see Organization}). `destinationUrl` is `null` on failure responses
 * (revoked, expired, scan limit, suspended issuer, flagged destination).
 *
 * `reason` is set on many non-`Verified` results (e.g. "This QR code has
 * been revoked by its issuer.").
 *
 * `warnings` is an advisory list with codes like `ALG_DEPRECATED`,
 * `TOKEN_EXPIRING_SOON`, `GEO_MISMATCH_SOFT`. The SDK exposes them as
 * raw associative arrays so callers can branch on whatever set the
 * upstream returns without a parser update.
 */
final class VerifyResult
{
    /**
     * @param array<int, array<string, mixed>> $warnings
     */
    public function __construct(
        public readonly bool $verified,
        public readonly TrustState $trustState,
        public readonly ?string $reason,
        public readonly Organization $organization,
        public readonly ?string $destinationUrl,
        public readonly LocationMatch $locationMatch,
        public readonly SecurityInfo $security,
        public readonly array $warnings,
        public readonly DateTimeImmutable $scannedAt,
    ) {
    }

    /**
     * @param  array<string, mixed> $data
     * @throws InvalidResponseException
     */
    public static function fromArray(array $data): self
    {
        $verified = $data['verified'] ?? null;
        if (! is_bool($verified)) {
            throw new InvalidResponseException('VerifyResult: missing or non-boolean `verified`');
        }

        $trustStateRaw = $data['trust_state'] ?? null;
        $trustState = is_string($trustStateRaw) ? TrustState::tryFrom($trustStateRaw) : null;
        if ($trustState === null) {
            throw new InvalidResponseException('VerifyResult: missing or unknown `trust_state`');
        }

        $reason = $data['reason'] ?? null;
        if ($reason !== null && ! is_string($reason)) {
            throw new InvalidResponseException('VerifyResult: `reason` must be a string when present');
        }

        $organization = $data['organization'] ?? null;
        if (! is_array($organization)) {
            throw new InvalidResponseException('VerifyResult: missing `organization` object');
        }

        $destinationUrl = $data['destination_url'] ?? null;
        if ($destinationUrl !== null && (! is_string($destinationUrl) || $destinationUrl === '')) {
            throw new InvalidResponseException('VerifyResult: `destination_url` must be a non-empty string when present');
        }

        $locationMatch = $data['location_match'] ?? null;
        if (! is_array($locationMatch)) {
            throw new InvalidResponseException('VerifyResult: missing `location_match` object');
        }

        $security = $data['security'] ?? null;
        if (! is_array($security)) {
            throw new InvalidResponseException('VerifyResult: missing `security` object');
        }

        $scannedAtRaw = $data['scannedAt'] ?? null;
        if (! is_string($scannedAtRaw) || $scannedAtRaw === '') {
            throw new InvalidResponseException('VerifyResult: missing or empty `scannedAt`');
        }
        try {
            $scannedAt = new DateTimeImmutable($scannedAtRaw);
        } catch (PhpException $e) {
            throw new InvalidResponseException(
                sprintf('VerifyResult: `scannedAt` is not a parseable timestamp (%s)', $scannedAtRaw),
                previous: $e,
            );
        }

        $warnings = [];
        $rawWarnings = $data['warnings'] ?? null;
        if (is_array($rawWarnings) && array_is_list($rawWarnings)) {
            foreach ($rawWarnings as $w) {
                if (is_array($w)) {
                    /** @var array<string, mixed> $w */
                    $warnings[] = $w;
                }
            }
        }

        return new self(
            verified: $verified,
            trustState: $trustState,
            reason: $reason,
            organization: Organization::fromArray($organization),
            destinationUrl: $destinationUrl,
            locationMatch: LocationMatch::fromArray($locationMatch),
            security: SecurityInfo::fromArray($security),
            warnings: $warnings,
            scannedAt: $scannedAt,
        );
    }
}
