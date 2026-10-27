<?php

declare(strict_types=1);

namespace QRAuth\DTO;

use QRAuth\Exception\InvalidResponseException;

/**
 * The QR-issuing organization, as returned inside a {@see VerifyResult}.
 *
 * The verify API names the issuer only when the result is
 * {@see TrustState::Verified}: `verified` is then `true` and `name` (plus
 * `verifiedDomain`, when the issuer has a verified domain) is set. For every
 * other result `verified` is `false` and `name` and `verifiedDomain` are
 * `null`.
 */
final class Organization
{
    public function __construct(
        public readonly bool $verified,
        public readonly ?string $name = null,
        public readonly ?string $verifiedDomain = null,
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
            throw new InvalidResponseException('Organization: missing or non-boolean `verified`');
        }

        if (! $verified) {
            return new self(verified: false);
        }

        $name = $data['name'] ?? null;
        if (! is_string($name) || $name === '') {
            throw new InvalidResponseException('Organization: missing or empty `name` on a verified organization');
        }

        $verifiedDomain = $data['verified_domain'] ?? null;
        if ($verifiedDomain !== null && (! is_string($verifiedDomain) || $verifiedDomain === '')) {
            throw new InvalidResponseException('Organization: `verified_domain` must be a non-empty string when present');
        }

        return new self(verified: true, name: $name, verifiedDomain: $verifiedDomain);
    }
}
