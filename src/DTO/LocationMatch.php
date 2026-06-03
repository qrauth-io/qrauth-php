<?php

declare(strict_types=1);

namespace QRAuth\DTO;

use QRAuth\Exception\InvalidResponseException;

/**
 * Result of the proximity check on a verify call.
 *
 * Present in every JSON verify response, but `matched` is meaningful
 * only when the QR was registered with a location and the caller
 * forwarded `clientLat` / `clientLng` query parameters. When either
 * is missing the upstream returns `matched: false` with `distanceM`
 * and `registeredAddress` null — this DTO surfaces that state directly.
 */
final class LocationMatch
{
    public function __construct(
        public readonly bool $matched,
        public readonly ?float $distanceM,
        public readonly ?string $registeredAddress,
    ) {
    }

    /**
     * @param  array<string, mixed> $data
     * @throws InvalidResponseException
     */
    public static function fromArray(array $data): self
    {
        $matched = $data['matched'] ?? null;
        if (! is_bool($matched)) {
            throw new InvalidResponseException('LocationMatch: missing or non-boolean `matched`');
        }

        $distanceM = $data['distanceM'] ?? null;
        if ($distanceM !== null && ! is_numeric($distanceM)) {
            throw new InvalidResponseException('LocationMatch: `distanceM` must be numeric or null');
        }

        $registeredAddress = $data['registeredAddress'] ?? null;
        if ($registeredAddress !== null && ! is_string($registeredAddress)) {
            throw new InvalidResponseException('LocationMatch: `registeredAddress` must be a string or null');
        }

        return new self(
            matched: $matched,
            distanceM: $distanceM === null ? null : (float) $distanceM,
            registeredAddress: $registeredAddress,
        );
    }
}
