<?php

declare(strict_types=1);

namespace QRAuth\DTO;

use QRAuth\Exception\InvalidResponseException;

/**
 * Geospatial constraint attached to a QR code.
 *
 * `radiusM` is the tolerance in metres within which a scanner's location
 * must fall for `verify()` to report `location_match.matched = true`.
 * The upstream field is `radiusM`; `fromArray()` also accepts the legacy
 * `radius` key for forward compatibility.
 *
 * @phpstan-type LocationArray array{lat: float, lng: float, radiusM: int}
 */
final class LocationData
{
    public function __construct(
        public readonly float $lat,
        public readonly float $lng,
        public readonly int $radiusM,
    ) {
    }

    /**
     * @param  array<string, mixed> $data
     * @throws InvalidResponseException If the array is missing required keys or has wrong types.
     */
    public static function fromArray(array $data): self
    {
        $lat = $data['lat'] ?? null;
        if (! is_numeric($lat)) {
            throw new InvalidResponseException('LocationData: missing or non-numeric `lat`');
        }

        $lng = $data['lng'] ?? null;
        if (! is_numeric($lng)) {
            throw new InvalidResponseException('LocationData: missing or non-numeric `lng`');
        }

        // Accept the upstream `radiusM` first; fall back to the legacy `radius`.
        $radius = $data['radiusM'] ?? $data['radius'] ?? null;
        if (! is_numeric($radius)) {
            throw new InvalidResponseException('LocationData: missing or non-numeric `radiusM`');
        }

        return new self(
            lat: (float) $lat,
            lng: (float) $lng,
            radiusM: (int) $radius,
        );
    }

    /**
     * @return LocationArray
     */
    public function toArray(): array
    {
        return [
            'lat' => $this->lat,
            'lng' => $this->lng,
            'radiusM' => $this->radiusM,
        ];
    }
}
