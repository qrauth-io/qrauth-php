<?php

declare(strict_types=1);

namespace QRAuth\DTO;

use QRAuth\Exception\InvalidResponseException;

/**
 * Cryptographic + fraud-signal verdict, returned inside a {@see VerifyResult}.
 *
 * `signatureValid` is the AND of both legs (ECDSA-P256 and the
 * SLH-DSA-SHA2-128s post-quantum leg). `trustScore` is QRAuth's
 * composite fraud score in `[0.0, 1.0]`. The remaining fields are
 * advisory metadata about the algorithm version and post-quantum
 * coverage and may be absent on legacy QR codes.
 */
final class SecurityInfo
{
    public function __construct(
        public readonly bool $signatureValid,
        public readonly bool $proxyDetected,
        public readonly float $trustScore,
        public readonly bool $transparencyLogVerified,
        public readonly ?string $algVersion,
        public readonly ?string $algVersionStatus,
        public readonly ?bool $pqcProtected,
        public readonly ?bool $merkleProofValid,
        public readonly ?string $merkleBatchId,
    ) {
    }

    /**
     * @param  array<string, mixed> $data
     * @throws InvalidResponseException
     */
    public static function fromArray(array $data): self
    {
        $signatureValid = $data['signatureValid'] ?? null;
        if (! is_bool($signatureValid)) {
            throw new InvalidResponseException('SecurityInfo: missing or non-boolean `signatureValid`');
        }

        $proxyDetected = $data['proxyDetected'] ?? null;
        if (! is_bool($proxyDetected)) {
            throw new InvalidResponseException('SecurityInfo: missing or non-boolean `proxyDetected`');
        }

        $trustScore = $data['trustScore'] ?? null;
        if (! is_numeric($trustScore)) {
            throw new InvalidResponseException('SecurityInfo: missing or non-numeric `trustScore`');
        }

        $transparencyLogVerified = $data['transparencyLogVerified'] ?? null;
        if (! is_bool($transparencyLogVerified)) {
            throw new InvalidResponseException('SecurityInfo: missing or non-boolean `transparencyLogVerified`');
        }

        return new self(
            signatureValid: $signatureValid,
            proxyDetected: $proxyDetected,
            trustScore: (float) $trustScore,
            transparencyLogVerified: $transparencyLogVerified,
            algVersion: self::optionalString($data, 'algVersion'),
            algVersionStatus: self::optionalString($data, 'algVersionStatus'),
            pqcProtected: self::optionalBool($data, 'pqcProtected'),
            merkleProofValid: self::optionalBool($data, 'merkleProofValid'),
            merkleBatchId: self::optionalString($data, 'merkleBatchId'),
        );
    }

    /**
     * @param array<string, mixed> $data
     */
    private static function optionalString(array $data, string $key): ?string
    {
        if (! array_key_exists($key, $data) || $data[$key] === null) {
            return null;
        }
        if (! is_string($data[$key])) {
            throw new InvalidResponseException(sprintf('SecurityInfo: `%s` must be a string or null', $key));
        }

        return $data[$key];
    }

    /**
     * @param array<string, mixed> $data
     */
    private static function optionalBool(array $data, string $key): ?bool
    {
        if (! array_key_exists($key, $data) || $data[$key] === null) {
            return null;
        }
        if (! is_bool($data[$key])) {
            throw new InvalidResponseException(sprintf('SecurityInfo: `%s` must be a boolean or null', $key));
        }

        return $data[$key];
    }
}
