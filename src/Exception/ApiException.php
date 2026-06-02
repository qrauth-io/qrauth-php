<?php

declare(strict_types=1);

namespace QRAuth\Exception;

use Throwable;

/**
 * Thrown when QRAuth returns a non-2xx HTTP response.
 *
 * Carries the response status code and decoded JSON body (when one
 * was returned), so callers can branch on specific API errors.
 *
 * @phpstan-type ApiErrorBody array{error?: string, message?: string, code?: string|int, ...}
 */
final class ApiException extends QRAuthException
{
    /**
     * @param int                       $statusCode    HTTP status returned by QRAuth.
     * @param array<string, mixed>|null $body          Decoded JSON body, or null if the response wasn't JSON.
     * @param string                    $message       Human-readable message, used for the exception.
     * @param Throwable|null            $previous      Underlying exception, if any.
     */
    public function __construct(
        public readonly int $statusCode,
        public readonly ?array $body,
        string $message = '',
        ?Throwable $previous = null,
    ) {
        parent::__construct(
            $message !== '' ? $message : sprintf('QRAuth API returned HTTP %d', $statusCode),
            $statusCode,
            $previous,
        );
    }

    /**
     * Convenience accessor for the `error` field most QRAuth error
     * payloads surface (e.g. `{"error": "invalid_signature"}`).
     */
    public function errorCode(): ?string
    {
        $value = $this->body['error'] ?? null;

        return is_string($value) ? $value : null;
    }
}
