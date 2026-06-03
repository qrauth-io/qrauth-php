<?php

declare(strict_types=1);

namespace QRAuth\Exception;

/**
 * Thrown when an HTTP request to QRAuth could not be completed at the
 * transport layer — DNS failures, TLS handshake failures, connection
 * refused, read timeouts, etc.
 *
 * Distinct from {@see ApiException}, which represents a request that
 * reached QRAuth and came back with a non-2xx response. Callers
 * commonly retry on transport failures and surface API errors.
 */
final class TransportException extends QRAuthException
{
}
