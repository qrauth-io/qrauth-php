<?php

declare(strict_types=1);

namespace QRAuth\Exception;

use RuntimeException;

/**
 * Base class for all SDK exceptions.
 *
 * Concrete subclasses describe what went wrong:
 *  - {@see ApiException}            non-2xx HTTP response from QRAuth
 *  - {@see TransportException}      transport-level failure (timeout, DNS, TLS)
 *  - {@see InvalidResponseException} malformed JSON or unexpected payload shape
 *  - {@see ConfigurationException}  invalid SDK configuration
 */
abstract class QRAuthException extends RuntimeException implements QRAuthExceptionInterface
{
}
