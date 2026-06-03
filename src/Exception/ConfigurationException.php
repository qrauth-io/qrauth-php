<?php

declare(strict_types=1);

namespace QRAuth\Exception;

/**
 * Thrown when the SDK is constructed with invalid configuration —
 * for example an empty tenant ID, an empty API key, or a base URL
 * that is not a syntactically valid HTTP(S) URL.
 *
 * Configuration errors are programmer errors and should be caught
 * during boot, never in a request hot path.
 */
final class ConfigurationException extends QRAuthException
{
}
