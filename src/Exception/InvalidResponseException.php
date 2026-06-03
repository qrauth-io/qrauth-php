<?php

declare(strict_types=1);

namespace QRAuth\Exception;

/**
 * Thrown when QRAuth returns a 2xx response whose body cannot be
 * trusted — non-JSON content, JSON that does not decode into an
 * object, or a payload that is missing required fields.
 *
 * Surfacing these as exceptions (rather than returning nullable
 * fields or empty DTOs) ensures a malformed response can never be
 * confused with a valid one — for example, a flaky upstream that
 * returns truncated JSON must never look like a successful auth
 * approval.
 */
final class InvalidResponseException extends QRAuthException
{
}
