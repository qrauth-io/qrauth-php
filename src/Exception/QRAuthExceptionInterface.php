<?php

declare(strict_types=1);

namespace QRAuth\Exception;

use Throwable;

/**
 * Marker interface implemented by every exception this SDK throws.
 *
 * Catch this to handle any QRAuth error generically:
 *
 * ```
 * try {
 *     $client->verify($token);
 * } catch (QRAuthExceptionInterface $e) {
 *     // any failure originating in the SDK
 * }
 * ```
 */
interface QRAuthExceptionInterface extends Throwable
{
}
