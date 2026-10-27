<?php

declare(strict_types=1);

namespace QRAuth\DTO;

/**
 * Trust state of a verified QR code, as returned by the verify API
 * (`trust_state`).
 *
 *  - `Verified`: every check passed and QRAuth has verified the issuer
 *    (verified domain or approved identity review).
 *  - `SignedUnverifiedIssuer`: every check passed, but QRAuth has not
 *    verified the issuer. The code is authentic; who issued it is not
 *    confirmed.
 *  - `Untrusted`: anything else (invalid signature, revoked, expired,
 *    geo-blocked, low trust score, lookalike or flagged destination,
 *    suspended issuer).
 */
enum TrustState: string
{
    case Verified = 'VERIFIED';
    case SignedUnverifiedIssuer = 'SIGNED_UNVERIFIED_ISSUER';
    case Untrusted = 'UNTRUSTED';
}
