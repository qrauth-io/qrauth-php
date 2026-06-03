<?php

declare(strict_types=1);

namespace QRAuth\DTO;

use QRAuth\Exception\InvalidResponseException;

/**
 * Identity returned by QRAuth after a successful auth-session approval.
 *
 * `id` is always present (QRAuth's stable identifier — the value you
 * should persist as the user's `qrauth_user_id`). `email` and `name`
 * are present only when the corresponding scopes were granted on the
 * session.
 */
final class AuthenticatedUser
{
    public function __construct(
        public readonly string $id,
        public readonly ?string $email,
        public readonly ?string $name,
    ) {
    }

    /**
     * @param  array<string, mixed> $data
     * @throws InvalidResponseException
     */
    public static function fromArray(array $data): self
    {
        $id = $data['id'] ?? null;
        if (! is_string($id) || $id === '') {
            throw new InvalidResponseException('AuthenticatedUser: missing or empty `id`');
        }

        $email = $data['email'] ?? null;
        if ($email !== null && (! is_string($email) || $email === '')) {
            throw new InvalidResponseException('AuthenticatedUser: `email` must be a non-empty string when present');
        }

        $name = $data['name'] ?? null;
        if ($name !== null && (! is_string($name) || $name === '')) {
            throw new InvalidResponseException('AuthenticatedUser: `name` must be a non-empty string when present');
        }

        return new self(id: $id, email: $email, name: $name);
    }
}
