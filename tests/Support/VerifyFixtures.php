<?php

declare(strict_types=1);

namespace QRAuth\Tests\Support;

/**
 * Loads the captured verify responses in tests/Fixtures (see the README there).
 */
final class VerifyFixtures
{
    /**
     * @return array<string, mixed>
     */
    public static function load(string $name): array
    {
        $json = file_get_contents(__DIR__ . '/../Fixtures/' . $name . '.json');
        if ($json === false) {
            throw new \RuntimeException("Fixture not found: {$name}");
        }

        /** @var array<string, mixed> */
        return json_decode($json, true, 512, JSON_THROW_ON_ERROR);
    }
}
