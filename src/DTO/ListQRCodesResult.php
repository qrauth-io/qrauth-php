<?php

declare(strict_types=1);

namespace QRAuth\DTO;

use QRAuth\Exception\InvalidResponseException;

/**
 * Paginated result of {@see \QRAuth\QRAuth::list()}.
 *
 * The upstream envelope is flat — `{data, total, page, pageSize, totalPages}` —
 * not the `{data, pagination: {...}}` shape some doc pages suggest.
 */
final class ListQRCodesResult
{
    /**
     * @param array<int, QRCode> $items
     */
    public function __construct(
        public readonly array $items,
        public readonly int $total,
        public readonly int $page,
        public readonly int $pageSize,
        public readonly int $totalPages,
    ) {
    }

    /**
     * @param  array<string, mixed> $data
     * @throws InvalidResponseException
     */
    public static function fromArray(array $data): self
    {
        $rawItems = $data['data'] ?? null;
        if (! is_array($rawItems) || ! array_is_list($rawItems)) {
            throw new InvalidResponseException('list(): expected `data` to be a list of QR codes.');
        }

        $items = [];
        foreach ($rawItems as $row) {
            if (! is_array($row)) {
                throw new InvalidResponseException('list(): non-object entry in `data`.');
            }
            $items[] = QRCode::fromArray($row);
        }

        return new self(
            items: $items,
            total: self::requireInt($data, 'total'),
            page: self::requireInt($data, 'page'),
            pageSize: self::requireInt($data, 'pageSize'),
            totalPages: self::requireInt($data, 'totalPages'),
        );
    }

    /**
     * @param array<string, mixed> $data
     */
    private static function requireInt(array $data, string $key): int
    {
        $value = $data[$key] ?? null;
        if (! is_int($value) && ! (is_string($value) && ctype_digit($value))) {
            throw new InvalidResponseException(sprintf('list(): missing or non-integer `%s`', $key));
        }

        return (int) $value;
    }
}
