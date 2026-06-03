<?php

declare(strict_types=1);

namespace QRAuth\Tests\Support;

use GuzzleHttp\Psr7\Response;
use Psr\Http\Client\ClientExceptionInterface;
use Psr\Http\Client\ClientInterface;
use Psr\Http\Message\RequestInterface;
use Psr\Http\Message\ResponseInterface;
use RuntimeException;

/**
 * Minimal PSR-18 client used by the test suite.
 *
 * Each call to `sendRequest()` is recorded (so tests can assert URL,
 * headers, and body) and the next queued response is returned in
 * FIFO order. Throws when the queue is empty so tests can't silently
 * pass on unexpected requests.
 */
final class MockHttpClient implements ClientInterface
{
    /** @var list<ResponseInterface|ClientExceptionInterface> */
    private array $queue = [];

    /** @var list<RequestInterface> */
    public array $requests = [];

    /**
     * @param array<string, string> $headers
     */
    public function queueResponse(int $status, mixed $jsonBody, array $headers = []): void
    {
        $body = is_string($jsonBody) ? $jsonBody : (string) json_encode($jsonBody, JSON_THROW_ON_ERROR);
        $this->queue[] = new Response($status, ['Content-Type' => 'application/json'] + $headers, $body);
    }

    public function queueRawResponse(ResponseInterface $response): void
    {
        $this->queue[] = $response;
    }

    public function queueTransportFailure(ClientExceptionInterface $exception): void
    {
        $this->queue[] = $exception;
    }

    public function sendRequest(RequestInterface $request): ResponseInterface
    {
        $this->requests[] = $request;

        if ($this->queue === []) {
            throw new RuntimeException(sprintf(
                'MockHttpClient received an unexpected request: %s %s',
                $request->getMethod(),
                (string) $request->getUri(),
            ));
        }

        $next = array_shift($this->queue);
        if ($next instanceof ClientExceptionInterface) {
            throw $next;
        }

        return $next;
    }

    public function lastRequest(): RequestInterface
    {
        $count = count($this->requests);
        if ($count === 0) {
            throw new RuntimeException('MockHttpClient: no requests have been recorded.');
        }

        return $this->requests[$count - 1];
    }
}
