<?php

declare(strict_types=1);

namespace QRAuth\Tests;

use DateTimeImmutable;
use GuzzleHttp\Psr7\Response;
use PHPUnit\Framework\TestCase;
use QRAuth\DTO\LocationData;
use QRAuth\DTO\QRCode;
use QRAuth\DTO\TrustState;
use QRAuth\Exception\ApiException;
use QRAuth\Exception\InvalidResponseException;
use QRAuth\QRAuth;
use QRAuth\Tests\Support\MockHttpClient;
use QRAuth\Tests\Support\VerifyFixtures;

final class QRAuthQRPrimitivesTest extends TestCase
{
    private MockHttpClient $http;

    private QRAuth $client;

    protected function setUp(): void
    {
        $this->http = new MockHttpClient();
        $this->client = new QRAuth(
            tenantId: 'tenant-1',
            apiKey: 'api-key-secret',
            httpClient: $this->http,
        );
    }

    public function testCreateBuildsExpectedRequestAndParsesResponse(): void
    {
        // Real upstream shape (snake_case create response).
        $this->http->queueResponse(201, [
            'token' => 'tok_abc',
            'verification_url' => 'https://qrauth.io/v/tok_abc',
            'qr_image_url' => 'https://api.qrserver.com/v1/create-qr-code/?data=...',
            'signature' => 'MEUCIQD...',
            'organization_id' => 'org_42',
            'label' => 'Trade Show 2026',
            'created_at' => '2026-05-07T12:00:00Z',
            'expires_at' => '2026-06-07T12:00:00Z',
            'transparency_log_index' => 17,
            'alg_version' => 'hybrid-ecdsa-slhdsa-v1',
            'merkle_batch_id' => 'mb_1',
        ]);

        $qr = $this->client->create(
            destinationUrl: 'https://example.com/landing',
            label: 'Trade Show 2026',
            location: new LocationData(lat: 40.7128, lng: -74.0060, radiusM: 100),
            expiresAt: new DateTimeImmutable('2026-06-07T12:00:00Z'),
        );

        $this->assertInstanceOf(QRCode::class, $qr);
        $this->assertSame('tok_abc', $qr->token);
        $this->assertSame('org_42', $qr->organizationId);
        $this->assertSame('https://qrauth.io/v/tok_abc', $qr->verificationUrl);
        $this->assertSame('Trade Show 2026', $qr->label);

        $request = $this->http->lastRequest();
        $this->assertSame('POST', $request->getMethod());
        $this->assertSame('/api/v1/qrcodes', $request->getUri()->getPath());
        // QR primitives use X-API-Key (not Authorization: Bearer).
        $this->assertSame('api-key-secret', $request->getHeaderLine('X-API-Key'));
        $this->assertFalse($request->hasHeader('Authorization'));
        $this->assertSame('application/json', $request->getHeaderLine('Content-Type'));

        $body = json_decode((string) $request->getBody(), true, 512, JSON_THROW_ON_ERROR);
        // Body shape per upstream zod schema. No `tenantId` — org is derived from the API key.
        $this->assertArrayNotHasKey('tenantId', $body);
        $this->assertSame('https://example.com/landing', $body['destinationUrl']);
        $this->assertSame('Trade Show 2026', $body['label']);
        $this->assertSame(['lat' => 40.7128, 'lng' => -74.0060, 'radiusM' => 100], $body['location']);
        // expiresAt is sent as ISO 8601 normalized to UTC with the `Z`
        // suffix — the qrauth.io backend's default Zod `datetime()`
        // schema rejects numeric offsets like `+00:00`.
        $this->assertSame('2026-06-07T12:00:00.000Z', $body['expiresAt']);
    }

    public function testCreateNormalizesNonUtcExpiryToZuluFormat(): void
    {
        $this->http->queueResponse(201, [
            'token' => 'tok_abc',
            'verification_url' => 'https://qrauth.io/v/tok_abc',
            'qr_image_url' => 'https://example.com/qr.png',
            'signature' => 'sig',
            'organization_id' => 'org_42',
            'label' => null,
            'created_at' => '2026-05-07T12:00:00Z',
            'expires_at' => '2026-06-07T12:00:00Z',
            'transparency_log_index' => 1,
            'alg_version' => 'hybrid-ecdsa-slhdsa-v1',
            'merkle_batch_id' => 'mb_1',
        ]);

        $this->client->create(
            destinationUrl: 'https://example.com/landing',
            expiresAt: new DateTimeImmutable('2026-06-07T15:00:00+03:00'),
        );

        $body = json_decode((string) $this->http->lastRequest()->getBody(), true, 512, JSON_THROW_ON_ERROR);
        $this->assertSame('2026-06-07T12:00:00.000Z', $body['expiresAt']);
    }

    public function testVerifyIsPublicAndForwardsClientCoords(): void
    {
        $this->http->queueResponse(200, $this->verifyResponseRow());

        $result = $this->client->verify('weird/token with spaces', clientLat: 40.0, clientLng: -74.0);

        $this->assertTrue($result->verified);
        $this->assertSame(TrustState::Verified, $result->trustState);
        $this->assertSame('Acme Wire Ltd', $result->organization->name);
        $this->assertTrue($result->security->signatureValid);

        $request = $this->http->lastRequest();
        // Verify is public — no auth header.
        $this->assertFalse($request->hasHeader('X-API-Key'));
        $this->assertFalse($request->hasHeader('Authorization'));

        $uri = $request->getUri();
        $this->assertSame('/api/v1/verify/weird%2Ftoken%20with%20spaces', $uri->getPath());
        parse_str($uri->getQuery(), $query);
        // Real upstream param names are clientLat/clientLng (not scannerLat/scannerLng).
        $this->assertSame('40', $query['clientLat']);
        $this->assertSame('-74', $query['clientLng']);
    }

    public function testRevokeIssuesDeleteRequestWithApiKey(): void
    {
        $this->http->queueRawResponse(new Response(204));

        $this->client->revoke('tok_abc');

        $request = $this->http->lastRequest();
        $this->assertSame('DELETE', $request->getMethod());
        $this->assertSame('/api/v1/qrcodes/tok_abc', $request->getUri()->getPath());
        $this->assertSame('api-key-secret', $request->getHeaderLine('X-API-Key'));
    }

    public function testListUsesPagePageSizeAndParsesEnvelope(): void
    {
        $this->http->queueResponse(200, [
            'data' => [$this->prismaQrRow('tok_a'), $this->prismaQrRow('tok_b')],
            'total' => 142,
            'page' => 1,
            'pageSize' => 50,
            'totalPages' => 3,
        ]);

        $result = $this->client->list(page: 1, pageSize: 50, status: 'ACTIVE');

        $this->assertCount(2, $result->items);
        $this->assertContainsOnlyInstancesOf(QRCode::class, $result->items);
        $this->assertSame(142, $result->total);
        $this->assertSame(1, $result->page);
        $this->assertSame(50, $result->pageSize);
        $this->assertSame(3, $result->totalPages);

        // List items are camelCase prisma rows — DTO should still parse them.
        $this->assertSame('tok_a', $result->items[0]->token);
        $this->assertSame('ACTIVE', $result->items[0]->status);

        parse_str($this->http->lastRequest()->getUri()->getQuery(), $query);
        $this->assertSame('1', $query['page']);
        $this->assertSame('50', $query['pageSize']);
        $this->assertSame('ACTIVE', $query['status']);
    }

    public function testApiErrorBubblesAsApiException(): void
    {
        $this->http->queueResponse(401, ['error' => 'invalid_api_key']);

        try {
            $this->client->revoke('tok');
            $this->fail('Expected ApiException');
        } catch (ApiException $e) {
            $this->assertSame(401, $e->statusCode);
            $this->assertSame('invalid_api_key', $e->errorCode());
        }
    }

    public function testRevokeApiErrorMessageRedactsToken(): void
    {
        $this->http->queueResponse(403, ['error' => 'forbidden']);

        try {
            $this->client->revoke('SECRET-TOKEN-DO-NOT-LOG');
            $this->fail('Expected ApiException');
        } catch (ApiException $e) {
            $this->assertStringContainsString('/api/v1/qrcodes/{token}', $e->getMessage());
            $this->assertStringNotContainsString('SECRET-TOKEN-DO-NOT-LOG', $e->getMessage());
        }
    }

    public function testMalformedJsonRaisesInvalidResponse(): void
    {
        $this->http->queueResponse(200, '{not-json');

        $this->expectException(InvalidResponseException::class);

        $this->client->verify('tok');
    }

    public function testMissingFieldRaisesInvalidResponse(): void
    {
        $row = $this->verifyResponseRow();
        unset($row['organization']);
        $this->http->queueResponse(200, $row);

        $this->expectException(InvalidResponseException::class);
        $this->expectExceptionMessage('missing `organization`');

        $this->client->verify('tok');
    }

    /**
     * A real VERIFIED response (tests/Fixtures/verify-verified.json).
     *
     * @return array<string, mixed>
     */
    private function verifyResponseRow(): array
    {
        return VerifyFixtures::load('verify-verified');
    }

    /**
     * Prisma-shaped (camelCase) QR row as returned by the list endpoint.
     *
     * @return array<string, mixed>
     */
    private function prismaQrRow(string $token): array
    {
        return [
            'id' => 'qr_'.$token,
            'token' => $token,
            'organizationId' => 'org_42',
            'destinationUrl' => 'https://example.com',
            'label' => 'Sample',
            'contentType' => 'url',
            'content' => null,
            'signature' => 'MEUCIQD...',
            'status' => 'ACTIVE',
            'createdAt' => '2026-05-07T12:00:00Z',
            'expiresAt' => null,
            'radiusM' => 50,
        ];
    }
}
