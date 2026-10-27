<?php

declare(strict_types=1);

namespace QRAuth\Tests;

use PHPUnit\Framework\Attributes\DataProvider;
use PHPUnit\Framework\TestCase;
use QRAuth\DTO\TrustState;
use QRAuth\DTO\VerifyResult;
use QRAuth\Exception\InvalidResponseException;
use QRAuth\QRAuth;
use QRAuth\Tests\Support\MockHttpClient;
use QRAuth\Tests\Support\VerifyFixtures;

/**
 * verify() against real API responses in every trust state
 * (tests/Fixtures, captured from a local QRAuth API).
 */
final class VerifyResultTest extends TestCase
{
    private MockHttpClient $http;

    private QRAuth $client;

    protected function setUp(): void
    {
        $this->http = new MockHttpClient();
        $this->client = new QRAuth(
            tenantId: 'org_1',
            apiKey: 'qrauth_test_key',
            baseUrl: 'https://qrauth.test',
            httpClient: $this->http,
        );
    }

    /**
     * @return array<string, array{string, TrustState, bool}>
     */
    public static function fixtures(): array
    {
        return [
            'verified' => ['verify-verified', TrustState::Verified, true],
            'signed, issuer not verified' => ['verify-signed-unverified-issuer', TrustState::SignedUnverifiedIssuer, true],
            'untrusted: lookalike destination' => ['verify-untrusted-lookalike', TrustState::Untrusted, true],
            'untrusted: revoked' => ['verify-revoked', TrustState::Untrusted, false],
            'untrusted: flagged destination' => ['verify-flagged', TrustState::Untrusted, false],
        ];
    }

    #[DataProvider('fixtures')]
    public function testParsesEveryTrustState(string $fixture, TrustState $expected, bool $hasDestination): void
    {
        $this->http->queueResponse(200, VerifyFixtures::load($fixture));

        $result = $this->client->verify('tok');

        $this->assertSame($expected, $result->trustState);
        $this->assertSame($expected === TrustState::Verified, $result->verified);
        $this->assertSame($hasDestination, $result->destinationUrl !== null);
    }

    public function testVerifiedResultNamesTheIssuer(): void
    {
        $this->http->queueResponse(200, VerifyFixtures::load('verify-verified'));

        $result = $this->client->verify('tok');

        $this->assertTrue($result->organization->verified);
        $this->assertSame('Acme Wire Ltd', $result->organization->name);
        $this->assertSame('acme-wire.example', $result->organization->verifiedDomain);
        $this->assertSame('https://acme-wire.example/pay', $result->destinationUrl);
    }

    public function testOtherResultsDoNotNameTheIssuer(): void
    {
        $this->http->queueResponse(200, VerifyFixtures::load('verify-signed-unverified-issuer'));

        $result = $this->client->verify('tok');

        $this->assertFalse($result->organization->verified);
        $this->assertNull($result->organization->name);
        $this->assertNull($result->organization->verifiedDomain);
    }

    public function testFailureResponsesCarryReasonAndNoDestination(): void
    {
        $this->http->queueResponse(200, VerifyFixtures::load('verify-revoked'));

        $result = $this->client->verify('tok');

        $this->assertSame('This QR code has been revoked by its issuer.', $result->reason);
        $this->assertNull($result->destinationUrl);
        $this->assertFalse($result->security->signatureValid);
        $this->assertNull($result->security->algVersion);
    }

    public function testFlaggedDestinationReason(): void
    {
        $this->http->queueResponse(200, VerifyFixtures::load('verify-flagged'));

        $result = $this->client->verify('tok');

        $this->assertSame('This code points to a site flagged as dangerous.', $result->reason);
    }

    public function testUnknownTrustStateIsRejected(): void
    {
        $row = VerifyFixtures::load('verify-verified');
        $row['trust_state'] = 'SOMETHING_NEW';
        $this->http->queueResponse(200, $row);

        $this->expectException(InvalidResponseException::class);
        $this->expectExceptionMessage('unknown `trust_state`');

        $this->client->verify('tok');
    }

    public function testVerifiedOrganizationWithoutNameIsRejected(): void
    {
        $row = VerifyFixtures::load('verify-verified');
        $row['organization'] = ['verified' => true];

        $this->expectException(InvalidResponseException::class);
        $this->expectExceptionMessage('`name` on a verified organization');

        VerifyResult::fromArray($row);
    }

    public function testEmptyDestinationIsRejected(): void
    {
        $row = VerifyFixtures::load('verify-verified');
        $row['destination_url'] = '';

        $this->expectException(InvalidResponseException::class);

        VerifyResult::fromArray($row);
    }
}
