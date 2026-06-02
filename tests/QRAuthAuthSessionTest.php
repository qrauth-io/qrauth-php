<?php

declare(strict_types=1);

namespace QRAuth\Tests;

use PHPUnit\Framework\TestCase;
use QRAuth\DTO\AuthSession;
use QRAuth\DTO\AuthSessionResult;
use QRAuth\Exception\ApiException;
use QRAuth\QRAuth;
use QRAuth\Tests\Support\MockHttpClient;

final class QRAuthAuthSessionTest extends TestCase
{
    private MockHttpClient $http;

    private QRAuth $client;

    protected function setUp(): void
    {
        $this->http = new MockHttpClient();
        $this->client = new QRAuth(
            tenantId: 'tenant-1',
            apiKey: 'api-key',
            clientId: 'client-1',
            clientSecret: 's3cret',
            httpClient: $this->http,
        );
    }

    public function testCreateAuthSessionUsesBasicAuthAndForwardsBody(): void
    {
        $this->http->queueResponse(201, [
            'sessionId' => 'as_abc',
            'token' => 'tok',
            'qrUrl' => 'https://qrauth.io/a/tok',
            'qrDataUrl' => 'https://qrauth.io/a/tok',
            'status' => 'PENDING',
            'scopes' => ['identity', 'email'],
            'expiresAt' => '2026-05-07T12:10:00Z',
        ]);

        $session = $this->client->createAuthSession([
            'scopes' => ['identity', 'email'],
            'codeChallenge' => str_repeat('a', 43),
            'codeChallengeMethod' => 'S256',
        ]);

        $this->assertInstanceOf(AuthSession::class, $session);
        $this->assertSame('as_abc', $session->sessionId);
        $this->assertSame('https://qrauth.io/a/tok', $session->qrUrl);
        $this->assertSame('tok', $session->token);
        $this->assertSame(['identity', 'email'], $session->scopes);
        $this->assertTrue($session->isPending());

        $request = $this->http->lastRequest();
        $this->assertSame('POST', $request->getMethod());
        $this->assertSame('/api/v1/auth-sessions', $request->getUri()->getPath());

        $expected = 'Basic '.base64_encode('client-1:s3cret');
        $this->assertSame($expected, $request->getHeaderLine('Authorization'));
        $this->assertSame('client-1', $request->getHeaderLine('X-Client-Id'));
        // No X-API-Key on auth-session calls.
        $this->assertFalse($request->hasHeader('X-API-Key'));

        $body = json_decode((string) $request->getBody(), true, 512, JSON_THROW_ON_ERROR);
        $this->assertSame(['identity', 'email'], $body['scopes']);
        $this->assertSame(str_repeat('a', 43), $body['codeChallenge']);
        // No tenantId in the body — upstream schema doesn't accept it.
        $this->assertArrayNotHasKey('tenantId', $body);
    }

    public function testCreateAuthSessionStripsCredentialKeys(): void
    {
        $this->http->queueResponse(201, [
            'sessionId' => 'as_abc',
            'token' => 'tok',
            'qrUrl' => 'https://qrauth.io/a/tok',
            'qrDataUrl' => 'https://qrauth.io/a/tok',
            'status' => 'PENDING',
            'scopes' => ['identity'],
            'expiresAt' => '2026-05-07T12:10:00Z',
        ]);

        $this->client->createAuthSession([
            'clientId' => 'attacker-client',
            'clientSecret' => 'leaked',
            'apiKey' => 'leaked',
            'scopes' => ['identity'],
        ]);

        $body = json_decode((string) $this->http->lastRequest()->getBody(), true, 512, JSON_THROW_ON_ERROR);
        $this->assertArrayNotHasKey('clientId', $body);
        $this->assertArrayNotHasKey('clientSecret', $body);
        $this->assertArrayNotHasKey('apiKey', $body);
        $this->assertSame(['identity'], $body['scopes']);
    }

    public function testToClientArrayReturnsBrowserSafeFields(): void
    {
        $this->http->queueResponse(201, [
            'sessionId' => 'as_abc',
            'token' => 'tok',
            'qrUrl' => 'https://qrauth.io/a/tok',
            'qrDataUrl' => 'https://qrauth.io/a/tok',
            'status' => 'PENDING',
            'scopes' => ['identity'],
            'expiresAt' => '2026-05-07T12:10:00Z',
            'internalUserId' => 'should-not-be-exposed',
            'debugTrace' => ['secret' => 'shhh'],
        ]);

        $session = $this->client->createAuthSession(['scopes' => ['identity']]);
        $public = $session->toClientArray();

        $this->assertSame('as_abc', $public['sessionId']);
        $this->assertSame('PENDING', $public['status']);
        $this->assertSame('https://qrauth.io/a/tok', $public['qrUrl']);
        $this->assertSame(['identity'], $public['scopes']);
        $this->assertArrayNotHasKey('internalUserId', $public);
        $this->assertArrayNotHasKey('debugTrace', $public);
    }

    public function testGetAuthSessionForwardsCodeVerifier(): void
    {
        $this->http->queueResponse(200, [
            'sessionId' => 'as_abc',
            'status' => 'APPROVED',
            'scopes' => ['identity', 'email'],
            'user' => ['id' => 'user_42', 'name' => 'Stefanos', 'email' => 'me@example.com'],
            'signature' => 'sig.base64url',
            'expiresAt' => '2026-05-07T12:10:00Z',
            'scannedAt' => '2026-05-07T12:06:00Z',
            'resolvedAt' => '2026-05-07T12:06:30Z',
        ]);

        $session = $this->client->getAuthSession('as_abc', codeVerifier: 'pkce_verifier');

        $this->assertTrue($session->isApproved());
        $this->assertNotNull($session->user);
        $this->assertSame('user_42', $session->user->id);
        $this->assertSame('sig.base64url', $session->signature);
        $this->assertNotNull($session->scannedAt);
        $this->assertNotNull($session->resolvedAt);

        $uri = $this->http->lastRequest()->getUri();
        $this->assertSame('/api/v1/auth-sessions/as_abc', $uri->getPath());
        parse_str($uri->getQuery(), $query);
        $this->assertSame('pkce_verifier', $query['code_verifier']);
    }

    public function testGetAuthSessionApiErrorMessageRedactsSessionId(): void
    {
        $this->http->queueResponse(404, ['error' => 'session_not_found']);

        try {
            $this->client->getAuthSession('SECRET-SESSION-ID');
            $this->fail('Expected ApiException');
        } catch (ApiException $e) {
            $this->assertStringContainsString('/api/v1/auth-sessions/{sessionId}', $e->getMessage());
            $this->assertStringNotContainsString('SECRET-SESSION-ID', $e->getMessage());
        }
    }

    public function testVerifyAuthResultSendsNoAuthorizationHeader(): void
    {
        $this->http->queueResponse(200, [
            'valid' => true,
            'session' => [
                'id' => 'as_abc',
                'status' => 'APPROVED',
                'appName' => 'LinkToLand',
                'scopes' => ['identity', 'email'],
                'user' => [
                    'id' => 'user_42',
                    'name' => 'Stefanos',
                    'email' => 'me@example.com',
                ],
                'signature' => 'sig.base64url',
                'resolvedAt' => '2026-05-07T12:06:30Z',
            ],
        ]);

        $result = $this->client->verifyAuthResult('as_abc', 'sig.base64url');

        $this->assertInstanceOf(AuthSessionResult::class, $result);
        $this->assertTrue($result->valid);
        $this->assertSame('as_abc', $result->sessionId);
        $this->assertSame('APPROVED', $result->status);
        $this->assertSame('LinkToLand', $result->appName);
        $this->assertNotNull($result->user);
        $this->assertSame('user_42', $result->user->id);
        $this->assertSame('me@example.com', $result->user->email);
        $this->assertSame(['identity', 'email'], $result->scopes);
        $this->assertSame('sig.base64url', $result->signature);

        $request = $this->http->lastRequest();
        $this->assertSame('POST', $request->getMethod());
        $this->assertSame('/api/v1/auth-sessions/verify-result', $request->getUri()->getPath());
        // Trust-bearing call: signature in body authenticates, no creds in headers.
        $this->assertFalse($request->hasHeader('Authorization'));
        $this->assertFalse($request->hasHeader('X-Client-Id'));
        $this->assertFalse($request->hasHeader('X-API-Key'));

        $body = json_decode((string) $request->getBody(), true, 512, JSON_THROW_ON_ERROR);
        $this->assertSame('as_abc', $body['sessionId']);
        $this->assertSame('sig.base64url', $body['signature']);
    }

    public function testVerifyAuthResultHandlesInvalidResponse(): void
    {
        $this->http->queueResponse(200, ['valid' => false]);

        $result = $this->client->verifyAuthResult('as_abc', 'bad-sig');

        $this->assertFalse($result->valid);
        $this->assertNull($result->user);
        $this->assertSame([], $result->scopes);
        $this->assertNull($result->resolvedAt);
        $this->assertSame('', $result->sessionId);
    }
}
