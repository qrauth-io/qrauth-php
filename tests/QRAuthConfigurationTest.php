<?php

declare(strict_types=1);

namespace QRAuth\Tests;

use PHPUnit\Framework\TestCase;
use QRAuth\Exception\ConfigurationException;
use QRAuth\QRAuth;
use QRAuth\Tests\Support\MockHttpClient;

final class QRAuthConfigurationTest extends TestCase
{
    public function testEmptyTenantIdRejected(): void
    {
        $this->expectException(ConfigurationException::class);
        $this->expectExceptionMessage('`tenantId` must not be empty');

        new QRAuth(tenantId: '   ', apiKey: 'k');
    }

    public function testEmptyApiKeyRejected(): void
    {
        $this->expectException(ConfigurationException::class);
        $this->expectExceptionMessage('`apiKey` must not be empty');

        new QRAuth(tenantId: 't', apiKey: '');
    }

    public function testInvalidBaseUrlRejected(): void
    {
        $this->expectException(ConfigurationException::class);
        $this->expectExceptionMessage('`baseUrl` must be an http(s) URL');

        new QRAuth(tenantId: 't', apiKey: 'k', baseUrl: 'not-a-url');
    }

    public function testFtpBaseUrlRejected(): void
    {
        $this->expectException(ConfigurationException::class);

        new QRAuth(tenantId: 't', apiKey: 'k', baseUrl: 'ftp://example.com');
    }

    public function testHttpBaseUrlRejectedAgainstNonLoopbackHost(): void
    {
        $this->expectException(ConfigurationException::class);
        $this->expectExceptionMessage('http:// against a non-loopback host');

        new QRAuth(tenantId: 't', apiKey: 'k', baseUrl: 'http://api.example.com');
    }

    public function testHttpBaseUrlAllowedAgainstLoopback(): void
    {
        $client = new QRAuth(
            tenantId: 't',
            apiKey: 'k',
            baseUrl: 'http://127.0.0.1:8080',
            httpClient: new MockHttpClient(),
        );
        $this->assertSame('t', $client->tenantId);

        $client = new QRAuth(
            tenantId: 't',
            apiKey: 'k',
            baseUrl: 'http://localhost:8080',
            httpClient: new MockHttpClient(),
        );
        $this->assertSame('t', $client->tenantId);
    }

    public function testHttpBaseUrlAllowedWithExplicitOptIn(): void
    {
        $client = new QRAuth(
            tenantId: 't',
            apiKey: 'k',
            baseUrl: 'http://api.internal',
            allowInsecure: true,
            httpClient: new MockHttpClient(),
        );
        $this->assertSame('t', $client->tenantId);
    }

    public function testBaseUrlWithUserInfoRejected(): void
    {
        $this->expectException(ConfigurationException::class);
        $this->expectExceptionMessage('must not embed credentials');

        new QRAuth(tenantId: 't', apiKey: 'k', baseUrl: 'https://user:pass@qrauth.io');
    }

    public function testApiKeyWithControlCharRejected(): void
    {
        $this->expectException(ConfigurationException::class);
        $this->expectExceptionMessage('`apiKey` must not contain control characters');

        new QRAuth(tenantId: 't', apiKey: "leaked\r\nX-Injected: yes");
    }

    public function testTenantIdWithControlCharRejected(): void
    {
        $this->expectException(ConfigurationException::class);
        $this->expectExceptionMessage('`tenantId` must not contain control characters');

        new QRAuth(tenantId: "t\nfoo", apiKey: 'k');
    }

    public function testClientSecretWithControlCharRejected(): void
    {
        $this->expectException(ConfigurationException::class);
        $this->expectExceptionMessage('`clientSecret` must not contain control characters');

        new QRAuth(
            tenantId: 't',
            apiKey: 'k',
            clientId: 'c',
            clientSecret: "secret\x00null",
        );
    }

    public function testClientIdWithoutSecretRejected(): void
    {
        $this->expectException(ConfigurationException::class);
        $this->expectExceptionMessage('both be provided or both be omitted');

        new QRAuth(tenantId: 't', apiKey: 'k', clientId: 'abc');
    }

    public function testClientSecretWithoutIdRejected(): void
    {
        $this->expectException(ConfigurationException::class);

        new QRAuth(tenantId: 't', apiKey: 'k', clientSecret: 'abc');
    }

    public function testValidConfigurationConstructs(): void
    {
        $client = new QRAuth(tenantId: 't', apiKey: 'k', httpClient: new MockHttpClient());
        $this->assertSame('t', $client->tenantId);
    }

    public function testAuthSessionMethodsRequireClientCredentials(): void
    {
        $http = new MockHttpClient();
        $client = new QRAuth(tenantId: 't', apiKey: 'k', httpClient: $http);

        $this->expectException(ConfigurationException::class);
        $this->expectExceptionMessage('Auth-session methods require');

        $client->createAuthSession([]);
    }
}
