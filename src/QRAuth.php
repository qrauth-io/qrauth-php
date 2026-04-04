<?php

namespace QRAuth;

use GuzzleHttp\Client;
use GuzzleHttp\Exception\GuzzleException;

/**
 * QRAuth SDK Client
 *
 * Main client class for interacting with the QRAuth API
 */
class QRAuth
{
    private string $tenantId;
    private string $apiKey;
    private string $baseUrl;
    private Client $httpClient;

    /**
     * Initialize QRAuth client
     *
     * @param string $tenantId Your QRAuth tenant ID
     * @param string $apiKey Your QRAuth API key
     * @param string|null $baseUrl Optional custom base URL (defaults to api.qrauth.io)
     */
    public function __construct(
        string $tenantId,
        string $apiKey,
        ?string $baseUrl = null
    ) {
        $this->tenantId = $tenantId;
        $this->apiKey = $apiKey;
        $this->baseUrl = $baseUrl ?? 'https://api.qrauth.io';

        $this->httpClient = new Client([
            'base_uri' => $this->baseUrl,
            'headers' => [
                'Authorization' => "Bearer {$this->apiKey}",
                'Content-Type' => 'application/json',
                'Accept' => 'application/json',
            ],
        ]);
    }

    /**
     * Create a new QR code for authentication
     *
     * @param string $destination Email or identifier for the QR code
     * @param string $label Label for the QR code
     * @param array|null $location Optional location data with lat, lng, radius
     * @param array|null $metadata Optional custom metadata
     * @param int|null $expiresIn Optional expiration time in seconds
     *
     * @return array QR code object with token, verification URL, and image URL
     *
     * @throws GuzzleException
     */
    public function create(
        string $destination,
        string $label,
        ?array $location = null,
        ?array $metadata = null,
        ?int $expiresIn = null
    ): array {
        $payload = [
            'tenantId' => $this->tenantId,
            'destination' => $destination,
            'label' => $label,
        ];

        if ($location !== null) {
            $payload['location'] = $location;
        }
        if ($metadata !== null) {
            $payload['metadata'] = $metadata;
        }
        if ($expiresIn !== null) {
            $payload['expiresIn'] = $expiresIn;
        }

        $response = $this->httpClient->post('/api/v1/qrcodes', [
            'json' => $payload,
        ]);

        return json_decode((string)$response->getBody(), true);
    }

    /**
     * Verify a QR code token
     *
     * @param string $token The QR code token to verify
     * @param float|null $scannerLat Optional latitude of the scanner
     * @param float|null $scannerLng Optional longitude of the scanner
     *
     * @return array Verification result with verified status and trust score
     *
     * @throws GuzzleException
     */
    public function verify(
        string $token,
        ?float $scannerLat = null,
        ?float $scannerLng = null
    ): array {
        $query = [];
        if ($scannerLat !== null) {
            $query['scannerLat'] = $scannerLat;
        }
        if ($scannerLng !== null) {
            $query['scannerLng'] = $scannerLng;
        }

        $response = $this->httpClient->get("/api/v1/verify/{$token}", [
            'query' => $query,
        ]);

        return json_decode((string)$response->getBody(), true);
    }

    /**
     * Revoke a QR code token
     *
     * @param string $token The QR code token to revoke
     *
     * @throws GuzzleException
     */
    public function revoke(string $token): void
    {
        $this->httpClient->delete("/api/v1/qrcodes/{$token}");
    }

    /**
     * List QR codes with optional filtering
     *
     * @param int|null $limit Maximum number of results
     * @param int|null $offset Number of results to skip
     * @param string|null $status Filter by status (active, expired, revoked)
     *
     * @return array List of QR code objects
     *
     * @throws GuzzleException
     */
    public function list(
        ?int $limit = null,
        ?int $offset = null,
        ?string $status = null
    ): array {
        $query = [];
        if ($limit !== null) {
            $query['limit'] = $limit;
        }
        if ($offset !== null) {
            $query['offset'] = $offset;
        }
        if ($status !== null) {
            $query['status'] = $status;
        }

        $response = $this->httpClient->get('/api/v1/qrcodes', [
            'query' => $query,
        ]);

        return json_decode((string)$response->getBody(), true);
    }
}
