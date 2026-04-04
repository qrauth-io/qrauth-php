# QRAuth PHP SDK

The official PHP SDK for QRAuth - secure QR code authentication and verification.

## Installation

```bash
composer require qrauth/qrauth-php
```

## Quick Start

### Create a QR Code

```php
require_once 'vendor/autoload.php';

use QRAuth\QRAuth;

$qrauth = new QRAuth(
    tenantId: 'your-tenant-id',
    apiKey: 'your-api-key'
);

$qrCode = $qrauth->create(
    destination: 'user@example.com',
    label: 'Login Verification',
    location: [
        'lat' => 40.7128,
        'lng' => -74.0060,
        'radius' => 100
    ]
);

echo $qrCode['qrImageUrl']; // Display to user
```

### Verify a Token

```php
$result = $qrauth->verify(
    token: $token,
    scannerLat: 40.7128,
    scannerLng: -74.0060
);

if ($result['verified']) {
    echo "Verified by " . $result['issuer']['name'];
    echo "Trust score: " . $result['trustScore'];
}
```

## API Reference

### QRAuth Class

#### `__construct(string $tenantId, string $apiKey, ?string $baseUrl = null)`
Initialize the QRAuth client.

#### `create(string $destination, string $label, ?array $location = null, ?array $metadata = null, ?int $expiresIn = null): array`
Create a new QR code for authentication.

#### `verify(string $token, ?float $scannerLat = null, ?float $scannerLng = null): array`
Verify a QR code token.

#### `revoke(string $token): void`
Revoke a QR code token.

#### `list(?int $limit = null, ?int $offset = null, ?string $status = null): array`
List QR codes with optional filtering.

## Full Documentation

For detailed API documentation, visit [docs.qrauth.io](https://docs.qrauth.io)
