# jwt-issuer

A standalone authentication service for the Livepeer remote signer. Authenticates users via **Sign-In With Ethereum** (EIP-4361 / SIWE) and issues **RS256 JWTs** that the remote signer validates via JWKS.

## Architecture

```
User Wallet          jwt-issuer              Remote Signer (go-livepeer)
    |                     |                          |
    | POST /auth/nonce    |                          |
    |-------------------->|                          |
    |  {nonce, domain}    |                          |
    |<--------------------|                          |
    |                     |                          |
    | Sign SIWE message   |                          |
    | POST /auth/login    |                          |
    |-------------------->|                          |
    |  {token, address}   |                          |
    |<--------------------|                          |
    |                     |                          |
    | POST /sign-orchestrator-info                   |
    | Authorization: Bearer <token>                  |
    |----------------------------------------------->|
    |                     |  GET /.well-known/jwks.json
    |                     |<-------------------------|
    |                     |  {keys: [{kty, kid, ...}]}
    |                     |------------------------->|
    |                     |                          |
    |  {address, signature}                          |
    |<-----------------------------------------------|
```

No shared secrets between services. The jwt-issuer signs JWTs with its RSA private key. The remote signer fetches the public key from the JWKS endpoint.

## Quick Start

### 1. Generate an RSA key pair

```bash
openssl genrsa -out private.pem 4096
```

See [doc/keygen.md](doc/keygen.md) for details.

### 2. Start the jwt-issuer

```bash
go build -o jwt-issuer .

./jwt-issuer \
  -listen :8082 \
  -jwkPrivateKeyPath ./private.pem \
  -jwkKeyID "livepeer-key-1" \
  -siweDomain livepeer.ai \
  -tokenTTL 8h
```

### 3. Start the remote signer (go-livepeer)

Point the remote signer at the jwt-issuer's JWKS endpoint:

```bash
./livepeer \
  -remoteSigner \
  -remoteSignerJWKSUrl http://localhost:8082/.well-known/jwks.json \
  -network arbitrum-one-mainnet \
  -httpAddr 0.0.0.0:8081 \
  -ethUrl <eth-rpc-url> \
  -ethAcctAddr <signer-eth-address> \
  -ethPassword <password-file>
```

### 4. Authenticate

```bash
# Get a nonce
NONCE=$(curl -s -X POST http://localhost:8082/auth/nonce | jq -r '.nonce')

# Sign a SIWE message with your wallet, then login
curl -s -X POST http://localhost:8082/auth/login \
  -H "Content-Type: application/json" \
  -d "{\"message\":\"<SIWE message>\",\"signature\":\"0x<sig>\"}" | jq .

# Use the JWT
curl -s -X POST http://localhost:8081/sign-orchestrator-info \
  -H "Authorization: Bearer <token>" | jq .
```

## Endpoints

| Method | Path | Auth | Description |
|--------|------|------|-------------|
| POST | `/auth/nonce` | None | Generate a SIWE nonce (valid 5 min) |
| POST | `/auth/login` | None | Verify SIWE signature, issue JWT |
| GET | `/.well-known/jwks.json` | None | Serve RSA public key (JWKS) |
| GET | `/healthz` | None | Health check |

## Flags

| Flag | Default | Description |
|------|---------|-------------|
| `-listen` | `:8082` | HTTP listen address |
| `-jwkPrivateKeyPath` | (required) | Path to RSA private key PEM file |
| `-jwkKeyID` | `livepeer-key-1` | Key ID for JWKS `kid` header |
| `-siweDomain` | (required) | Domain for SIWE message verification |
| `-tokenTTL` | `8h` | JWT token lifetime |

## JWT Claims

Issued tokens contain:

```json
{
  "sub": "0xUserEthAddress",
  "iss": "livepeer-jwt-issuer",
  "aud": "livepeer-remote-signer",
  "exp": 1738972800,
  "iat": 1738943200,
  "jti": "unique-id",
  "scope": "sign:orchestrator sign:payment sign:byoc",
  "tier": "standard"
}
```

## Security

- **No shared secrets**: Asymmetric RS256 signing. The private key stays on the jwt-issuer. The remote signer only has the public key.
- **EIP-4361 SIWE**: Users prove wallet ownership by signing a standardized, replay-safe message. No passwords, no stored credentials.
- **Nonce protection**: Each nonce is single-use and expires after 5 minutes.
- **Domain binding**: SIWE messages are bound to a specific domain, preventing phishing.

See [doc/keygen.md](doc/keygen.md) for key management and rotation.
