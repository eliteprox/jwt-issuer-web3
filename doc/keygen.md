# RSA Key Generation for JWT Signing

The jwt-issuer service signs JWTs using RS256 (RSA with SHA-256). You need to generate an RSA key pair before starting the service.

## Generate a key pair

```bash
# Generate a 4096-bit RSA private key (recommended)
openssl genrsa -out private.pem 4096

# Extract the public key (for reference -- the JWKS endpoint serves it automatically)
openssl rsa -in private.pem -pubout -out public.pem
```

Minimum key size is 2048 bits. 4096 bits is recommended for production.

## Verify the key

```bash
# Check key details
openssl rsa -in private.pem -text -noout | head -1

# Expected output: RSA Private-Key: (4096 bit, 2 primes)
```

## File permissions

The private key file should be readable only by the jwt-issuer process:

```bash
chmod 600 private.pem
```

## Key rotation

To rotate keys:

1. Generate a new key pair with a new key ID
2. Start a new jwt-issuer instance with `-jwkKeyID "livepeer-key-2"` and the new private key
3. Run both instances in parallel (both serve their public key via JWKS)
4. Wait for all old JWTs to expire (max token TTL)
5. Shut down the old instance

The remote signer's JWKS cache refreshes every hour, so new keys are picked up automatically.

## Never share the private key

- The private key (`private.pem`) stays on the jwt-issuer server only
- The remote signer never needs the private key -- it fetches the public key via JWKS
- Do not commit private keys to version control
- Use secrets management (Vault, AWS Secrets Manager, etc.) in production
