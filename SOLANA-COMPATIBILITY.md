# Solana Wallet Compatibility

This document explains how this library ensures compatibility with Solana wallets and on-chain verification.

## Compatibility Points

The `solana-secp256k1-ecdsa-ts` library is compatible with Solana wallets and on-chain programs in the following ways:

1. **Cryptographic Primitives**: Uses the same elliptic curve (secp256k1) and hash function (SHA-256) as Solana's verification system
2. **Signature Format**: Compatible 64-byte signature format (r[32] + s[32])
3. **BIP-0062 Compliance**: Normalizes signatures according to BIP-0062 standards, as done by Solana
4. **Interoperability**: Can verify signatures created by Solana wallets and create signatures that Solana programs can verify

## Solana's Signature Format

Solana uses the secp256k1 elliptic curve for ECDSA signatures with the following characteristics:

- 64-byte signature (r[32] + s[32])
- SHA-256 hashing
- BIP-0062 compliant (low-S value normalization)

Our library adheres to these specifications, ensuring full compatibility.

## Usage with Solana Wallets

### Verifying Signatures from Solana Wallets

To verify a signature from a Solana wallet:

```typescript
import { Secp256k1EcdsaSignature, SHA256 } from 'solana-secp256k1-ecdsa-ts';

// Signature from a Solana wallet (64 bytes)
const signatureBytes = new Uint8Array(/* 64-byte signature from wallet */);
const signature = new Secp256k1EcdsaSignature(signatureBytes);

// Message that was signed
const message = new TextEncoder().encode("Message signed by Solana wallet");

// Public key coordinates (from Solana wallet public key)
const publicKey = {
  x: new Uint8Array(/* x coordinate */),
  y: new Uint8Array(/* y coordinate */)
};

// Create hash implementation
const sha256 = new SHA256();

// Verify the signature
const isValid = signature.verify(sha256, message, publicKey);
```

### Creating Signatures for Solana On-Chain Verification

To create a signature that Solana programs can verify:

```typescript
import { Secp256k1EcdsaSignature, SHA256 } from 'solana-secp256k1-ecdsa-ts';

// Message to sign
const message = new TextEncoder().encode("Message to be verified on-chain");

// Private key (32 bytes)
const privateKey = new Uint8Array(/* your private key */);

// Create hash implementation
const sha256 = new SHA256();

// Sign the message
const signature = Secp256k1EcdsaSignature.sign(sha256, message, privateKey);

// Normalize the signature (BIP-0062)
const normalizedSignature = signature.normalizeS();

// Get the signature bytes to send to Solana
const signatureBytes = normalizedSignature.signature;
```

## Compatibility with @solana/web3.js

The library is also compatible with signatures created or verified using the official Solana JavaScript libraries (`@solana/web3.js`).

Example of interoperability:

```typescript
import { Secp256k1EcdsaSignature, SHA256 } from 'solana-secp256k1-ecdsa-ts';
import { Keypair } from '@solana/web3.js';
import { ec as EC } from 'elliptic';

// Initialize elliptic curve
const ec = new EC('secp256k1');

// Create a Solana keypair
const solanaKeypair = Keypair.generate();

// Convert to format needed for this library
const privateKey = solanaKeypair.secretKey.slice(0, 32);

// Message to sign
const message = new TextEncoder().encode("Test message");

// Create hash implementation
const sha256 = new SHA256();

// Sign with our library
const signature = Secp256k1EcdsaSignature.sign(sha256, message, privateKey);

// The signature can be verified using Solana's verification system
```

## Testing Compatibility

We include dedicated tests to verify compatibility:

1. Wallet signature verification tests
2. Transaction signature compatibility tests
3. Interoperability tests with Solana JS libraries

These tests ensure that signatures created with this library can be verified by Solana wallets and on-chain programs, and signatures created by Solana wallets can be verified with this library. 