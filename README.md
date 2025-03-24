# Solana Secp256k1 ECDSA TypeScript

A TypeScript port of the [solana-secp256k1-ecdsa](https://github.com/deanmlittle/solana-secp256k1-ecdsa-rust) Rust library for signing and verifying Secp256k1 ECDSA signatures. Compatible with Solana wallets and on-chain verification.

## Features

- Sign and verify Secp256k1 ECDSA signatures
- RFC6979 deterministic nonce generation
- Support for multiple hash algorithms:
  - SHA256
  - Double SHA256 (SHA256d)
  - Keccak-256
  - Bitcoin Signed Message (BSM)
  - Ethereum Signed Message (ESM)
- BIP-0062 compatible signature normalization
- **Compatible with Solana wallet signatures and on-chain verification**

## Installation

```bash
bun add solana-secp256k1-ecdsa
```

or

```bash
npm install solana-secp256k1-ecdsa
```

## Usage

### Signing a message

```typescript
import { Secp256k1EcdsaSignature, SHA256 } from 'sol-ecdsa-signatures';

// Create a message
const message = new TextEncoder().encode("Hello, world!");

// Private key (32 bytes)
const privateKey = new Uint8Array(/* your private key */);

// Create a hash implementation
const sha256 = new SHA256();

// Sign the message
const signature = Secp256k1EcdsaSignature.sign(sha256, message, privateKey);

// Normalize the signature (BIP-0062)
const normalizedSignature = signature.normalizeS();

// Get the signature bytes
const signatureBytes = normalizedSignature.signature;
```

### Verifying a signature

```typescript
import { Secp256k1EcdsaSignature, SHA256 } from 'sol-ecdsa-signatures';

// Message that was signed
const message = new TextEncoder().encode("Hello, world!");

// Signature to verify (64 bytes: r[32] + s[32])
const signatureBytes = new Uint8Array(/* signature bytes */);
const signature = new Secp256k1EcdsaSignature(signatureBytes);

// Public key (x,y coordinates)
const publicKey = {
  x: new Uint8Array(/* x coordinate */),
  y: new Uint8Array(/* y coordinate */)
};

// Create hash implementation
const sha256 = new SHA256();

// Verify the signature
const isValid = signature.verify(sha256, message, publicKey);
console.log(`Signature is ${isValid ? 'valid' : 'invalid'}`);
```

### Using Ethereum Signed Message

```typescript
import { Secp256k1EcdsaSignature, ESM } from 'sol-ecdsa-signatures';

// Message to sign
const message = new TextEncoder().encode("Sign this message");

// Private key (32 bytes)
const privateKey = new Uint8Array(/* your private key */);

// Create ESM hash implementation
const esm = new ESM();

// Sign with Ethereum Signed Message format
const signature = Secp256k1EcdsaSignature.sign(esm, message, privateKey);

// Normalize signature
const normalizedSignature = signature.normalizeS();
```

### Solana Wallet Compatibility

This library is compatible with Solana wallet signatures and can be used to verify signatures generated by Solana wallets or to create signatures that can be verified by Solana's on-chain programs.

```typescript
import { Secp256k1EcdsaSignature, SHA256 } from 'sol-ecdsa-signatures';
import { ec as EC } from 'elliptic';

// Initialize elliptic curve
const ec = new EC('secp256k1');

// Handling a signature from a Solana wallet
function verifySolanaWalletSignature(
  message: Uint8Array,
  signatureBytes: Uint8Array,
  publicKeyX: Uint8Array,
  publicKeyY: Uint8Array
): boolean {
  // Create a signature object
  const signature = new Secp256k1EcdsaSignature(signatureBytes);
  
  // Create hash implementation
  const sha256 = new SHA256();
  
  // Verify the signature
  return signature.verify(sha256, message, { x: publicKeyX, y: publicKeyY });
}

// Converting a Solana wallet public key to x,y coordinates
function solanaPublicKeyToCoordinates(solanaWalletPrivateKey: Uint8Array): { x: Uint8Array, y: Uint8Array } {
  const keypair = ec.keyFromPrivate(solanaWalletPrivateKey);
  const pubPoint = keypair.getPublic();
  
  // Extract x and y coordinates
  const x = Uint8Array.from(pubPoint.getX().toArray('be', 32));
  const y = Uint8Array.from(pubPoint.getY().toArray('be', 32));
  
  return { x, y };
}
```

## Development

### Setup

```bash
git clone https://github.com/snieking/solana-secp256k1-ecdsa-ts.git
cd solana-secp256k1-ecdsa-ts
bun install
```

### Testing

Run the test suite:

```bash
bun test
```

### Building

Build the library:

```bash
bun run build
```

## Solana Compatibility Tests

The library includes specific tests to verify compatibility with Solana wallets and on-chain programs:

1. **Wallet signature verification**: Tests that signatures created with this library can be verified with Solana wallet public keys
2. **Transaction signature compatibility**: Tests that transaction data can be signed and verified in a way compatible with Solana's on-chain verification
3. **Interoperability with @solana/web3.js**: Tests compatibility with signatures created using Solana JS libraries

## License

MIT License

## Credits

Port of the [solana-secp256k1-ecdsa](https://github.com/deanmlittle/solana-secp256k1-ecdsa) Rust library by Dean Little (@deanmlittle).
