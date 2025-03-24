import { describe, expect, it } from "bun:test";
import { Secp256k1EcdsaSignature, SHA256 } from "../src";
import { ec as EC } from 'elliptic';

// Initialize the secp256k1 curve
const ec = new EC('secp256k1');

// Helper function to convert hex string to Uint8Array
function hexToBytes(hex: string): Uint8Array {
  const bytes = new Uint8Array(hex.length / 2);
  for (let i = 0; i < hex.length; i += 2) {
    bytes[i / 2] = parseInt(hex.substring(i, i + 2), 16);
  }
  return bytes;
}

describe("Solana Transaction Compatibility", () => {
  // Solana test private key
  const SOLANA_TEST_PRIVATE_KEY = "4b9d6f57d28b06cbfa1d4cc710953e62d653caf853d12da2581e69c4c400555c";
  
  // This is similar to how transaction data is hashed in Solana
  const SOLANA_TX_DATA = hexToBytes(
    "010001030405060708090a0b0c0d0e0f101112131415161718191a1b1c1d1e1f202122232425262728292a2b2c2d2e2f"
  );
  
  it("should sign and verify transaction data in Solana format", () => {
    // Arrange - convert the test private key to bytes
    const privateKey = hexToBytes(SOLANA_TEST_PRIVATE_KEY);
    
    // Generate the public key from the private key
    const keypair = ec.keyFromPrivate(privateKey);
    const pubPoint = keypair.getPublic();
    
    // Extract x and y coordinates for verification
    const x = hexToBytes(pubPoint.getX().toString(16, 64));
    const y = hexToBytes(pubPoint.getY().toString(16, 64));
    
    // Create hash implementation
    const sha256 = new SHA256();
    
    // Use a fixed k for deterministic testing
    const kHex = "0000000000000000000000000000000000000000000000000000000000000001";
    const k = hexToBytes(kHex);
    
    // Act - Sign the transaction data
    const signature = Secp256k1EcdsaSignature.signWithK(sha256, SOLANA_TX_DATA, k, privateKey);
    const normalizedSignature = signature.normalizeS();
    
    // Assert - Verify with the associated public key
    const isValid = normalizedSignature.verify(sha256, SOLANA_TX_DATA, { x, y });
    expect(isValid).toBe(true);
  });
  
  it("should verify transaction signatures as they would be verified on-chain", () => {
    // This test simulates the process of signature verification in the Solana runtime
    
    // Arrange - convert the test private key to bytes
    const privateKey = hexToBytes(SOLANA_TEST_PRIVATE_KEY);
    
    // Generate the public key from the private key
    const keypair = ec.keyFromPrivate(privateKey);
    const pubPoint = keypair.getPublic();
    
    // Extract x and y coordinates for verification
    const x = hexToBytes(pubPoint.getX().toString(16, 64));
    const y = hexToBytes(pubPoint.getY().toString(16, 64));
    
    // Create hash implementation
    const sha256 = new SHA256();
    
    // Hash the message as done in Solana's on-chain verification
    const messageHash = sha256.hash(SOLANA_TX_DATA);
    
    // Act - Create a signature using the elliptic library (simulating Solana's client-side signing)
    const ellipticSignature = keypair.sign(Buffer.from(messageHash));
    
    // Convert the signature to the format used by our library
    const r = hexToBytes(ellipticSignature.r.toString(16, 64));
    const s = hexToBytes(ellipticSignature.s.toString(16, 64));
    
    const signature = new Uint8Array(64);
    signature.set(r, 0);
    signature.set(s, 32);
    
    const ourSignature = new Secp256k1EcdsaSignature(signature);
    
    // Assert - Verify with our implementation (simulating the on-chain verification)
    const isValid = ourSignature.verify(sha256, SOLANA_TX_DATA, { x, y });
    expect(isValid).toBe(true);
  });
}); 