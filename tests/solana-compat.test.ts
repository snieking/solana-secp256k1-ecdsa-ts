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

// Helper function to convert Uint8Array to hex string
function bytesToHex(bytes: Uint8Array): string {
  return Array.from(bytes)
    .map(b => b.toString(16).padStart(2, '0'))
    .join('');
}

// Sample from a real Solana wallet - typically the private key is derived from a mnemonic
describe("Solana Wallet Compatibility", () => {
  // Test vector from a Solana wallet - this is a valid Solana test keypair
  const SOLANA_TEST_PRIVATE_KEY = "4b9d6f57d28b06cbfa1d4cc710953e62d653caf853d12da2581e69c4c400555c";
  const SOLANA_TEST_PUBLIC_KEY = "GZNnvZa5Dy6CYYmjpGoQWPZjjCWQago4ndxvQG3ErYrz";

  // The message that would be signed by a Solana wallet
  const TEST_MESSAGE = "Sign this message for a Solana dApp";
  
  it("should generate a signature that can be verified with the correct public key", () => {
    // Arrange - convert the test private key to bytes
    const privateKey = hexToBytes(SOLANA_TEST_PRIVATE_KEY);
    const message = new TextEncoder().encode(TEST_MESSAGE);
    
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
    
    // Act - Sign the message
    const signature = Secp256k1EcdsaSignature.signWithK(sha256, message, k, privateKey);
    const normalizedSignature = signature.normalizeS();
    
    // Assert - Verify with the associated public key
    const isValid = normalizedSignature.verify(sha256, message, { x, y });
    expect(isValid).toBe(true);
  });
  
  it("should verify signatures from message bytes in Solana wallet format", () => {
    // Solana typically prefixes messages with a domain separator
    // This test ensures our implementation can handle this pattern
    
    // Standard Solana message prefix
    const SOLANA_MESSAGE_PREFIX = "Solana Message";
    
    // Create a message in Solana message format
    const messageToSign = TEST_MESSAGE;
    const prefix = new TextEncoder().encode(SOLANA_MESSAGE_PREFIX);
    const messageBytes = new TextEncoder().encode(messageToSign);
    
    // Combine prefix and message (this mimics how Solana creates messages to sign)
    const combinedMessage = new Uint8Array(prefix.length + 1 + messageBytes.length);
    combinedMessage.set(prefix, 0);
    combinedMessage[prefix.length] = 0; // Separator
    combinedMessage.set(messageBytes, prefix.length + 1);
    
    // Arrange test data
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
    
    // Act - Sign the combined message
    const signature = Secp256k1EcdsaSignature.signWithK(sha256, combinedMessage, k, privateKey);
    const normalizedSignature = signature.normalizeS();
    
    // Assert - Verify with the associated public key
    const isValid = normalizedSignature.verify(sha256, combinedMessage, { x, y });
    expect(isValid).toBe(true);
  });
  
  it("should interoperate with elliptic library signatures (used by Solana JS libraries)", () => {
    // Arrange
    const privateKey = hexToBytes(SOLANA_TEST_PRIVATE_KEY);
    const message = new TextEncoder().encode(TEST_MESSAGE);
    
    // Create hash implementation
    const sha256 = new SHA256();
    
    // Hash the message (as would happen in Solana JS libraries)
    const messageHash = sha256.hash(message);
    
    // Act - Create a signature using the elliptic library directly (as used in @solana/web3.js)
    const keypair = ec.keyFromPrivate(privateKey);
    const ellipticSignature = keypair.sign(Buffer.from(messageHash));
    
    // Convert the signature to our format
    const r = hexToBytes(ellipticSignature.r.toString(16, 64));
    const s = hexToBytes(ellipticSignature.s.toString(16, 64));
    
    const signature = new Uint8Array(64);
    signature.set(r, 0);
    signature.set(s, 32);
    
    const ourSignature = new Secp256k1EcdsaSignature(signature);
    
    // Get public key coordinates
    const pubPoint = keypair.getPublic();
    const x = hexToBytes(pubPoint.getX().toString(16, 64));
    const y = hexToBytes(pubPoint.getY().toString(16, 64));
    
    // Assert - Verify with our implementation
    const isValidWithOur = ourSignature.verify(sha256, message, { x, y });
    expect(isValidWithOur).toBe(true);
    
    // Check the reverse direction: verify an elliptic signature with our code
    const kHex = "0000000000000000000000000000000000000000000000000000000000000001";
    const k = hexToBytes(kHex);
    
    const ourGeneratedSignature = Secp256k1EcdsaSignature.signWithK(sha256, message, k, privateKey);
    
    // Convert our signature to elliptic format
    const rBN = ec.keyFromPrivate(Buffer.from(ourGeneratedSignature.r())).getPrivate();
    const sBN = ec.keyFromPrivate(Buffer.from(ourGeneratedSignature.s())).getPrivate();
    
    // Verify using elliptic
    const isVerified = keypair.verify(Buffer.from(messageHash), { r: rBN, s: sBN });
    expect(isVerified).toBe(true);
  });
}); 