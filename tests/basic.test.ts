import { describe, expect, it } from "bun:test";
import { 
  Secp256k1EcdsaSignature, 
  SHA256, 
  BSM, 
  ESM 
} from "../src";
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

describe("Secp256k1 ECDSA Signature", () => {
  it("should create a valid signature with a provided k", () => {
    const message = new TextEncoder().encode("Hello");
    const privkeyHex = "ef235aacf90d9f4aadd8c92e4b2562e1d9eb97f0df9ba3b50825873901013db2";
    const privkey = hexToBytes(privkeyHex);
    
    // Fixed k for testing
    const kHex = "0000000000000000000000000000000000000000000000000000000000000001";
    const k = hexToBytes(kHex);
    
    // Create hash implementations
    const sha256 = new SHA256();
    
    // Sign the message with fixed k
    const signature = Secp256k1EcdsaSignature.signWithK(sha256, message, k, privkey);
    const normalizedSignature = signature.normalizeS();
    
    // Generate public key from private key
    const keypair = ec.keyFromPrivate(privkey);
    const pubPoint = keypair.getPublic();
    
    // Extract x and y coordinates
    const x = hexToBytes(pubPoint.getX().toString(16, 64));
    const y = hexToBytes(pubPoint.getY().toString(16, 64));
    
    // Verify the signature
    const isValid = normalizedSignature.verify(sha256, message, { x, y });
    
    expect(isValid).toBe(true);
  });
  
  it("should handle Bitcoin Signed Message correctly with a provided k", () => {
    const message = new TextEncoder().encode("test");
    const privkeyHex = "0000000000000000000000000000000000000000000000000000000000000001";
    const privkey = hexToBytes(privkeyHex);
    
    // Fixed k for testing
    const kHex = "0000000000000000000000000000000000000000000000000000000000000001";
    const k = hexToBytes(kHex);
    
    // Create hash implementations
    const bsm = new BSM();
    
    // Sign the message with fixed k
    const signature = Secp256k1EcdsaSignature.signWithK(bsm, message, k, privkey);
    const normalizedSignature = signature.normalizeS();
    
    // Generate public key from private key
    const keypair = ec.keyFromPrivate(privkey);
    const pubPoint = keypair.getPublic();
    
    // Extract x and y coordinates
    const x = hexToBytes(pubPoint.getX().toString(16, 64));
    const y = hexToBytes(pubPoint.getY().toString(16, 64));
    
    // Verify the signature
    const isValid = normalizedSignature.verify(bsm, message, { x, y });
    
    expect(isValid).toBe(true);
  });
  
  it("should handle Ethereum Signed Message correctly with a provided k", () => {
    const message = new TextEncoder().encode("test");
    const privkeyHex = "0000000000000000000000000000000000000000000000000000000000000001";
    const privkey = hexToBytes(privkeyHex);
    
    // Fixed k for testing
    const kHex = "0000000000000000000000000000000000000000000000000000000000000001";
    const k = hexToBytes(kHex);
    
    // Create hash implementations
    const esm = new ESM();
    
    // Sign the message with fixed k
    const signature = Secp256k1EcdsaSignature.signWithK(esm, message, k, privkey);
    const normalizedSignature = signature.normalizeS();
    
    // Generate public key from private key
    const keypair = ec.keyFromPrivate(privkey);
    const pubPoint = keypair.getPublic();
    
    // Extract x and y coordinates
    const x = hexToBytes(pubPoint.getX().toString(16, 64));
    const y = hexToBytes(pubPoint.getY().toString(16, 64));
    
    // Verify the signature
    const isValid = normalizedSignature.verify(esm, message, { x, y });
    
    expect(isValid).toBe(true);
  });
}); 