import { keccak_256 } from 'js-sha3';
import type { Secp256k1EcdsaHash } from './index';

/**
 * Ethereum Signed Message hash implementation
 */
export class ESM implements Secp256k1EcdsaHash {
  /**
   * Hash a message using Ethereum Signed Message format
   * @param message - The message to hash
   * @returns The 32-byte hash
   */
  hash(message: Uint8Array): Uint8Array {
    // Create prefix "\x19Ethereum Signed Message:\n" + message.length
    const prefix = `\x19Ethereum Signed Message:\n${message.length}`;
    
    // Encode prefix as UTF-8
    const prefixBytes = new TextEncoder().encode(prefix);
    
    // Concatenate prefix and message
    const combined = new Uint8Array(prefixBytes.length + message.length);
    combined.set(prefixBytes, 0);
    combined.set(message, prefixBytes.length);
    
    // Hash the combined message with Keccak-256
    const hash = keccak_256.create();
    hash.update(combined);
    const digest = hash.digest();
    
    return new Uint8Array(digest);
  }
} 