import { sha256 } from 'js-sha256';
import type { Secp256k1EcdsaHash } from './index';

/**
 * SHA256 hash implementation
 */
export class SHA256 implements Secp256k1EcdsaHash {
  /**
   * Hash a message using SHA256
   * @param message - The message to hash
   * @returns The 32-byte hash
   */
  hash(message: Uint8Array): Uint8Array {
    const hash = sha256.create();
    hash.update(message);
    const digest = hash.digest();
    
    // Convert the array to Uint8Array
    return new Uint8Array(digest);
  }
} 