import { keccak_256 } from 'js-sha3';
import type { Secp256k1EcdsaHash } from './index';

/**
 * Keccak-256 hash implementation
 */
export class Keccak implements Secp256k1EcdsaHash {
  /**
   * Hash a message using Keccak-256
   * @param message - The message to hash
   * @returns The 32-byte hash
   */
  hash(message: Uint8Array): Uint8Array {
    const hash = keccak_256.create();
    hash.update(message);
    const digest = hash.digest();
    
    return new Uint8Array(digest);
  }
} 