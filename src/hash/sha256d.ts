import { sha256 } from 'js-sha256';
import type { Secp256k1EcdsaHash } from './index';

/**
 * SHA256d hash implementation
 * Applies SHA256 twice: sha256(sha256(message))
 */
export class SHA256d implements Secp256k1EcdsaHash {
  /**
   * Hash a message using double SHA256
   * @param message - The message to hash
   * @returns The 32-byte hash
   */
  hash(message: Uint8Array): Uint8Array {
    // First SHA256
    const firstHash = sha256.create();
    firstHash.update(message);
    const firstDigest = firstHash.digest();
    
    // Second SHA256
    const secondHash = sha256.create();
    secondHash.update(firstDigest);
    const secondDigest = secondHash.digest();
    
    return new Uint8Array(secondDigest);
  }
} 