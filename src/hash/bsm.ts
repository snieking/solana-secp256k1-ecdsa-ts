import { sha256 } from 'js-sha256';
import type { Secp256k1EcdsaHash } from './index';

/**
 * Bitcoin Signed Message hash implementation
 */
export class BSM implements Secp256k1EcdsaHash {
  private static readonly MAGIC_BYTES = new TextEncoder().encode('\u0018Bitcoin Signed Message:\n');

  /**
   * Hash a message using Bitcoin Signed Message format
   * @param message - The message to hash
   * @returns The 32-byte hash
   */
  hash(message: Uint8Array): Uint8Array {
    const len = message.length;
    
    // Encode message length in varint format
    const buffer = new Uint8Array(9);
    const bufferLen = BSM.encodeVarint(len, buffer);
    
    // First SHA256 hash
    const firstHash = sha256.create();
    firstHash.update(BSM.MAGIC_BYTES);
    firstHash.update(buffer.subarray(0, bufferLen));
    firstHash.update(message);
    const firstDigest = firstHash.digest();
    
    // Second SHA256 hash
    const secondHash = sha256.create();
    secondHash.update(firstDigest);
    const secondDigest = secondHash.digest();
    
    return new Uint8Array(secondDigest);
  }

  /**
   * Encode a number as a Bitcoin varint
   * @param varint - The number to encode
   * @param buffer - The output buffer (must be at least 9 bytes)
   * @returns The number of bytes written
   */
  private static encodeVarint(varint: number, buffer: Uint8Array): number {
    if (varint <= 252) {
      buffer[0] = varint;
      return 1;
    } else if (varint <= 0xffff) {
      buffer[0] = 0xfd;
      buffer[1] = varint & 0xff;
      buffer[2] = (varint >> 8) & 0xff;
      return 3;
    } else if (varint <= 0xffffffff) {
      buffer[0] = 0xfe;
      buffer[1] = varint & 0xff;
      buffer[2] = (varint >> 8) & 0xff;
      buffer[3] = (varint >> 16) & 0xff;
      buffer[4] = (varint >> 24) & 0xff;
      return 5;
    } else {
      buffer[0] = 0xff;
      buffer[1] = varint & 0xff;
      buffer[2] = (varint >> 8) & 0xff;
      buffer[3] = (varint >> 16) & 0xff;
      buffer[4] = (varint >> 24) & 0xff;
      
      // JavaScript bitwise operations work on 32-bit integers, so we need to handle the upper bits carefully
      const upper = Math.floor(varint / 0x100000000);
      buffer[5] = upper & 0xff;
      buffer[6] = (upper >> 8) & 0xff;
      buffer[7] = (upper >> 16) & 0xff;
      buffer[8] = (upper >> 24) & 0xff;
      
      return 9;
    }
  }
} 