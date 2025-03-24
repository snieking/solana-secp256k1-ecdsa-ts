import { Curve, rfc6979Generate } from './utils';
import { Secp256k1EcdsaError, Secp256k1EcdsaException } from './errors';
import type { Secp256k1EcdsaHash } from './hash';

// Re-export hash implementations
export * from './hash';
export * from './errors';

// Signature length
export const SECP256K1_ECDSA_SIGNATURE_LENGTH = 64;

/**
 * Secp256k1EcdsaSignature
 * An ECDSA signature used for signature verification purposes.
 */
export class Secp256k1EcdsaSignature {
  /**
   * Create a new signature from a 64-byte array
   * @param signature - The signature bytes
   */
  constructor(public readonly signature: Uint8Array) {
    if (signature.length !== SECP256K1_ECDSA_SIGNATURE_LENGTH) {
      throw new Secp256k1EcdsaException(
        Secp256k1EcdsaError.InvalidSignature,
        `Invalid signature length: ${signature.length}`
      );
    }
  }

  /**
   * Get the r component of the signature
   * @returns The r component as a 32-byte array
   */
  r(): Uint8Array {
    return this.signature.slice(0, 32);
  }

  /**
   * Get the s component of the signature
   * @returns The s component as a 32-byte array
   */
  s(): Uint8Array {
    return this.signature.slice(32, 64);
  }

  /**
   * Sign a message with a defined ephemeral key (k)
   * @param hashImpl - The hash implementation to use
   * @param message - The message to sign
   * @param k - The ephemeral key (must be cryptographically secure if not deterministic)
   * @param privkey - The private key
   * @returns The signature
   */
  static signWithK<H extends Secp256k1EcdsaHash>(
    hashImpl: H,
    message: Uint8Array,
    k: Uint8Array,
    privkey: Uint8Array
  ): Secp256k1EcdsaSignature {
    // Hash the message first
    const h = hashImpl.hash(message);
    
    // Calculate R = k*G and extract x-coordinate
    try {
      const r = Curve.mulG(k);
      
      // Calculate k^-1 (mod n)
      const modInvK = Curve.modInvN(k);
      
      // Calculate s = k^-1 * (h + privkey*r) (mod n)
      const pMulRModN = Curve.mulModN(r, privkey); // Compute privkey * r mod n
      const sum = Curve.addModN(h, pMulRModN); // Compute (h + privkey*r) mod n
      const s = Curve.mulModN(modInvK, sum); // Multiply by k⁻¹ mod n
      
      // Assemble the signature: first 32 bytes R, last 32 bytes S
      const signature = new Uint8Array(64);
      signature.set(r, 0);
      signature.set(s, 32);
      
      return new Secp256k1EcdsaSignature(signature);
    } catch (error) {
      throw new Secp256k1EcdsaException(Secp256k1EcdsaError.InvalidSecretKey);
    }
  }

  /**
   * Sign a message using RFC6979 deterministic nonce generation
   * @param hashImpl - The hash implementation to use
   * @param message - The message to sign
   * @param privkey - The private key
   * @returns The signature
   */
  static sign<H extends Secp256k1EcdsaHash>(
    hashImpl: H,
    message: Uint8Array,
    privkey: Uint8Array
  ): Secp256k1EcdsaSignature {
    // Hash the message first
    const h = hashImpl.hash(message);
    
    // Generate deterministic k using RFC6979
    const k = rfc6979Generate(privkey, h);
    
    // Sign using the generated k
    return Secp256k1EcdsaSignature.signWithK(hashImpl, message, k, privkey);
  }

  /**
   * Normalize the signature to a lower S value (for BIP-0062 compliance)
   * @returns Normalized signature
   */
  normalizeS(): Secp256k1EcdsaSignature {
    const s = this.s();
    
    // Convert to BN for comparison with N_DIV_2
    const sBN = Buffer.from(s);
    const nDiv2Array = Curve.N_DIV_2.toArray('be', 32); // Ensure fixed length array
    const nDiv2Buf = Buffer.from(nDiv2Array);
    
    // Check if s > N/2
    let shouldNegate = false;
    if (sBN.length > nDiv2Buf.length) {
      shouldNegate = true;
    } else if (sBN.length === nDiv2Buf.length) {
      for (let i = 0; i < sBN.length; i++) {
        if (sBN[i] > nDiv2Buf[i]) {
          shouldNegate = true;
          break;
        }
        if (sBN[i] < nDiv2Buf[i]) {
          break;
        }
      }
    }
    
    if (shouldNegate) {
      // Compute the negated s (n - s)
      const negS = Curve.negateN(s);
      
      // Create new signature with negated s
      const signature = new Uint8Array(64);
      signature.set(this.r(), 0);
      signature.set(negS, 32);
      
      return new Secp256k1EcdsaSignature(signature);
    }
    
    // No need to normalize
    return this;
  }

  /**
   * Verify a signature against a public key
   * @param hashImpl - The hash implementation to use
   * @param message - The message that was signed
   * @param pubkey - The public key to verify against
   * @returns True if the signature is valid
   */
  verify<H extends Secp256k1EcdsaHash>(
    hashImpl: H,
    message: Uint8Array,
    pubkey: { x: Uint8Array, y: Uint8Array }
  ): boolean {
    try {
      // Hash message
      const h = hashImpl.hash(message);
      
      // s1 = s^-1 % N
      const s1 = Curve.modInvN(this.s());
      
      // R' = (h * s1) * G + (r * s1) * pubKey
      const rMulS1 = Curve.mulModN(this.r(), s1);
      
      // ecmul pubkey by r*s1
      const point = Curve.ecMul(pubkey, rMulS1);
      
      // Calculate h * s1
      const hMulS1 = Curve.mulModN(h, s1);
      
      // Tweak our point by h*s1
      const recoveredPoint = point.tweak(hMulS1);
      
      // Compare r to x coordinate of recovered point
      const rDigest = Buffer.from(this.r());
      const pointX = Buffer.from(recoveredPoint.x);
      
      for (let i = 0; i < 32; i++) {
        if (rDigest[i] !== pointX[i]) {
          return false;
        }
      }
      
      return true;
    } catch (error) {
      return false;
    }
  }

  /**
   * Compare this signature to another
   * @param other - The other signature
   * @returns True if signatures are equal
   */
  equals(other: Secp256k1EcdsaSignature): boolean {
    if (this.signature.length !== other.signature.length) {
      return false;
    }
    
    for (let i = 0; i < this.signature.length; i++) {
      if (this.signature[i] !== other.signature[i]) {
        return false;
      }
    }
    
    return true;
  }
} 