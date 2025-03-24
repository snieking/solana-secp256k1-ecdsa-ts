/**
 * ECDSA Error types for the library
 */
export enum Secp256k1EcdsaError {
  InvalidSecretKey = 1,
  InvalidPublicKey = 2,
  InvalidRecoveryId = 3,
  InvalidSignature = 4,
  InvalidNonce = 5,
  ArithmeticOverflow = 6
}

/**
 * ECDSA Exception class for throwing typed errors
 */
export class Secp256k1EcdsaException extends Error {
  constructor(public code: Secp256k1EcdsaError, message: string = '') {
    const errorType = Secp256k1EcdsaError[code] || 'Unknown';
    super(message || `Secp256k1 Error: ${errorType}`);
    this.name = 'Secp256k1EcdsaException';
  }
} 