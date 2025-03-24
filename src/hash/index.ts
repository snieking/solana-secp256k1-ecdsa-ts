/**
 * Secp256k1EcdsaHash Interface
 * Defines a standard API for ECDSA hashing functions
 */
export interface Secp256k1EcdsaHash {
  hash(message: Uint8Array): Uint8Array;
}

/**
 * Hash Implementation Modules - imported in dedicated files for better tree-shaking
 */
export * from './sha256';
export * from './sha256d';
export * from './keccak';
export * from './bsm';
export * from './esm'; 