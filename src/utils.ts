import { ec as EC } from 'elliptic';

// Initialize secp256k1 curve
const ec = new EC('secp256k1');

/**
 * Utility functions for elliptic curve operations
 */
export class Curve {
  // Half of the curve order
  public static readonly N_DIV_2 = ec.n!.shrn(1);
  
  // Curve order
  public static readonly N = ec.n!;

  /**
   * Multiply generator point by scalar
   * @param k - The scalar value
   * @returns The resulting point x-coordinate as a 32-byte array
   */
  public static mulG(k: Uint8Array): Uint8Array {
    try {
      // Convert k to BN
      const scalar = toScalar(k);
      
      // Multiply generator by scalar
      const point = ec.g.mul(scalar);
      
      return pointXToBytes(point);
    } catch (error) {
      console.error('Error in mulG:', error);
      throw error;
    }
  }

  /**
   * Compute modular inverse of a number mod N
   * @param k - The input value
   * @returns The modular inverse as a 32-byte array
   */
  public static modInvN(k: Uint8Array): Uint8Array {
    try {
      const scalar = toScalar(k);
      
      // Calculate modular inverse
      const inverse = scalar.invm(ec.n!);
      
      return bnToBytes(inverse);
    } catch (error) {
      console.error('Error in modInvN:', error);
      throw error;
    }
  }

  /**
   * Multiply two numbers modulo N
   * @param a - First number
   * @param b - Second number
   * @returns The product as a 32-byte array
   */
  public static mulModN(a: Uint8Array, b: Uint8Array): Uint8Array {
    try {
      const aBN = toScalar(a);
      const bBN = toScalar(b);
      
      // Calculate product modulo N
      const product = aBN.mul(bBN).mod(ec.n!);
      
      return bnToBytes(product);
    } catch (error) {
      console.error('Error in mulModN:', error);
      throw error;
    }
  }

  /**
   * Add two numbers modulo N
   * @param a - First number
   * @param b - Second number
   * @returns The sum as a 32-byte array
   */
  public static addModN(a: Uint8Array, b: Uint8Array): Uint8Array {
    try {
      const aBN = toScalar(a);
      const bBN = toScalar(b);
      
      // Calculate sum modulo N
      const sum = aBN.add(bBN).mod(ec.n!);
      
      return bnToBytes(sum);
    } catch (error) {
      console.error('Error in addModN:', error);
      throw error;
    }
  }

  /**
   * Negate a number modulo N
   * @param a - The number to negate
   * @returns The negation as a 32-byte array
   */
  public static negateN(a: Uint8Array): Uint8Array {
    try {
      const aBN = toScalar(a);
      
      // Calculate negation modulo N
      const negation = ec.n!.sub(aBN).mod(ec.n!);
      
      return bnToBytes(negation);
    } catch (error) {
      console.error('Error in negateN:', error);
      throw error;
    }
  }

  /**
   * Multiply point by scalar
   * @param point - The point (as an EC point or an object with x,y coordinates)
   * @param scalar - The scalar value
   * @returns The resulting point
   */
  public static ecMul(point: any, scalar: Uint8Array): any {
    try {
      // If point is already an EC point, use it directly
      let ecPoint;
      if (typeof point.mul === 'function') {
        ecPoint = point;
      } else {
        // Otherwise, create a point from x,y coordinates
        const xHex = Buffer.from(point.x).toString('hex');
        const yHex = Buffer.from(point.y).toString('hex');
        ecPoint = ec.curve.point(xHex, yHex);
      }
      
      // Multiply by scalar
      const result = ecPoint.mul(toScalar(scalar));
      
      return {
        x: pointXToBytes(result),
        y: pointYToBytes(result),
        tweak: function(scalar: Uint8Array) {
          try {
            // Generate generator * scalar
            const tweakPoint = ec.g.mul(toScalar(scalar));
            
            // Add to current point
            const sumPoint = result.add(tweakPoint);
            
            return {
              x: pointXToBytes(sumPoint),
              y: pointYToBytes(sumPoint)
            };
          } catch (error) {
            console.error('Error in tweak function:', error);
            throw error;
          }
        }
      };
    } catch (error) {
      console.error('Error in ecMul:', error);
      throw error;
    }
  }
}

/**
 * Convert a Uint8Array to a BN scalar
 */
function toScalar(bytes: Uint8Array): any {
  try {
    // Convert to hex string first
    const hex = Buffer.from(bytes).toString('hex');
    // Create BN from hex
    return ec.keyFromPrivate(hex, 'hex').getPrivate();
  } catch (error) {
    console.error('Error in toScalar:', error);
    throw error;
  }
}

/**
 * Convert a BN to a 32-byte Uint8Array
 */
function bnToBytes(bn: any): Uint8Array {
  try {
    if (!bn) {
      throw new Error('BN is undefined or null');
    }
    
    // Get hex representation with padding
    const hex = bn.toString(16).padStart(64, '0');
    const result = new Uint8Array(32);
    
    for (let i = 0; i < 32; i++) {
      result[i] = parseInt(hex.substring(i * 2, i * 2 + 2), 16);
    }
    
    return result;
  } catch (error) {
    console.error('Error in bnToBytes:', error, 'BN:', bn);
    throw error;
  }
}

/**
 * Extract x-coordinate from a point as a 32-byte Uint8Array
 */
function pointXToBytes(point: any): Uint8Array {
  try {
    if (!point || !point.getX) {
      throw new Error('Invalid point object');
    }
    return bnToBytes(point.getX());
  } catch (error) {
    console.error('Error in pointXToBytes:', error);
    throw error;
  }
}

/**
 * Extract y-coordinate from a point as a 32-byte Uint8Array
 */
function pointYToBytes(point: any): Uint8Array {
  try {
    if (!point || !point.getY) {
      throw new Error('Invalid point object');
    }
    return bnToBytes(point.getY());
  } catch (error) {
    console.error('Error in pointYToBytes:', error);
    throw error;
  }
}

/**
 * Generate an RFC6979 deterministic k value for ECDSA signing
 */
export function rfc6979Generate(privKey: Uint8Array, message: Uint8Array): Uint8Array {
  try {
    // Convert to hex string first
    const privHex = Buffer.from(privKey).toString('hex');
    const msgHex = Buffer.from(message).toString('hex');
    
    // Use elliptic's built-in RFC6979 implementation
    const key = ec.keyFromPrivate(privHex, 'hex');
    const msgHash = Buffer.from(msgHex, 'hex');
    
    // Get k value from the built-in deterministic k generation
    const signOptions: { canonical: boolean, k: any } = { canonical: true, k: null };
    const sign = key.sign(msgHash, signOptions);
    
    // In elliptic library, the 'k' is available on the Signature object
    const k = (sign as any).k;
    
    return bnToBytes(k);
  } catch (error) {
    console.error('Error in rfc6979Generate:', error);
    throw error;
  }
} 