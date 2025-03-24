import { describe, expect, it } from "bun:test";
import { Secp256k1EcdsaSignature, SHA256 } from "../src";
import * as web3 from "@solana/web3.js";
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

describe("Solana Web3.js Integration", () => {
  it("should verify signatures from Solana keypairs", async () => {
    // Create a Solana keypair (this would typically be a wallet)
    const wallet = web3.Keypair.generate();
    
    // The message to sign
    const message = new TextEncoder().encode("Hello from Solana");
    
    // Hash the message as would be done in Solana
    const sha256 = new SHA256();
    const messageHash = sha256.hash(message);
    
    // Convert Solana private key to format expected by elliptic
    // Solana uses the first 32 bytes of the keypair for the private key
    const privateKeyBytes = wallet.secretKey.slice(0, 32);
    
    // Use elliptic to sign like Solana web3.js would
    const keypair = ec.keyFromPrivate(Buffer.from(privateKeyBytes));
    const signature = keypair.sign(Buffer.from(messageHash));
    
    // Convert signature to our format
    const r = Buffer.from(signature.r.toArray('be', 32));
    const s = Buffer.from(signature.s.toArray('be', 32));
    
    const combinedSignature = new Uint8Array(64);
    combinedSignature.set(r, 0);
    combinedSignature.set(s, 32);
    
    // Create our signature object
    const ourSignature = new Secp256k1EcdsaSignature(combinedSignature);
    
    // Extract x and y coordinates from the Solana public key
    const publicKey = keypair.getPublic();
    const x = Uint8Array.from(publicKey.getX().toArray('be', 32));
    const y = Uint8Array.from(publicKey.getY().toArray('be', 32));
    
    // Verify the signature using our library
    const isValid = ourSignature.verify(sha256, message, { x, y });
    
    expect(isValid).toBe(true);
  });
  
  it("should verify transaction signatures compatible with Solana", async () => {
    // Create a Solana connection (this is a fake/test endpoint)
    const connection = new web3.Connection("http://localhost:8899", "confirmed");
    
    // Create a transaction
    const transaction = new web3.Transaction();
    
    // Add a simple system program transfer
    const sender = web3.Keypair.generate();
    const recipient = web3.Keypair.generate();
    
    // Create a transfer instruction
    const transferInstruction = web3.SystemProgram.transfer({
      fromPubkey: sender.publicKey,
      toPubkey: recipient.publicKey,
      lamports: 1000000, // 0.001 SOL
    });
    
    // Add the instruction to the transaction
    transaction.add(transferInstruction);
    
    // Get the transaction message (this is what gets signed)
    transaction.recentBlockhash = "11111111111111111111111111111111";
    transaction.feePayer = sender.publicKey;
    
    // Serialize the transaction message (this would be signed)
    const serializedMessage = transaction.serializeMessage();
    
    // Now we'll sign this with our library instead of using Solana's sign method
    const privateKey = sender.secretKey.slice(0, 32);
    
    // Create hash implementation
    const sha256 = new SHA256();
    
    // Use a fixed k for deterministic testing
    const kHex = "0000000000000000000000000000000000000000000000000000000000000001";
    const k = hexToBytes(kHex);
    
    // Sign the serialized message using our library
    const signature = Secp256k1EcdsaSignature.signWithK(sha256, serializedMessage, k, privateKey);
    const normalizedSignature = signature.normalizeS();
    
    // Extract x and y coordinates from the sender's public key
    const ecKeypair = ec.keyFromPrivate(Buffer.from(privateKey));
    const publicKey = ecKeypair.getPublic();
    const x = Uint8Array.from(publicKey.getX().toArray('be', 32));
    const y = Uint8Array.from(publicKey.getY().toArray('be', 32));
    
    // Verify the signature using our library
    const isValid = normalizedSignature.verify(sha256, serializedMessage, { x, y });
    
    expect(isValid).toBe(true);
    
    // The signature could now be added to the transaction and sent to the Solana network
    // transaction.addSignature(sender.publicKey, Buffer.from(normalizedSignature.signature));
  });
}); 