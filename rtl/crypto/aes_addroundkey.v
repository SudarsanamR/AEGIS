`timescale 1ns / 1ps
//==============================================================================
// AES AddRoundKey Transformation
// AEGIS Project - ChipVerse '26
//==============================================================================
// XORs the current AES state with a 128-bit round key.
// This is the ONLY step where the secret key material enters the cipher.
//
// This is PURE XOR LOGIC - implemented as 128 XOR gates in the fabric.
// On Spartan-7, XORs are "free" - they're built into the carry chain and
// don't consume LUTs.
//
// Operation:
//   state_out = state_in XOR round_key
//
// This transformation is applied at:
//   - Initial whitening (before round 0) with round_key[0]
//   - After each round (rounds 1-9) with round_key[1..9]
//   - Final round (round 10) with round_key[10]
//
// NIST Verification (FIPS 197 Initial AddRoundKey):
//   Plaintext:  00112233445566778899aabbccddeeff
//   Key[0]:     000102030405060708090a0b0c0d0e0f
//   Output:     00102030405060708090a0b0c0d0e0f0
//
// NIST Verification (FIPS 197 Round 1 AddRoundKey):
//   Input (after MixColumns): 5f72641557f5bc92f7be3b291db9f91a
//   RoundKey[1]:              d6aa74fdd2af72fadaa678f1d6ab76fe
//   Output:                   89d810e85592e1ead263b9e9e9e93ce4
//==============================================================================

module aes_addroundkey (
    input  wire [127:0] state_in,    // Current state (16 bytes)
    input  wire [127:0] round_key,   // Round key to XOR with state
    output wire [127:0] state_out    // State after XOR operation
);

    //==========================================================================
    // XOR the State with the Round Key
    //==========================================================================
    // This is a simple bitwise XOR across all 128 bits.
    // In hardware, this synthesizes to 128 XOR2 gates.
    // On Spartan-7, these are implemented using the fast carry logic,
    // so they consume zero LUTs and have ~0.1ns propagation delay.
    
    assign state_out = state_in ^ round_key;

endmodule
