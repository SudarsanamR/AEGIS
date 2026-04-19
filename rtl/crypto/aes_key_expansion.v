`timescale 1ns / 1ps
//==============================================================================
// AES-128 Key Expansion
// AEGIS Project - ChipVerse '26
//==============================================================================
// Generates all 11 round keys (round_key[0] through round_key[10]) from
// the 128-bit cipher key using the AES key schedule algorithm.
//
// This is PURE COMBINATIONAL LOGIC - all 11 round keys are generated
// simultaneously from the input key. No clock, no state.
//
// Algorithm (FIPS 197 Section 5.2):
//   - Input: 4 words (W[0], W[1], W[2], W[3]) = 128-bit cipher key
//   - Output: 44 words (W[0] through W[43]) = 11 round keys
//
//   For i = 4 to 43:
//     if (i % 4 == 0):  // Every 4th word (start of new round key)
//       temp = SubWord(RotWord(W[i-1])) XOR Rcon[i/4]
//       W[i] = W[i-4] XOR temp
//     else:
//       W[i] = W[i-4] XOR W[i-1]
//
// Helper Functions:
//   - RotWord(word): Circular left shift by 1 byte
//       [a0, a1, a2, a3] -> [a1, a2, a3, a0]
//   - SubWord(word): Apply S-box to each byte
//       [a0, a1, a2, a3] -> [S(a0), S(a1), S(a2), S(a3)]
//   - Rcon[i]: Round constant (only affects leftmost byte)
//       Rcon[1]=01, Rcon[2]=02, Rcon[3]=04, Rcon[4]=08, Rcon[5]=10,
//       Rcon[6]=20, Rcon[7]=40, Rcon[8]=80, Rcon[9]=1B, Rcon[10]=36
//
// NIST Test Vector (FIPS 197 Appendix A.1):
//   Cipher Key: 000102030405060708090a0b0c0d0e0f
//
//   Round Key  0: 000102030405060708090a0b0c0d0e0f
//   Round Key  1: d6aa74fdd2af72fadaa678f1d6ab76fe
//   Round Key  2: b692cf0b643dbdf1be9bc5006830b3fe
//   Round Key  3: b6ff744ed2c2c9bf6c590cbf0469bf41
//   Round Key  4: 47f7f7bc95353e03f96c32bcfd058dfd
//   Round Key  5: 3caaa3e8a99f9deb50f3af57adf622aa
//   Round Key  6: 5e390f7df7a69296a7553dc10aa31f6b
//   Round Key  7: 14f9701ae35fe28c440adf4d4ea9c026
//   Round Key  8: 47438735a41c65b9e016baf4aebf7ad2
//   Round Key  9: 549932d1f08557681093ed9cbe2c974e
//   Round Key 10: 13111d7fe3944a17f307a78b4d2b30c5
//==============================================================================

module aes_key_expansion (
    input  wire [127:0] cipher_key,    // Input: 128-bit cipher key
    output wire [127:0] round_key_0,   // Round key  0 (initial whitening)
    output wire [127:0] round_key_1,   // Round key  1
    output wire [127:0] round_key_2,   // Round key  2
    output wire [127:0] round_key_3,   // Round key  3
    output wire [127:0] round_key_4,   // Round key  4
    output wire [127:0] round_key_5,   // Round key  5
    output wire [127:0] round_key_6,   // Round key  6
    output wire [127:0] round_key_7,   // Round key  7
    output wire [127:0] round_key_8,   // Round key  8
    output wire [127:0] round_key_9,   // Round key  9
    output wire [127:0] round_key_10   // Round key 10 (final round)
);

    //==========================================================================
    // AES S-box (Same as SubBytes)
    //==========================================================================
    // Used by SubWord function to substitute bytes during key expansion.
    
    function [7:0] sbox;
        input [7:0] in;
        begin
            case (in)
                8'h00: sbox = 8'h63; 8'h01: sbox = 8'h7c; 8'h02: sbox = 8'h77; 8'h03: sbox = 8'h7b;
                8'h04: sbox = 8'hf2; 8'h05: sbox = 8'h6b; 8'h06: sbox = 8'h6f; 8'h07: sbox = 8'hc5;
                8'h08: sbox = 8'h30; 8'h09: sbox = 8'h01; 8'h0a: sbox = 8'h67; 8'h0b: sbox = 8'h2b;
                8'h0c: sbox = 8'hfe; 8'h0d: sbox = 8'hd7; 8'h0e: sbox = 8'hab; 8'h0f: sbox = 8'h76;
                8'h10: sbox = 8'hca; 8'h11: sbox = 8'h82; 8'h12: sbox = 8'hc9; 8'h13: sbox = 8'h7d;
                8'h14: sbox = 8'hfa; 8'h15: sbox = 8'h59; 8'h16: sbox = 8'h47; 8'h17: sbox = 8'hf0;
                8'h18: sbox = 8'had; 8'h19: sbox = 8'hd4; 8'h1a: sbox = 8'ha2; 8'h1b: sbox = 8'haf;
                8'h1c: sbox = 8'h9c; 8'h1d: sbox = 8'ha4; 8'h1e: sbox = 8'h72; 8'h1f: sbox = 8'hc0;
                8'h20: sbox = 8'hb7; 8'h21: sbox = 8'hfd; 8'h22: sbox = 8'h93; 8'h23: sbox = 8'h26;
                8'h24: sbox = 8'h36; 8'h25: sbox = 8'h3f; 8'h26: sbox = 8'hf7; 8'h27: sbox = 8'hcc;
                8'h28: sbox = 8'h34; 8'h29: sbox = 8'ha5; 8'h2a: sbox = 8'he5; 8'h2b: sbox = 8'hf1;
                8'h2c: sbox = 8'h71; 8'h2d: sbox = 8'hd8; 8'h2e: sbox = 8'h31; 8'h2f: sbox = 8'h15;
                8'h30: sbox = 8'h04; 8'h31: sbox = 8'hc7; 8'h32: sbox = 8'h23; 8'h33: sbox = 8'hc3;
                8'h34: sbox = 8'h18; 8'h35: sbox = 8'h96; 8'h36: sbox = 8'h05; 8'h37: sbox = 8'h9a;
                8'h38: sbox = 8'h07; 8'h39: sbox = 8'h12; 8'h3a: sbox = 8'h80; 8'h3b: sbox = 8'he2;
                8'h3c: sbox = 8'heb; 8'h3d: sbox = 8'h27; 8'h3e: sbox = 8'hb2; 8'h3f: sbox = 8'h75;
                8'h40: sbox = 8'h09; 8'h41: sbox = 8'h83; 8'h42: sbox = 8'h2c; 8'h43: sbox = 8'h1a;
                8'h44: sbox = 8'h1b; 8'h45: sbox = 8'h6e; 8'h46: sbox = 8'h5a; 8'h47: sbox = 8'ha0;
                8'h48: sbox = 8'h52; 8'h49: sbox = 8'h3b; 8'h4a: sbox = 8'hd6; 8'h4b: sbox = 8'hb3;
                8'h4c: sbox = 8'h29; 8'h4d: sbox = 8'he3; 8'h4e: sbox = 8'h2f; 8'h4f: sbox = 8'h84;
                8'h50: sbox = 8'h53; 8'h51: sbox = 8'hd1; 8'h52: sbox = 8'h00; 8'h53: sbox = 8'hed;
                8'h54: sbox = 8'h20; 8'h55: sbox = 8'hfc; 8'h56: sbox = 8'hb1; 8'h57: sbox = 8'h5b;
                8'h58: sbox = 8'h6a; 8'h59: sbox = 8'hcb; 8'h5a: sbox = 8'hbe; 8'h5b: sbox = 8'h39;
                8'h5c: sbox = 8'h4a; 8'h5d: sbox = 8'h4c; 8'h5e: sbox = 8'h58; 8'h5f: sbox = 8'hcf;
                8'h60: sbox = 8'hd0; 8'h61: sbox = 8'hef; 8'h62: sbox = 8'haa; 8'h63: sbox = 8'hfb;
                8'h64: sbox = 8'h43; 8'h65: sbox = 8'h4d; 8'h66: sbox = 8'h33; 8'h67: sbox = 8'h85;
                8'h68: sbox = 8'h45; 8'h69: sbox = 8'hf9; 8'h6a: sbox = 8'h02; 8'h6b: sbox = 8'h7f;
                8'h6c: sbox = 8'h50; 8'h6d: sbox = 8'h3c; 8'h6e: sbox = 8'h9f; 8'h6f: sbox = 8'ha8;
                8'h70: sbox = 8'h51; 8'h71: sbox = 8'ha3; 8'h72: sbox = 8'h40; 8'h73: sbox = 8'h8f;
                8'h74: sbox = 8'h92; 8'h75: sbox = 8'h9d; 8'h76: sbox = 8'h38; 8'h77: sbox = 8'hf5;
                8'h78: sbox = 8'hbc; 8'h79: sbox = 8'hb6; 8'h7a: sbox = 8'hda; 8'h7b: sbox = 8'h21;
                8'h7c: sbox = 8'h10; 8'h7d: sbox = 8'hff; 8'h7e: sbox = 8'hf3; 8'h7f: sbox = 8'hd2;
                8'h80: sbox = 8'hcd; 8'h81: sbox = 8'h0c; 8'h82: sbox = 8'h13; 8'h83: sbox = 8'hec;
                8'h84: sbox = 8'h5f; 8'h85: sbox = 8'h97; 8'h86: sbox = 8'h44; 8'h87: sbox = 8'h17;
                8'h88: sbox = 8'hc4; 8'h89: sbox = 8'ha7; 8'h8a: sbox = 8'h7e; 8'h8b: sbox = 8'h3d;
                8'h8c: sbox = 8'h64; 8'h8d: sbox = 8'h5d; 8'h8e: sbox = 8'h19; 8'h8f: sbox = 8'h73;
                8'h90: sbox = 8'h60; 8'h91: sbox = 8'h81; 8'h92: sbox = 8'h4f; 8'h93: sbox = 8'hdc;
                8'h94: sbox = 8'h22; 8'h95: sbox = 8'h2a; 8'h96: sbox = 8'h90; 8'h97: sbox = 8'h88;
                8'h98: sbox = 8'h46; 8'h99: sbox = 8'hee; 8'h9a: sbox = 8'hb8; 8'h9b: sbox = 8'h14;
                8'h9c: sbox = 8'hde; 8'h9d: sbox = 8'h5e; 8'h9e: sbox = 8'h0b; 8'h9f: sbox = 8'hdb;
                8'ha0: sbox = 8'he0; 8'ha1: sbox = 8'h32; 8'ha2: sbox = 8'h3a; 8'ha3: sbox = 8'h0a;
                8'ha4: sbox = 8'h49; 8'ha5: sbox = 8'h06; 8'ha6: sbox = 8'h24; 8'ha7: sbox = 8'h5c;
                8'ha8: sbox = 8'hc2; 8'ha9: sbox = 8'hd3; 8'haa: sbox = 8'hac; 8'hab: sbox = 8'h62;
                8'hac: sbox = 8'h91; 8'had: sbox = 8'h95; 8'hae: sbox = 8'he4; 8'haf: sbox = 8'h79;
                8'hb0: sbox = 8'he7; 8'hb1: sbox = 8'hc8; 8'hb2: sbox = 8'h37; 8'hb3: sbox = 8'h6d;
                8'hb4: sbox = 8'h8d; 8'hb5: sbox = 8'hd5; 8'hb6: sbox = 8'h4e; 8'hb7: sbox = 8'ha9;
                8'hb8: sbox = 8'h6c; 8'hb9: sbox = 8'h56; 8'hba: sbox = 8'hf4; 8'hbb: sbox = 8'hea;
                8'hbc: sbox = 8'h65; 8'hbd: sbox = 8'h7a; 8'hbe: sbox = 8'hae; 8'hbf: sbox = 8'h08;
                8'hc0: sbox = 8'hba; 8'hc1: sbox = 8'h78; 8'hc2: sbox = 8'h25; 8'hc3: sbox = 8'h2e;
                8'hc4: sbox = 8'h1c; 8'hc5: sbox = 8'ha6; 8'hc6: sbox = 8'hb4; 8'hc7: sbox = 8'hc6;
                8'hc8: sbox = 8'he8; 8'hc9: sbox = 8'hdd; 8'hca: sbox = 8'h74; 8'hcb: sbox = 8'h1f;
                8'hcc: sbox = 8'h4b; 8'hcd: sbox = 8'hbd; 8'hce: sbox = 8'h8b; 8'hcf: sbox = 8'h8a;
                8'hd0: sbox = 8'h70; 8'hd1: sbox = 8'h3e; 8'hd2: sbox = 8'hb5; 8'hd3: sbox = 8'h66;
                8'hd4: sbox = 8'h48; 8'hd5: sbox = 8'h03; 8'hd6: sbox = 8'hf6; 8'hd7: sbox = 8'h0e;
                8'hd8: sbox = 8'h61; 8'hd9: sbox = 8'h35; 8'hda: sbox = 8'h57; 8'hdb: sbox = 8'hb9;
                8'hdc: sbox = 8'h86; 8'hdd: sbox = 8'hc1; 8'hde: sbox = 8'h1d; 8'hdf: sbox = 8'h9e;
                8'he0: sbox = 8'he1; 8'he1: sbox = 8'hf8; 8'he2: sbox = 8'h98; 8'he3: sbox = 8'h11;
                8'he4: sbox = 8'h69; 8'he5: sbox = 8'hd9; 8'he6: sbox = 8'h8e; 8'he7: sbox = 8'h94;
                8'he8: sbox = 8'h9b; 8'he9: sbox = 8'h1e; 8'hea: sbox = 8'h87; 8'heb: sbox = 8'he9;
                8'hec: sbox = 8'hce; 8'hed: sbox = 8'h55; 8'hee: sbox = 8'h28; 8'hef: sbox = 8'hdf;
                8'hf0: sbox = 8'h8c; 8'hf1: sbox = 8'ha1; 8'hf2: sbox = 8'h89; 8'hf3: sbox = 8'h0d;
                8'hf4: sbox = 8'hbf; 8'hf5: sbox = 8'he6; 8'hf6: sbox = 8'h42; 8'hf7: sbox = 8'h68;
                8'hf8: sbox = 8'h41; 8'hf9: sbox = 8'h99; 8'hfa: sbox = 8'h2d; 8'hfb: sbox = 8'h0f;
                8'hfc: sbox = 8'hb0; 8'hfd: sbox = 8'h54; 8'hfe: sbox = 8'hbb; 8'hff: sbox = 8'h16;
            endcase
        end
    endfunction

    //==========================================================================
    // Round Constants (Rcon)
    //==========================================================================
    // Used in the key expansion for rounds 1-10.
    // Rcon[i] = {RC[i], 0x00, 0x00, 0x00} where RC[i] = x^(i-1) in GF(2^8)
    
    function [31:0] rcon;
        input [3:0] round;
        begin
            case (round)
                4'd1:  rcon = 32'h01000000;
                4'd2:  rcon = 32'h02000000;
                4'd3:  rcon = 32'h04000000;
                4'd4:  rcon = 32'h08000000;
                4'd5:  rcon = 32'h10000000;
                4'd6:  rcon = 32'h20000000;
                4'd7:  rcon = 32'h40000000;
                4'd8:  rcon = 32'h80000000;
                4'd9:  rcon = 32'h1b000000;
                4'd10: rcon = 32'h36000000;
                default: rcon = 32'h00000000;
            endcase
        end
    endfunction

    //==========================================================================
    // Key Expansion Word Array
    //==========================================================================
    // AES-128 uses 44 words (W[0] through W[43]).
    // Each round key is 4 consecutive words (128 bits).
    // Word layout: [31:24]=byte0, [23:16]=byte1, [15:8]=byte2, [7:0]=byte3
    
    wire [31:0] w[0:43];  // 44 words for key expansion

    //==========================================================================
    // Initial 4 Words (W[0] - W[3]) = Cipher Key
    //==========================================================================
    // The first round key (round_key[0]) is the cipher key itself.
    // Split the 128-bit cipher key into 4 words.
    // NOTE: AES standard uses big-endian word ordering within the key.
    
    assign w[0] = cipher_key[127:96];  // First word  (leftmost 32 bits)
    assign w[1] = cipher_key[95:64];   // Second word
    assign w[2] = cipher_key[63:32];   // Third word
    assign w[3] = cipher_key[31:0];    // Fourth word (rightmost 32 bits)

    //==========================================================================
    // Key Expansion: Generate W[4] through W[43]
    //==========================================================================
    // For each word W[i] where i >= 4:
    //   if (i % 4 == 0):  // Start of new round key
    //     temp = SubWord(RotWord(W[i-1])) XOR Rcon[i/4]
    //     W[i] = W[i-4] XOR temp
    //   else:
    //     W[i] = W[i-4] XOR W[i-1]

    // Round 1: W[4], W[5], W[6], W[7]
    assign w[4] = w[0] ^ (subword(rotword(w[3])) ^ rcon(1));
    assign w[5] = w[1] ^ w[4];
    assign w[6] = w[2] ^ w[5];
    assign w[7] = w[3] ^ w[6];

    // Round 2: W[8], W[9], W[10], W[11]
    assign w[8]  = w[4] ^ (subword(rotword(w[7])) ^ rcon(2));
    assign w[9]  = w[5] ^ w[8];
    assign w[10] = w[6] ^ w[9];
    assign w[11] = w[7] ^ w[10];

    // Round 3: W[12], W[13], W[14], W[15]
    assign w[12] = w[8]  ^ (subword(rotword(w[11])) ^ rcon(3));
    assign w[13] = w[9]  ^ w[12];
    assign w[14] = w[10] ^ w[13];
    assign w[15] = w[11] ^ w[14];

    // Round 4: W[16], W[17], W[18], W[19]
    assign w[16] = w[12] ^ (subword(rotword(w[15])) ^ rcon(4));
    assign w[17] = w[13] ^ w[16];
    assign w[18] = w[14] ^ w[17];
    assign w[19] = w[15] ^ w[18];

    // Round 5: W[20], W[21], W[22], W[23]
    assign w[20] = w[16] ^ (subword(rotword(w[19])) ^ rcon(5));
    assign w[21] = w[17] ^ w[20];
    assign w[22] = w[18] ^ w[21];
    assign w[23] = w[19] ^ w[22];

    // Round 6: W[24], W[25], W[26], W[27]
    assign w[24] = w[20] ^ (subword(rotword(w[23])) ^ rcon(6));
    assign w[25] = w[21] ^ w[24];
    assign w[26] = w[22] ^ w[25];
    assign w[27] = w[23] ^ w[26];

    // Round 7: W[28], W[29], W[30], W[31]
    assign w[28] = w[24] ^ (subword(rotword(w[27])) ^ rcon(7));
    assign w[29] = w[25] ^ w[28];
    assign w[30] = w[26] ^ w[29];
    assign w[31] = w[27] ^ w[30];

    // Round 8: W[32], W[33], W[34], W[35]
    assign w[32] = w[28] ^ (subword(rotword(w[31])) ^ rcon(8));
    assign w[33] = w[29] ^ w[32];
    assign w[34] = w[30] ^ w[33];
    assign w[35] = w[31] ^ w[34];

    // Round 9: W[36], W[37], W[38], W[39]
    assign w[36] = w[32] ^ (subword(rotword(w[35])) ^ rcon(9));
    assign w[37] = w[33] ^ w[36];
    assign w[38] = w[34] ^ w[37];
    assign w[39] = w[35] ^ w[38];

    // Round 10: W[40], W[41], W[42], W[43]
    assign w[40] = w[36] ^ (subword(rotword(w[39])) ^ rcon(10));
    assign w[41] = w[37] ^ w[40];
    assign w[42] = w[38] ^ w[41];
    assign w[43] = w[39] ^ w[42];

    //==========================================================================
    // Helper Functions
    //==========================================================================

    // RotWord: Circular left shift by 1 byte
    // Input:  [a0, a1, a2, a3] (a0 in bits [31:24])
    // Output: [a1, a2, a3, a0]
    function [31:0] rotword;
        input [31:0] word;
        begin
            rotword = {word[23:0], word[31:24]};
        end
    endfunction

    // SubWord: Apply S-box to each byte of the word
    // Input:  [a0, a1, a2, a3]
    // Output: [S(a0), S(a1), S(a2), S(a3)]
    function [31:0] subword;
        input [31:0] word;
        begin
            subword = {sbox(word[31:24]), sbox(word[23:16]), 
                      sbox(word[15:8]),  sbox(word[7:0])};
        end
    endfunction

    //==========================================================================
    // Output Round Keys
    //==========================================================================
    // Each round key is 128 bits = 4 consecutive words.
    // Concatenate 4 words to form each round key.
    
    assign round_key_0  = {w[0],  w[1],  w[2],  w[3]};   // Round 0 (initial)
    assign round_key_1  = {w[4],  w[5],  w[6],  w[7]};   // Round 1
    assign round_key_2  = {w[8],  w[9],  w[10], w[11]};  // Round 2
    assign round_key_3  = {w[12], w[13], w[14], w[15]};  // Round 3
    assign round_key_4  = {w[16], w[17], w[18], w[19]};  // Round 4
    assign round_key_5  = {w[20], w[21], w[22], w[23]};  // Round 5
    assign round_key_6  = {w[24], w[25], w[26], w[27]};  // Round 6
    assign round_key_7  = {w[28], w[29], w[30], w[31]};  // Round 7
    assign round_key_8  = {w[32], w[33], w[34], w[35]};  // Round 8
    assign round_key_9  = {w[36], w[37], w[38], w[39]};  // Round 9
    assign round_key_10 = {w[40], w[41], w[42], w[43]};  // Round 10 (final)

endmodule
