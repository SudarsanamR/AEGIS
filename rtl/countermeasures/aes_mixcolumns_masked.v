// =============================================================================
// Module:      aes_mixcolumns_masked
// File:        rtl/countermeasures/aes_mixcolumns_masked.v
// Project:     AEGIS — Act 2, Step 4.2
//
// Purpose:     Boolean-masked MixColumns transformation.
//
// Security argument — MixColumns linearity over GF(2^8):
//
//   MC(state ⊕ mask) = MC(state) ⊕ MC(mask)          [linearity]
//   MC({m,m,m,m})    = {m,m,m,m}  for any byte m      [fixed-point property]
//
//   Proof of fixed-point:
//     MC row 0: 2m ⊕ 3m ⊕ m ⊕ m
//             = (2⊕3⊕1⊕1)·m  in GF(2^8)
//             = 1·m = m       because 2⊕3=1, 1⊕1=0, total=1
//     All four rows of the MixColumns matrix have the same coefficient
//     sum = 1, so every output byte equals m.
//     Python sweep over all 256 values confirms this (see Step 4.2 notes).
//
//   Therefore:
//     MC(state_masked)  =  MC(real_state ⊕ {m,...,m})
//                       =  MC(real_state) ⊕ MC({m,...,m})
//                       =  MC(real_state) ⊕ {m,...,m}
//
//   The output is automatically masked with the *same* mask m.
//   mask_out = mask_in.  No separate mask-propagation logic is needed.
//
//   This means: there is NO point in this module where the unmasked
//   state appears, even combinationally.  MixColumns never sees real_state.
//   This is fundamentally stronger protection than masked SubBytes.
//
// Interface:
//   state_masked [127:0] — input,  real_state ⊕ {mask_in × 16}
//   mask_in      [7:0]   — input,  current boolean mask byte
//   state_out    [127:0] — output, MC(real_state) ⊕ {mask_in × 16}
//   mask_out     [7:0]   — output, = mask_in (passthrough, proven above)
//
// Bit ordering: column-major per project convention.
//   Col k occupies bits [127-32k : 96-32k].
//   Within a column: row0=bits[31:24], row1=[23:16], row2=[15:8], row3=[7:0].
//
// Purely combinational — no clock or reset ports.
// =============================================================================

module aes_mixcolumns_masked (
    input  wire [127:0] state_masked,  // state XOR mask_in on every byte
    input  wire [7:0]   mask_in,       // current boolean mask
    output wire [127:0] state_out,     // MC(state) XOR mask_in (same mask)
    output wire [7:0]   mask_out       // = mask_in, unchanged through MC
);

    // =========================================================================
    // mask_out: passthrough, proven by MC fixed-point property above.
    // =========================================================================
    assign mask_out = mask_in; // MC({m,m,m,m}) = {m,m,m,m}  → mask unchanged

    // =========================================================================
    // GF(2^8) helper: multiply by 2 (xtime)
    //   AES irreducible polynomial: x^8 + x^4 + x^3 + x + 1  (0x11b)
    //   If MSB=1, shift left and XOR with 0x1b (low 8 bits of 0x11b).
    //   If MSB=0, shift left only.
    // =========================================================================
    function automatic [7:0] xtime;
        input [7:0] b;
        // Ternary: if b[7] set, reduce; otherwise plain shift.
        xtime = b[7] ? ((b << 1) ^ 8'h1b) : (b << 1);
    endfunction

    // =========================================================================
    // MixColumns on one 32-bit column.
    //
    // AES MixColumns matrix (rows applied to column [b0,b1,b2,b3]):
    //   out0 = 2·b0 ⊕ 3·b1 ⊕ b2   ⊕ b3
    //   out1 = b0   ⊕ 2·b1 ⊕ 3·b2 ⊕ b3
    //   out2 = b0   ⊕ b1   ⊕ 2·b2 ⊕ 3·b3
    //   out3 = 3·b0 ⊕ b1   ⊕ b2   ⊕ 2·b3
    //
    // Note: 3·x = 2·x ⊕ x  (no separate GF multiply table needed).
    //
    // This function is identical to the one in aes_mixcolumns.v (Act 1).
    // Duplication is intentional: this module must be self-contained so that
    // the countermeasures/ directory does not depend on rtl/crypto/ at
    // instantiation time. Vivado elaboration order can vary.
    // =========================================================================
    function automatic [31:0] mix_col;
        input [31:0] col; // {row0[7:0], row1[7:0], row2[7:0], row3[7:0]}
        reg [7:0] b0, b1, b2, b3;
        reg [7:0] x0, x1, x2, x3; // xtime of each byte
        begin
            b0 = col[31:24];
            b1 = col[23:16];
            b2 = col[15: 8];
            b3 = col[ 7: 0];

            x0 = xtime(b0); // 2·b0
            x1 = xtime(b1); // 2·b1
            x2 = xtime(b2); // 2·b2
            x3 = xtime(b3); // 2·b3

            // 3·b = 2·b ⊕ b = xtime(b) ⊕ b
            mix_col[31:24] = x0 ^ (x1^b1) ^ b2       ^ b3;       // 2b0⊕3b1⊕b2⊕b3
            mix_col[23:16] = b0  ^ x1      ^ (x2^b2)  ^ b3;       // b0⊕2b1⊕3b2⊕b3
            mix_col[15: 8] = b0  ^ b1      ^ x2        ^ (x3^b3);  // b0⊕b1⊕2b2⊕3b3
            mix_col[ 7: 0] = (x0^b0) ^ b1  ^ b2        ^ x3;       // 3b0⊕b1⊕b2⊕2b3
        end
    endfunction

    // =========================================================================
    // Apply mix_col to all four columns of state_masked.
    //
    // Because MC is linear: mix_col(state_masked_col) = mix_col(real_col) ⊕ m
    // The unmasked state is never computed — the mask is implicit in the data.
    // =========================================================================

    // Column 0: bits [127:96]
    assign state_out[127:96] = mix_col(state_masked[127:96]);

    // Column 1: bits [95:64]
    assign state_out[ 95:64] = mix_col(state_masked[ 95:64]);

    // Column 2: bits [63:32]
    assign state_out[ 63:32] = mix_col(state_masked[ 63:32]);

    // Column 3: bits [31:0]
    assign state_out[ 31: 0] = mix_col(state_masked[ 31: 0]);

endmodule
