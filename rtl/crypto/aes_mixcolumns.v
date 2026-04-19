`timescale 1ns / 1ps
//==============================================================================
// AES MixColumns Transformation
// AEGIS Project - ChipVerse '26
//==============================================================================
// Multiplies each column of the AES state by the MixColumns matrix in GF(2^8).
// This is pure combinational logic - no registers, no clock.
//
// MixColumns matrix (applied identically to each of the 4 columns):
//
//   [out0]   [2 3 1 1] [s0]
//   [out1] = [1 2 3 1] [s1]   (all arithmetic in GF(2^8))
//   [out2]   [1 1 2 3] [s2]
//   [out3]   [3 1 1 2] [s3]
//
// GF(2^8) irreducible polynomial: x^8 + x^4 + x^3 + x + 1  (0x11b)
//
// Key identities used:
//   xtime(a) = 2*a:
//     If a[7] == 1: {a[6:0], 1'b0} ^ 8'h1b   (shift + polynomial reduction)
//     If a[7] == 0: {a[6:0], 1'b0}            (shift only, no reduction)
//   3*a = xtime(a) ^ a                         (since 3 = 2+1 in GF)
//
// Expanded output equations (identical for all 4 columns):
//   out0 = t0 ^ t1 ^ s1 ^ s2 ^ s3   [= 2s0 ^ 3s1 ^ s2  ^ s3 ]
//   out1 = s0 ^ t1 ^ t2 ^ s2 ^ s3   [= s0  ^ 2s1 ^ 3s2 ^ s3 ]
//   out2 = s0 ^ s1 ^ t2 ^ t3 ^ s3   [= s0  ^ s1  ^ 2s2 ^ 3s3]
//   out3 = t0 ^ s0 ^ s1 ^ s2 ^ t3   [= 3s0 ^ s1  ^ s2  ^ 2s3]
//   where t_i = xtime(s_i)
//
// IMPLEMENTATION NOTE - xtime as inline ternary, not a function:
//   XSim (Vivado 2025.2) has a behavioral simulation issue where the
//   {8{a[7]}} replication inside a function call on a continuous assign
//   does not re-evaluate correctly on net-change events, causing xtime to
//   behave as identity (returning the input unchanged). Inlining the ternary
//   directly as a wire declaration is unambiguous in all Verilog simulators
//   and avoids the function call evaluation entirely.
//
// Column layout (column-major, within 128-bit state word):
//   Column 0: bits [127:96]   Column 2: bits [63:32]
//   Column 1: bits [95:64]    Column 3: bits [31:0]
//   Within each column: row0=[top 8 bits] ... row3=[bottom 8 bits]
//
// NIST Verification (FIPS 197 Round 1):
//   Input  (after ShiftRows):  6353e08c0960e104cd70b751bacad0e7
//   Output (after MixColumns): 5f72641557f5bc92f7be3b291db9f91a
//==============================================================================

module aes_mixcolumns (
    input  wire [127:0] state_in,   // Input state (4 columns, column-major)
    output wire [127:0] state_out   // Output state after MixColumns
);

    //==========================================================================
    // Column 0: state_in[127:96]
    //==========================================================================

    wire [7:0] c0_s0 = state_in[127:120];  // col0, row0
    wire [7:0] c0_s1 = state_in[119:112];  // col0, row1
    wire [7:0] c0_s2 = state_in[111:104];  // col0, row2
    wire [7:0] c0_s3 = state_in[103:96];   // col0, row3

    // xtime inline ternary: if MSB set, shift and XOR 0x1b (GF reduction);
    // if MSB clear, shift only. This models 2*s in GF(2^8).
    wire [7:0] c0_t0 = c0_s0[7] ? ({c0_s0[6:0], 1'b0} ^ 8'h1b) : {c0_s0[6:0], 1'b0};
    wire [7:0] c0_t1 = c0_s1[7] ? ({c0_s1[6:0], 1'b0} ^ 8'h1b) : {c0_s1[6:0], 1'b0};
    wire [7:0] c0_t2 = c0_s2[7] ? ({c0_s2[6:0], 1'b0} ^ 8'h1b) : {c0_s2[6:0], 1'b0};
    wire [7:0] c0_t3 = c0_s3[7] ? ({c0_s3[6:0], 1'b0} ^ 8'h1b) : {c0_s3[6:0], 1'b0};

    // MixColumns XOR tree: t_i = 2*s_i, so (t_i ^ s_i) = 3*s_i
    assign state_out[127:120] = c0_t0 ^ c0_t1 ^ c0_s1 ^ c0_s2 ^ c0_s3; // 2s0^3s1^s2^s3
    assign state_out[119:112] = c0_s0 ^ c0_t1 ^ c0_t2 ^ c0_s2 ^ c0_s3; // s0^2s1^3s2^s3
    assign state_out[111:104] = c0_s0 ^ c0_s1 ^ c0_t2 ^ c0_t3 ^ c0_s3; // s0^s1^2s2^3s3
    assign state_out[103:96]  = c0_t0 ^ c0_s0 ^ c0_s1 ^ c0_s2 ^ c0_t3; // 3s0^s1^s2^2s3

    //==========================================================================
    // Column 1: state_in[95:64]
    //==========================================================================

    wire [7:0] c1_s0 = state_in[95:88];
    wire [7:0] c1_s1 = state_in[87:80];
    wire [7:0] c1_s2 = state_in[79:72];
    wire [7:0] c1_s3 = state_in[71:64];

    wire [7:0] c1_t0 = c1_s0[7] ? ({c1_s0[6:0], 1'b0} ^ 8'h1b) : {c1_s0[6:0], 1'b0};
    wire [7:0] c1_t1 = c1_s1[7] ? ({c1_s1[6:0], 1'b0} ^ 8'h1b) : {c1_s1[6:0], 1'b0};
    wire [7:0] c1_t2 = c1_s2[7] ? ({c1_s2[6:0], 1'b0} ^ 8'h1b) : {c1_s2[6:0], 1'b0};
    wire [7:0] c1_t3 = c1_s3[7] ? ({c1_s3[6:0], 1'b0} ^ 8'h1b) : {c1_s3[6:0], 1'b0};

    assign state_out[95:88]  = c1_t0 ^ c1_t1 ^ c1_s1 ^ c1_s2 ^ c1_s3;
    assign state_out[87:80]  = c1_s0 ^ c1_t1 ^ c1_t2 ^ c1_s2 ^ c1_s3;
    assign state_out[79:72]  = c1_s0 ^ c1_s1 ^ c1_t2 ^ c1_t3 ^ c1_s3;
    assign state_out[71:64]  = c1_t0 ^ c1_s0 ^ c1_s1 ^ c1_s2 ^ c1_t3;

    //==========================================================================
    // Column 2: state_in[63:32]
    //==========================================================================

    wire [7:0] c2_s0 = state_in[63:56];
    wire [7:0] c2_s1 = state_in[55:48];
    wire [7:0] c2_s2 = state_in[47:40];
    wire [7:0] c2_s3 = state_in[39:32];

    wire [7:0] c2_t0 = c2_s0[7] ? ({c2_s0[6:0], 1'b0} ^ 8'h1b) : {c2_s0[6:0], 1'b0};
    wire [7:0] c2_t1 = c2_s1[7] ? ({c2_s1[6:0], 1'b0} ^ 8'h1b) : {c2_s1[6:0], 1'b0};
    wire [7:0] c2_t2 = c2_s2[7] ? ({c2_s2[6:0], 1'b0} ^ 8'h1b) : {c2_s2[6:0], 1'b0};
    wire [7:0] c2_t3 = c2_s3[7] ? ({c2_s3[6:0], 1'b0} ^ 8'h1b) : {c2_s3[6:0], 1'b0};

    assign state_out[63:56]  = c2_t0 ^ c2_t1 ^ c2_s1 ^ c2_s2 ^ c2_s3;
    assign state_out[55:48]  = c2_s0 ^ c2_t1 ^ c2_t2 ^ c2_s2 ^ c2_s3;
    assign state_out[47:40]  = c2_s0 ^ c2_s1 ^ c2_t2 ^ c2_t3 ^ c2_s3;
    assign state_out[39:32]  = c2_t0 ^ c2_s0 ^ c2_s1 ^ c2_s2 ^ c2_t3;

    //==========================================================================
    // Column 3: state_in[31:0]
    //==========================================================================

    wire [7:0] c3_s0 = state_in[31:24];
    wire [7:0] c3_s1 = state_in[23:16];
    wire [7:0] c3_s2 = state_in[15:8];
    wire [7:0] c3_s3 = state_in[7:0];

    wire [7:0] c3_t0 = c3_s0[7] ? ({c3_s0[6:0], 1'b0} ^ 8'h1b) : {c3_s0[6:0], 1'b0};
    wire [7:0] c3_t1 = c3_s1[7] ? ({c3_s1[6:0], 1'b0} ^ 8'h1b) : {c3_s1[6:0], 1'b0};
    wire [7:0] c3_t2 = c3_s2[7] ? ({c3_s2[6:0], 1'b0} ^ 8'h1b) : {c3_s2[6:0], 1'b0};
    wire [7:0] c3_t3 = c3_s3[7] ? ({c3_s3[6:0], 1'b0} ^ 8'h1b) : {c3_s3[6:0], 1'b0};

    assign state_out[31:24]  = c3_t0 ^ c3_t1 ^ c3_s1 ^ c3_s2 ^ c3_s3;
    assign state_out[23:16]  = c3_s0 ^ c3_t1 ^ c3_t2 ^ c3_s2 ^ c3_s3;
    assign state_out[15:8]   = c3_s0 ^ c3_s1 ^ c3_t2 ^ c3_t3 ^ c3_s3;
    assign state_out[7:0]    = c3_t0 ^ c3_s0 ^ c3_s1 ^ c3_s2 ^ c3_t3;

endmodule