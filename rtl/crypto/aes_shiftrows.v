`timescale 1ns / 1ps
//==============================================================================
// AES ShiftRows Transformation
// AEGIS Project - ChipVerse '26
//==============================================================================
// Performs the AES ShiftRows step: cyclically shifts each row of the state
// matrix left by the row index (0, 1, 2, 3 byte positions).
//
// This is PURE WIRE ROUTING - zero logic gates, zero LUTs consumed.
// Synthesis will implement this as direct net connections only.
//
// AES State Matrix (column-major layout):
//
//           col0   col1   col2   col3
//   row0:  [127:120] [95:88] [63:56] [31:24]   <- shift left 0 (unchanged)
//   row1:  [119:112] [87:80] [55:48] [23:16]   <- shift left 1
//   row2:  [111:104] [79:72] [47:40] [15: 8]   <- shift left 2
//   row3:  [103: 96] [71:64] [39:32] [ 7: 0]   <- shift left 3
//
// ShiftRows result (reading input bytes into new column positions):
//
//           col0      col1      col2      col3
//   row0:   b[0]      b[4]      b[8]      b[12]   (unchanged)
//   row1:   b[5]      b[9]      b[13]     b[1]    (rotated left 1)
//   row2:   b[10]     b[14]     b[2]      b[6]    (rotated left 2)
//   row3:   b[15]     b[3]      b[7]      b[11]   (rotated left 3)
//
// NIST Verification (FIPS 197 Round 1):
//   Input  (SubBytes out): 63cab7040953d051cd60e0e7ba70e18c
//   Output (ShiftRows out): 6353e08c0960e104cd70b751bacad0e7
//==============================================================================

module aes_shiftrows (
    input  wire [127:0] state_in,   // Input state (16 bytes, column-major)
    output wire [127:0] state_out   // Output state after row shifts
);

    //==========================================================================
    // Row 0 - No Shift (bytes 0, 4, 8, 12 stay in their columns)
    //==========================================================================
    // b[0]  stays in col0 → out_byte0  = in_byte0
    // b[4]  stays in col1 → out_byte4  = in_byte4
    // b[8]  stays in col2 → out_byte8  = in_byte8
    // b[12] stays in col3 → out_byte12 = in_byte12
    assign state_out[127:120] = state_in[127:120]; // row0,col0 <- row0,col0 (b0)
    assign state_out[95:88]   = state_in[95:88];   // row0,col1 <- row0,col1 (b4)
    assign state_out[63:56]   = state_in[63:56];   // row0,col2 <- row0,col2 (b8)
    assign state_out[31:24]   = state_in[31:24];   // row0,col3 <- row0,col3 (b12)

    //==========================================================================
    // Row 1 - Shift Left by 1 Byte
    //==========================================================================
    // Original row1: [b1, b5, b9, b13] at cols [0,1,2,3]
    // After shift:   [b5, b9, b13, b1] at cols [0,1,2,3]
    // WHY: "shift left 1" means the element at col1 moves to col0,
    //      col2 moves to col1, col3 moves to col2, col0 wraps to col3.
    assign state_out[119:112] = state_in[87:80];   // row1,col0 <- row1,col1 (b5)
    assign state_out[87:80]   = state_in[55:48];   // row1,col1 <- row1,col2 (b9)
    assign state_out[55:48]   = state_in[23:16];   // row1,col2 <- row1,col3 (b13)
    assign state_out[23:16]   = state_in[119:112]; // row1,col3 <- row1,col0 (b1) wrap

    //==========================================================================
    // Row 2 - Shift Left by 2 Bytes
    //==========================================================================
    // Original row2: [b2, b6, b10, b14] at cols [0,1,2,3]
    // After shift:   [b10, b14, b2, b6] at cols [0,1,2,3]
    // WHY: shift by 2 is equivalent to swapping the two 16-bit halves of the row.
    assign state_out[111:104] = state_in[47:40];   // row2,col0 <- row2,col2 (b10)
    assign state_out[79:72]   = state_in[15:8];    // row2,col1 <- row2,col3 (b14)
    assign state_out[47:40]   = state_in[111:104]; // row2,col2 <- row2,col0 (b2) wrap
    assign state_out[15:8]    = state_in[79:72];   // row2,col3 <- row2,col1 (b6) wrap

    //==========================================================================
    // Row 3 - Shift Left by 3 Bytes (= Shift Right by 1 Byte)
    //==========================================================================
    // Original row3: [b3, b7, b11, b15] at cols [0,1,2,3]
    // After shift:   [b15, b3, b7, b11] at cols [0,1,2,3]
    // WHY: left-3 wraps three elements, which is the same as moving the last
    //      element to the front. Simplest to see as a right-rotate-by-1.
    assign state_out[103:96]  = state_in[7:0];     // row3,col0 <- row3,col3 (b15) wrap
    assign state_out[71:64]   = state_in[103:96];  // row3,col1 <- row3,col0 (b3)
    assign state_out[39:32]   = state_in[71:64];   // row3,col2 <- row3,col1 (b7)
    assign state_out[7:0]     = state_in[39:32];   // row3,col3 <- row3,col2 (b11)

endmodule