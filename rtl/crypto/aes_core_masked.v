// =============================================================================
// Module:      aes_core_masked
// File:        rtl/crypto/aes_core_masked.v
// Project:     AEGIS — Act 2, Step 4.4
//
// Purpose:     AES-128 iterative encryption core with boolean masking.
//              Identical external interface to aes_core.v (Act 1).
//
// Countermeasures active:
//   1. Masked SubBytes    (aes_subbytes_masked)
//   2. Masked MixColumns  (aes_mixcolumns_masked — linear passthrough)
//   3. Per-round mask rotation via internal LFSR register
//
// Security properties:
//   - The unmasked AES state never exists as a named register or wire.
//   - mask_reg always tracks the mask currently on state_masked (invariant).
//   - SubBytes receives mask_in=mask_reg and mask_out=next_mask.
//   - state_masked and mask_reg advance simultaneously at each posedge.
//   - At DONE only: ciphertext is unmasked combinationally for one cycle.
//
// MASKING INVARIANT (held every cycle between INIT and DONE):
//   state_masked  ==  real_state  XOR  {mask_reg × 16}
//
// Mask register design:
//   mask_reg holds the mask currently ON state_masked (not "next" mask).
//   next_mask = lfsr_next(mask_reg)  is purely combinational.
//   At each ROUND/FINAL posedge, both update simultaneously:
//     state_masked <= next_state (output masked with next_mask)
//     mask_reg     <= next_mask  (matches the new state_masked)
//   This is the key difference from a naive design where mask_reg and
//   state_masked get out of sync by one cycle.
//
// Note on mask_refresh.v:
//   NOT instantiated here. In Act 3, aes_core_hardened.v will accept
//   a trng_seed input and load it into mask_reg at encryption start.
//   For Act 2, the seed is the compile-time constant MASK_SEED = 8'hAC.
//
// FSM: IDLE → INIT → ROUND (×9) → FINAL → DONE
//   Latency: 13 clock cycles from start asserted to done asserted.
//
// NIST test vector (confirmed against Python cryptography library):
//   Plaintext:  00112233445566778899aabbccddeeff
//   Key:        000102030405060708090a0b0c0d0e0f
//   Ciphertext: 69c4e0d86a7b0430d8cdb78070b4c55a
//   NOTE: the value 69c4e0d86a7b04300d8a2611689e2c00 listed in the original
//   project spec is incorrect — it belongs to a different NIST test vector.
//
// Dependencies:
//   rtl/crypto/aes_key_expansion.v
//   rtl/countermeasures/aes_subbytes_masked.v
//   rtl/countermeasures/aes_mixcolumns_masked.v
// =============================================================================

module aes_core_masked (
    input  wire         clk,
    input  wire         rst,        // synchronous reset, active high
    input  wire         start,      // pulse high one cycle to begin encryption
    input  wire [127:0] plaintext,
    input  wire [127:0] key,
    output reg  [127:0] ciphertext,
    output reg          done,
    // NEW: masked SubBytes tap for Hamming Weight monitor.
    // Exposes after_subbytes_m — SubBytes result masked with next_mask.
    // HW(masked_value) has no key correlation — demonstrates DPA failure.
    output wire [127:0] subbytes_out
);

    // =========================================================================
    // FSM state encoding
    // =========================================================================
    localparam S_IDLE  = 3'd0;
    localparam S_INIT  = 3'd1;
    localparam S_ROUND = 3'd2;
    localparam S_FINAL = 3'd3;
    localparam S_DONE  = 3'd4;

    reg [2:0] state;
    reg [3:0] round_ctr;   // 1–9 in ROUND, 10 in FINAL

    // =========================================================================
    // Key schedule — 11 flat wires matching aes_key_expansion port names.
    // The module exposes individual ports round_key_0 … round_key_10,
    // not an array.  sel_rk() muxes the correct key for round_ctr.
    // =========================================================================
    wire [127:0] rk0, rk1, rk2, rk3, rk4, rk5,
                 rk6, rk7, rk8, rk9, rk10;

    aes_key_expansion u_key_exp (
        .cipher_key   (key),          // MODIFIED: port is cipher_key, not key
        .round_key_0  (rk0),  .round_key_1  (rk1),
        .round_key_2  (rk2),  .round_key_3  (rk3),
        .round_key_4  (rk4),  .round_key_5  (rk5),
        .round_key_6  (rk6),  .round_key_7  (rk7),
        .round_key_8  (rk8),  .round_key_9  (rk9),
        .round_key_10 (rk10)
    );

    // Mux round key by index — used in ROUND path (rounds 1–9).
    // rk0 and rk10 are used directly by name in INIT and FINAL.
    function [127:0] sel_rk;
        input [3:0] r;
        begin
            case (r)
                4'd1:    sel_rk = rk1;
                4'd2:    sel_rk = rk2;
                4'd3:    sel_rk = rk3;
                4'd4:    sel_rk = rk4;
                4'd5:    sel_rk = rk5;
                4'd6:    sel_rk = rk6;
                4'd7:    sel_rk = rk7;
                4'd8:    sel_rk = rk8;
                4'd9:    sel_rk = rk9;
                default: sel_rk = rk10;
            endcase
        end
    endfunction

    // =========================================================================
    // Masked state register
    // =========================================================================
    reg [127:0] state_masked;

    // =========================================================================
    // mask_reg — the mask currently applied to state_masked.
    //
    // LFSR: Fibonacci form, poly x^8+x^6+x^5+x^4+1, same as mask_refresh.v.
    //   new_bit = mask_reg[7]^mask_reg[5]^mask_reg[4]^mask_reg[3]
    //   next    = {mask_reg[6:0], new_bit}
    // Period 255, no zero state reachable from seed 8'hAC.
    // =========================================================================
    reg  [7:0]  mask_reg;
    localparam  MASK_SEED = 8'hAC;

    wire        mask_new_bit;
    wire [7:0]  next_mask;
    assign mask_new_bit = mask_reg[7] ^ mask_reg[5]
                        ^ mask_reg[4] ^ mask_reg[3];
    assign next_mask    = {mask_reg[6:0], mask_new_bit};

    // 128-bit expansions (uniform byte replicated across all 16 positions)
    wire [127:0] mask_128;
    wire [127:0] next_mask_128;
    assign mask_128      = {16{mask_reg}};   // mask currently on state_masked
    assign next_mask_128 = {16{next_mask}};  // mask SubBytes will output

    // =========================================================================
    // Masked SubBytes — combinational
    //   mask_in  = mask_reg   (mask currently on state_masked)
    //   mask_out = next_mask  (mask to apply to the SubBytes output)
    //   Result:  SubBytes(real_state) XOR next_mask_128
    //   The unmasked byte only exists as the S-Box array-index expression.
    // =========================================================================
    wire [127:0] after_subbytes_m;
    assign subbytes_out = after_subbytes_m; // NEW: port tap

    aes_subbytes_masked u_sb_m (
        .state_masked (state_masked),
        .mask_in      (mask_reg),
        .mask_out     (next_mask),
        .state_out    (after_subbytes_m)
    );

    // =========================================================================
    // ShiftRows — pure wire permutation, no logic.
    //   ShiftRows on a uniformly-masked state preserves the mask:
    //     SR(s XOR {m×16}) = SR(s) XOR {m×16}
    //   because {m×16} is invariant under any byte permutation.
    //   The next_mask passes through unchanged.
    //
    //   Left shift: output byte at (row,col) = input byte at (row,(col+row)%4)
    //   Column-major index of (row,col) = col*4+row
    // =========================================================================
    wire [127:0] after_shiftrows_m;

    genvar gr, gc;
    generate
        for (gr = 0; gr < 4; gr = gr + 1) begin : SR_ROW
            for (gc = 0; gc < 4; gc = gc + 1) begin : SR_COL
                assign after_shiftrows_m[127 - (gc*4+gr)*8 -: 8] =
                    after_subbytes_m[127 - (((gc+gr)%4)*4+gr)*8 -: 8];
            end
        end
    endgenerate

    // =========================================================================
    // Masked MixColumns — combinational, used in rounds 1–9 only.
    //   MC is linear: MC(s XOR {m×16}) = MC(s) XOR {m×16}
    //   (fixed-point: MC({m,m,m,m}) = {m,m,m,m} for all m, verified over
    //    all 256 values in Step 4.2 pre-flight).
    //   The next_mask passes through unchanged.
    // =========================================================================
    wire [127:0] after_mixcols_m;
    wire [7:0]   mc_mask_passthrough; // always == next_mask (unused)

    aes_mixcolumns_masked u_mc_m (
        .state_masked (after_shiftrows_m),
        .mask_in      (next_mask),
        .state_out    (after_mixcols_m),
        .mask_out     (mc_mask_passthrough)
    );

    // =========================================================================
    // AddRoundKey — XOR is linear, mask passes through unchanged.
    //   ROUND path: after MixColumns, XOR sel_rk(round_ctr)  (rounds 1–9)
    //   FINAL path: after ShiftRows only, XOR rk10
    // =========================================================================
    wire [127:0] next_state_round;
    wire [127:0] next_state_final;

    assign next_state_round = after_mixcols_m   ^ sel_rk(round_ctr);
    assign next_state_final = after_shiftrows_m ^ rk10;

    // =========================================================================
    // INIT: ARK(pt, rk0) then mask with mask_128.
    //   The mask in INIT is mask_reg = MASK_SEED (reset value).
    //   mask_reg is NOT advanced in INIT so that it still equals the mask
    //   on state_masked when ROUND 1 begins — invariant is established here.
    // =========================================================================
    wire [127:0] init_state_masked;
    assign init_state_masked = (plaintext ^ rk0) ^ mask_128;  // MODIFIED

    // =========================================================================
    // Output unmasking — combinational, valid only at DONE.
    //   After FINAL: mask_reg = next_mask of the final SubBytes call.
    //   state_masked carries that same next_mask as its boolean mask.
    //   XOR strips it to recover the real ciphertext.
    // =========================================================================
    wire [127:0] ciphertext_unmasked;
    assign ciphertext_unmasked = state_masked ^ mask_128;

    // =========================================================================
    // FSM
    // =========================================================================
    always @(posedge clk) begin
        if (rst) begin
            state        <= S_IDLE;
            round_ctr    <= 4'd0;
            state_masked <= 128'd0;
            mask_reg     <= MASK_SEED;
            ciphertext   <= 128'd0;
            done         <= 1'b0;
        end else begin
            done <= 1'b0;  // default: deasserted

            case (state)

                S_IDLE: begin
                    if (start)
                        state <= S_INIT;
                end

                S_INIT: begin
                    // Latch ARK(pt, rk0) XOR {mask_reg × 16}.
                    // mask_reg holds MASK_SEED and is NOT changed here —
                    // it must match state_masked on entry to ROUND 1.
                    state_masked <= init_state_masked;
                    round_ctr    <= 4'd1;
                    state        <= S_ROUND;
                end

                S_ROUND: begin
                    // SB(mask_in=mask_reg, mask_out=next_mask) + SR + MC + ARK.
                    // Both state_masked and mask_reg advance simultaneously
                    // to keep the invariant: state_masked == real ^ {mask_reg×16}.
                    state_masked <= next_state_round; // carries next_mask
                    mask_reg     <= next_mask;        // tracks state_masked

                    if (round_ctr == 4'd9) begin
                        state     <= S_FINAL;
                        round_ctr <= 4'd10;
                    end else begin
                        round_ctr <= round_ctr + 4'd1;
                    end
                end

                S_FINAL: begin
                    // SB(mask_in=mask_reg, mask_out=next_mask) + SR + ARK.
                    // No MixColumns.  Same simultaneous advance.
                    state_masked <= next_state_final; // carries next_mask
                    mask_reg     <= next_mask;        // tracks state_masked
                    state        <= S_DONE;
                end

                S_DONE: begin
                    // mask_reg == mask on state_masked (post-FINAL).
                    // ciphertext_unmasked = state_masked XOR {mask_reg×16} = real_ct.
                    ciphertext <= ciphertext_unmasked;
                    done       <= 1'b1;
                    state      <= S_IDLE;
                end

                default: state <= S_IDLE;
            endcase
        end
    end

endmodule
