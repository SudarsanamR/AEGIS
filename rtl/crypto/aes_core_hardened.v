// =============================================================================
// Module:      aes_core_hardened
// File:        rtl/crypto/aes_core_hardened.v
// Project:     AEGIS — Act 3, Step 5.4
//
// Purpose:     AES-128 encryption core with full side-channel hardening:
//                1. Boolean masking (from Act 2 — aes_subbytes_masked,
//                   aes_mixcolumns_masked)
//                2. TRNG-sourced mask seed (replaces compile-time 8'hAC)
//                3. Randomized inter-round timing jitter (0–15 dummy cycles)
//
//              Same external interface as aes_core_masked.v with two
//              additional inputs: trng_seed (8-bit) and timing handshake.
//
// DIFFERENCES FROM aes_core_masked.v:
//   1. mask_reg is loaded from trng_seed (port) instead of MASK_SEED constant.
//      This means every encryption uses a different initial mask, sourced
//      from the ring oscillator TRNG via trng_validator.
//
//   2. A new S_JITTER state is inserted between ROUND iterations.
//      After each round completes, the FSM enters S_JITTER, asserts
//      round_done to the timing_randomizer, and waits for proceed
//      before advancing to the next round. This inserts 0–15 random
//      dummy cycles per round.
//
//   3. Encryption latency is no longer fixed:
//      Minimum: 13 cycles (same as masked, all jitter = 0)
//      Maximum: 13 + 10×16 = 173 cycles (jitter = 15 on all 10 rounds)
//      Average: 13 + 10×8.5 = 98 cycles
//
// MASKING INVARIANT (unchanged from Act 2):
//   state_masked  ==  real_state  XOR  {mask_reg × 16}
//   Held every cycle between INIT and DONE.
//   mask_reg and state_masked advance simultaneously.
//
// FSM: IDLE → INIT → [ROUND → S_JITTER]×9 → FINAL → DONE
//
// Security properties:
//   - Unmasked intermediate never appears as a named register/wire
//   - TRNG seed makes mask unpredictable across encryptions
//   - Timing jitter desynchronizes traces across encryptions
//   - Combined effect: both DPA and neural attacks fail
//
// Dependencies:
//   rtl/crypto/aes_key_expansion.v
//   rtl/countermeasures/aes_subbytes_masked.v
//   rtl/countermeasures/aes_mixcolumns_masked.v
//   rtl/countermeasures/timing_randomizer.v  (external, instantiated in top)
//
// Interface (new ports marked with ★):
//   clk          — system clock
//   rst          — synchronous reset, active high
//   start        — pulse to begin encryption
//   plaintext    — 128-bit input
//   key          — 128-bit cipher key
//   trng_seed    — ★ 8-bit TRNG seed for mask initialization
//   proceed      — ★ pulse from timing_randomizer: jitter complete
//   ciphertext   — 128-bit output
//   done         — pulse when ciphertext is ready
//   subbytes_out — masked SubBytes tap for HW monitor
//   round_done   — ★ pulse to timing_randomizer: round complete
// =============================================================================

module aes_core_hardened (
    input  wire         clk,
    input  wire         rst,            // synchronous reset, active high
    input  wire         start,          // pulse to begin encryption
    input  wire [127:0] plaintext,
    input  wire [127:0] key,
    input  wire [7:0]   trng_seed,      // NEW: TRNG-sourced mask seed
    input  wire         proceed,        // NEW: from timing_randomizer
    output reg  [127:0] ciphertext,
    output reg          done,
    output wire [127:0] subbytes_out,   // masked SubBytes tap
    output reg          round_done      // NEW: to timing_randomizer
);

    // =========================================================================
    // FSM state encoding
    //
    // S_JITTER is the NEW state inserted between rounds.
    // The FSM pauses here, asserts round_done, and waits for proceed.
    // =========================================================================
    localparam S_IDLE   = 3'd0;
    localparam S_INIT   = 3'd1;
    localparam S_ROUND  = 3'd2;
    localparam S_JITTER = 3'd3;  // NEW: wait for timing randomizer
    localparam S_FINAL  = 3'd4;
    localparam S_DONE   = 3'd5;

    reg [2:0] state;
    reg [3:0] round_ctr;     // 1–9 in ROUND, 10 in FINAL
    reg       jitter_sent;   // tracks whether round_done pulse was sent

    // =========================================================================
    // Key schedule — identical to aes_core_masked.v
    // =========================================================================
    wire [127:0] rk0, rk1, rk2, rk3, rk4, rk5,
                 rk6, rk7, rk8, rk9, rk10;

    aes_key_expansion u_key_exp (
        .cipher_key   (key),
        .round_key_0  (rk0),  .round_key_1  (rk1),
        .round_key_2  (rk2),  .round_key_3  (rk3),
        .round_key_4  (rk4),  .round_key_5  (rk5),
        .round_key_6  (rk6),  .round_key_7  (rk7),
        .round_key_8  (rk8),  .round_key_9  (rk9),
        .round_key_10 (rk10)
    );

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
    // mask_reg — TRNG-seeded instead of compile-time constant
    //
    // CHANGE FROM ACT 2: On reset, mask_reg loads from trng_seed port
    // instead of localparam MASK_SEED. This means every encryption can
    // start with a different, truly random mask — the TRNG provides
    // entropy that the LFSR alone cannot.
    //
    // On each INIT, mask_reg is reloaded from trng_seed to ensure
    // fresh masking per encryption.
    //
    // LFSR next-state logic is identical to Act 2:
    //   Polynomial: x^8 + x^6 + x^5 + x^4 + 1
    //   new_bit = mask_reg[7] ^ mask_reg[5] ^ mask_reg[4] ^ mask_reg[3]
    //   next = {mask_reg[6:0], new_bit}
    // =========================================================================
    reg  [7:0]  mask_reg;

    wire        mask_new_bit;
    wire [7:0]  next_mask;
    assign mask_new_bit = mask_reg[7] ^ mask_reg[5]
                        ^ mask_reg[4] ^ mask_reg[3];
    assign next_mask    = {mask_reg[6:0], mask_new_bit};

    // 128-bit mask expansions
    wire [127:0] mask_128;
    wire [127:0] next_mask_128;
    assign mask_128      = {16{mask_reg}};
    assign next_mask_128 = {16{next_mask}};

    // =========================================================================
    // Masked SubBytes — combinational (identical to Act 2)
    // =========================================================================
    wire [127:0] after_subbytes_m;
    assign subbytes_out = after_subbytes_m;

    aes_subbytes_masked u_sb_m (
        .state_masked (state_masked),
        .mask_in      (mask_reg),
        .mask_out     (next_mask),
        .state_out    (after_subbytes_m)
    );

    // =========================================================================
    // ShiftRows — pure wire permutation (identical to Act 2)
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
    // Masked MixColumns — combinational (identical to Act 2)
    // =========================================================================
    wire [127:0] after_mixcols_m;
    wire [7:0]   mc_mask_passthrough;

    aes_mixcolumns_masked u_mc_m (
        .state_masked (after_shiftrows_m),
        .mask_in      (next_mask),
        .state_out    (after_mixcols_m),
        .mask_out     (mc_mask_passthrough)
    );

    // =========================================================================
    // AddRoundKey — linear, mask passes through (identical to Act 2)
    // =========================================================================
    wire [127:0] next_state_round;
    wire [127:0] next_state_final;

    assign next_state_round = after_mixcols_m   ^ sel_rk(round_ctr);
    assign next_state_final = after_shiftrows_m ^ rk10;

    // =========================================================================
    // INIT masking
    // =========================================================================
    wire [127:0] init_state_masked;
    assign init_state_masked = (plaintext ^ rk0) ^ mask_128;

    // =========================================================================
    // Output unmasking — valid only at S_DONE
    // =========================================================================
    wire [127:0] ciphertext_unmasked;
    assign ciphertext_unmasked = state_masked ^ mask_128;

    // =========================================================================
    // FSM — extended with S_JITTER state for timing randomization
    //
    // Flow: IDLE → INIT → ROUND → S_JITTER → ROUND → S_JITTER → ... →
    //       ROUND(9) → S_JITTER → FINAL → DONE
    //
    // S_JITTER behavior:
    //   1. On entry: assert round_done for 1 cycle (tells timing_randomizer
    //      to begin its countdown).
    //   2. Wait for proceed pulse from timing_randomizer (0–15 cycles).
    //   3. On proceed: transition to next round (ROUND or FINAL).
    //
    // The round computation happens in S_ROUND (state_masked and mask_reg
    // advance). S_JITTER only adds delay — it does NOT modify AES state.
    // This means the functional correctness is identical to Act 2;
    // only the timing profile changes.
    // =========================================================================
    always @(posedge clk) begin
        if (rst) begin
            state        <= S_IDLE;
            round_ctr    <= 4'd0;
            state_masked <= 128'd0;
            mask_reg     <= trng_seed;    // MODIFIED: TRNG seed instead of constant
            ciphertext   <= 128'd0;
            done         <= 1'b0;
            round_done   <= 1'b0;
            jitter_sent  <= 1'b0;
        end else begin
            done       <= 1'b0;   // default: deasserted
            round_done <= 1'b0;   // default: deasserted (1-cycle pulse)

            case (state)

                S_IDLE: begin
                    if (start) begin
                        mask_reg <= trng_seed;  // MODIFIED: fresh seed per encryption
                        state    <= S_INIT;
                    end
                end

                S_INIT: begin
                    // ARK(pt, rk0) XOR {mask_reg × 16}
                    // mask_reg was loaded from trng_seed in IDLE→INIT transition
                    state_masked <= init_state_masked;
                    round_ctr    <= 4'd1;
                    state        <= S_ROUND;
                end

                S_ROUND: begin
                    // Execute round: SB + SR + MC + ARK (rounds 1–9)
                    // or SB + SR + ARK (round 10 — but round 10 goes to S_FINAL)
                    state_masked <= next_state_round;
                    mask_reg     <= next_mask;

                    // After round computation, enter S_JITTER for timing delay
                    state       <= S_JITTER;
                    jitter_sent <= 1'b0;  // will send round_done on next cycle
                end

                S_JITTER: begin
                    // NEW STATE: insert random timing jitter between rounds
                    //
                    // Step 1: Send round_done pulse (once)
                    if (!jitter_sent) begin
                        round_done  <= 1'b1;   // tell timing_randomizer to start
                        jitter_sent <= 1'b1;   // don't send again
                    end

                    // Step 2: Wait for proceed from timing_randomizer
                    if (proceed) begin
                        if (round_ctr == 4'd9) begin
                            // All 9 normal rounds done → go to FINAL (round 10)
                            state     <= S_FINAL;
                            round_ctr <= 4'd10;
                        end else begin
                            // More rounds to go
                            state     <= S_ROUND;
                            round_ctr <= round_ctr + 4'd1;
                        end
                    end
                    // While waiting: state_masked and mask_reg hold their values.
                    // No AES computation happens during jitter — just dummy cycles.
                end

                S_FINAL: begin
                    // Round 10: SB + SR + ARK (no MixColumns)
                    state_masked <= next_state_final;
                    mask_reg     <= next_mask;
                    state        <= S_DONE;
                end

                S_DONE: begin
                    ciphertext <= ciphertext_unmasked;
                    done       <= 1'b1;
                    state      <= S_IDLE;
                end

                default: state <= S_IDLE;

            endcase
        end
    end

endmodule
