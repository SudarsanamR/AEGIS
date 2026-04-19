// =============================================================================
// Module:      trng_validator
// File:        rtl/countermeasures/trng_validator.v
// Project:     AEGIS — Act 3, Step 5.2
//
// Purpose:     Validates the quality of ring_oscillator_trng output by
//              checking the ones ratio over a 10,000-bit window.
//              If the ratio falls outside 45%–55%, the TRNG is considered
//              compromised and entropy_valid is deasserted, which causes
//              the hardened AES core to halt (no encryption with bad entropy).
//
// Algorithm:
//   Batch-window approach (non-overlapping):
//     1. Collect 10,000 consecutive TRNG bits, counting the number of 1s.
//     2. After 10,000 bits: check if 4,500 ≤ ones_count ≤ 5,500.
//        - YES → entropy_valid = 1 (TRNG is healthy)
//        - NO  → entropy_valid = 0 (TRNG is compromised → AES halts)
//     3. Reset counters, repeat from step 1.
//
//   At the 1 MHz TRNG sampling rate, each validation window takes 10 ms.
//   The AES core can complete thousands of encryptions in 10 ms, so the
//   validation overhead is negligible.
//
// Architecture:
//
//   trng_bit ──┬──────────────────────────┐
//              │                          │
//   bit_valid ─┤  ┌────────────────┐      │
//              ├──┤  bit_counter   │      │
//              │  │  (0 to 9999)   │      │
//              │  └────────┬───────┘      │
//              │           │ window_done  │
//              │  ┌────────┴───────┐      │
//              └──┤  ones_counter  │      │
//                 │  (0 to 10000)  │      │
//                 └────────┬───────┘      │
//                          │              │
//                 ┌────────┴───────┐      │
//                 │  Range Check   │      │
//                 │ 4500 ≤ N ≤5500 │      │
//                 └────────┬───────┘      │
//                          │              │
//                   entropy_valid         │
//                                         │
//                   trng_bit_out ─────────┘ (passthrough)
//                   trng_valid_out ← bit_valid AND entropy_valid
//
// Initial State:
//   entropy_valid starts at 0 after reset. The AES core must wait for the
//   first 10,000-bit validation window to complete before encrypting.
//   This takes 10 ms at 1 MHz — imperceptible to the user.
//
// Passthrough ports:
//   trng_bit_out and trng_valid_out pass the TRNG output downstream,
//   but trng_valid_out is gated by entropy_valid. This ensures that
//   downstream consumers (mask_refresh, timing_randomizer) only receive
//   bits from a validated TRNG source.
//
// Resource Usage:
//   - bit_counter:  14-bit register (0–9999)
//   - ones_counter: 14-bit register (0–10000)
//   - entropy_valid: 1-bit register
//   - Comparators:  two 14-bit comparisons
//   Total: ~30 LUTs, ~30 FFs
//
// Interface:
//   clk            — 100 MHz system clock
//   rst            — synchronous reset, active high
//   bit_in         — raw TRNG bit from ring_oscillator_trng
//   bit_valid      — pulse from ring_oscillator_trng (1 MHz rate)
//   entropy_valid  — 1 if TRNG passes quality check, 0 otherwise
//   trng_bit_out   — passthrough of bit_in (for downstream use)
//   trng_valid_out — bit_valid gated by entropy_valid
// =============================================================================

module trng_validator (
    input  wire clk,
    input  wire rst,            // synchronous reset, active high
    input  wire bit_in,         // raw random bit from TRNG
    input  wire bit_valid,      // pulse when new bit available (1 MHz)
    output reg  entropy_valid,  // 1 = TRNG passes entropy test
    output wire trng_bit_out,   // passthrough of bit_in
    output wire trng_valid_out  // bit_valid gated by entropy_valid
);

    // =========================================================================
    // Constants
    //
    // WINDOW_SIZE = 10,000 bits per validation batch.
    // ONES_MIN = 4,500 (45% of 10,000) — lower bound for healthy TRNG.
    // ONES_MAX = 5,500 (55% of 10,000) — upper bound for healthy TRNG.
    //
    // WHY 45%–55%: An ideal random source produces 50% ones. The ±5%
    // tolerance accounts for statistical fluctuation in a 10,000-bit
    // sample. For a truly random source, the standard deviation is
    // sqrt(10000 × 0.5 × 0.5) = 50, so 4500–5500 is a ±10σ window —
    // essentially guaranteed to pass for a good source and fail for
    // a stuck-at or heavily biased source.
    // =========================================================================
    localparam WINDOW_SIZE = 14'd10000;
    localparam ONES_MIN    = 14'd4500;   // 45% of 10,000
    localparam ONES_MAX    = 14'd5500;   // 55% of 10,000

    // =========================================================================
    // Counters
    //
    // bit_counter: counts bits received in current window (0 to 9999).
    //              When it reaches 9999, the window is complete.
    // ones_counter: counts the number of 1-bits in the current window.
    // =========================================================================
    reg [13:0] bit_counter;    // 14 bits: range 0–9999
    reg [13:0] ones_counter;   // 14 bits: range 0–10000

    // Window complete when bit_counter has reached the last bit
    wire window_done;
    assign window_done = bit_valid & (bit_counter == (WINDOW_SIZE - 14'd1));

    // =========================================================================
    // Passthrough — TRNG output gated by entropy validity
    //
    // trng_bit_out: always mirrors bit_in (consumer decides when to sample).
    // trng_valid_out: only pulses when BOTH a new bit is available AND the
    //                 TRNG has passed its most recent validation window.
    //                 This prevents downstream modules from consuming
    //                 potentially biased bits.
    // =========================================================================
    assign trng_bit_out   = bit_in;
    assign trng_valid_out = bit_valid & entropy_valid;

    // =========================================================================
    // Main sequential logic
    //
    // On each valid TRNG bit:
    //   1. Increment bit_counter
    //   2. If bit is 1, increment ones_counter
    //   3. When window completes (bit_counter == 9999):
    //      a. Check ones_counter against [ONES_MIN, ONES_MAX]
    //      b. Update entropy_valid
    //      c. Reset both counters for the next window
    // =========================================================================
    always @(posedge clk) begin
        if (rst) begin
            bit_counter   <= 14'd0;
            ones_counter  <= 14'd0;
            entropy_valid <= 1'b0;  // invalid until first window passes
        end else if (bit_valid) begin
            if (window_done) begin
                // Window complete — include the final bit in ones_counter
                // before checking the range.
                //
                // ones_final = ones_counter + bit_in accounts for the
                // 10,000th bit that arrives on this cycle.
                if ((ones_counter + {13'd0, bit_in} >= ONES_MIN) &&
                    (ones_counter + {13'd0, bit_in} <= ONES_MAX)) begin
                    entropy_valid <= 1'b1;  // TRNG is healthy
                end else begin
                    entropy_valid <= 1'b0;  // TRNG is compromised
                end

                // Reset for next window
                bit_counter  <= 14'd0;
                ones_counter <= 14'd0;
            end else begin
                // Mid-window: count bits and ones
                bit_counter  <= bit_counter + 14'd1;
                ones_counter <= ones_counter + {13'd0, bit_in};
            end
        end
        // When bit_valid = 0: all registers hold their values.
    end

endmodule
