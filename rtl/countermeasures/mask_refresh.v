// =============================================================================
// Module:      mask_refresh
// File:        rtl/countermeasures/mask_refresh.v
// Project:     AEGIS — Act 2, Step 4.3
//
// Purpose:     Provides a fresh 8-bit boolean mask on each enabled clock edge.
//              Used by aes_core_masked to advance the mask between AES rounds,
//              ensuring each round operates under a different mask value.
//
// Implementation: 8-bit Fibonacci LFSR
//   Polynomial:  x^8 + x^6 + x^5 + x^4 + 1
//   Taps (0-indexed from LSB): bits 7, 5, 4, 3
//   new_bit = lfsr[7] ^ lfsr[5] ^ lfsr[4] ^ lfsr[3]
//   Next state: {lfsr[6:0], new_bit}  (shift left, insert at bit 0)
//   Period:  255 (maximal-length — all non-zero 8-bit values visited)
//   Dead state: 8'h00 — the synchronous reset must never load this.
//              Seed 8'hAC is the default; the seed port is exposed for
//              the Act 3 TRNG to supply entropy.
//
// Usage in aes_core_masked:
//   - Assert enable for one clock cycle at each round boundary.
//   - mask_out is the mask to use for the *next* round.
//   - The core latches mask_out into its own mask register on the same edge.
//
// NOTE: In Act 3, the seed port is driven by ring_oscillator_trng.v.
//       In Act 2, seed is tied to 8'hAC at instantiation (deterministic).
//
// Interface:
//   clk      — 100 MHz system clock
//   rst      — synchronous reset, active high; loads seed into LFSR
//   seed     — 8-bit initial value (must be non-zero; caller responsibility)
//   enable   — advance LFSR by one step on rising edge when asserted
//   mask_out — current LFSR state (valid combinationally, registered on enable)
// =============================================================================

module mask_refresh (
    input  wire       clk,
    input  wire       rst,      // synchronous reset, active high
    input  wire [7:0] seed,     // LFSR seed — must be non-zero
    input  wire       enable,   // advance mask on rising edge
    output reg  [7:0] mask_out  // current mask value
);

    // =========================================================================
    // Fibonacci LFSR next-state logic
    //   Polynomial: x^8 + x^6 + x^5 + x^4 + 1
    //   new_bit is XOR of taps at bit positions 7, 5, 4, 3.
    //   The register shifts left and inserts new_bit at position 0.
    //   This produces a sequence of 255 unique non-zero bytes before repeating.
    // =========================================================================
    wire new_bit;
    assign new_bit = mask_out[7] ^ mask_out[5] ^ mask_out[4] ^ mask_out[3];

    // =========================================================================
    // Sequential: advance LFSR on enable; reload seed on reset.
    //   Synchronous reset per project hardware rules.
    //   The {mask_out[6:0], new_bit} expression is the one-cycle advance.
    // =========================================================================
    always @(posedge clk) begin
        if (rst) begin
            mask_out <= seed;   // reload — seed must be non-zero (caller ensures)
        end else if (enable) begin
            mask_out <= {mask_out[6:0], new_bit}; // shift left, new bit at LSB
        end
        // When enable=0 and rst=0: mask_out holds its current value.
        // This allows the AES core to use a stable mask throughout one round.
    end

endmodule
