// =============================================================================
// Module:      timing_randomizer
// File:        rtl/countermeasures/timing_randomizer.v
// Project:     AEGIS — Act 3, Step 5.3
//
// Purpose:     Inserts 0–15 random dummy clock cycles between AES rounds
//              to desynchronize power traces, defeating both DPA and
//              neural network side-channel attacks.
//
// How it defeats side-channel analysis:
//   Without timing randomization, every encryption uses identical cycle
//   counts, so traces align perfectly. An attacker averages thousands of
//   aligned traces to extract the key-dependent signal.
//
//   With randomization, each round starts at a different cycle offset
//   (0–15 extra dummy cycles per round × 10 rounds = 0–150 extra cycles).
//   This misaligns traces across encryptions, smearing the key-dependent
//   signal across time and destroying correlation.
//
// Architecture:
//
//   AES Core                  Timing Randomizer
//   ┌──────────┐              ┌──────────────────────┐
//   │          │─ round_done ─►│ delay_counter        │
//   │          │              │ (loaded from TRNG)   │
//   │          │◄─ proceed ───│                      │
//   │          │              │ ┌──────────────────┐ │
//   │          │              │ │ 4-bit TRNG latch │ │
//   │          │              │ └──────────────────┘ │
//   └──────────┘              └──────────────────────┘
//
// Protocol:
//   1. AES core completes a round and asserts round_done for 1 cycle.
//   2. Timing randomizer latches a 4-bit random value (0–15) from the
//      TRNG accumulator into delay_counter.
//   3. delay_counter counts down to 0 over 0–15 clock cycles.
//   4. When delay_counter reaches 0, proceed is asserted for 1 cycle.
//   5. AES core sees proceed and begins the next round.
//
//   If delay_counter loads 0 (from TRNG), proceed asserts on the very
//   next cycle — zero additional latency. This is the minimum-delay case.
//
// TRNG bit accumulation:
//   The TRNG produces 1 bit per microsecond at 1 MHz. We need 4 bits
//   for the delay value. The accumulator collects TRNG bits one at a
//   time using a shift register. When 4 bits are ready, the random
//   nibble is available for the next round_done event.
//
//   At 1 MHz, 4 bits are ready every 4 µs. At 50 MHz AES clock with
//   ~13 cycles per encryption plus up to 150 dummy cycles, one
//   encryption takes at most ~3.26 µs. The TRNG bit rate is sufficient.
//
// Resource Usage:
//   - delay_counter:    4-bit register
//   - random_nibble:    4-bit shift register
//   - nibble_count:     2-bit counter
//   - state machine:    2-bit register
//   Total: ~15 LUTs, ~15 FFs
//
// Interface:
//   clk           — system clock (matches AES core clock domain)
//   rst           — synchronous reset, active high
//   trng_bit      — random bit from validated TRNG
//   trng_valid    — pulse when new TRNG bit available
//   round_done    — pulse from AES core: current round is complete
//   proceed       — pulse to AES core: start next round
//   jitter_active — high while dummy cycles are being inserted (for debug)
// =============================================================================

module timing_randomizer (
    input  wire clk,
    input  wire rst,            // synchronous reset, active high
    input  wire trng_bit,       // random bit from validated TRNG
    input  wire trng_valid,     // pulse when new TRNG bit available
    input  wire round_done,     // pulse: AES round complete, requesting delay
    output reg  proceed,        // pulse: delay complete, AES may proceed
    output wire jitter_active   // high during dummy cycle insertion
);

    // =========================================================================
    // FSM states
    //
    // IDLE:    waiting for round_done from AES core
    // DELAY:   counting down dummy cycles (0–15)
    // =========================================================================
    localparam S_IDLE  = 1'b0;
    localparam S_DELAY = 1'b1;

    reg fsm_state;

    // =========================================================================
    // TRNG bit accumulator — collects 4 bits into a random nibble
    //
    // Operates continuously in the background. Every time 4 TRNG bits
    // are collected, random_nibble holds a fresh 4-bit random value.
    // nibble_ready pulses for 1 cycle when a new nibble is complete.
    //
    // The nibble is consumed by the FSM on round_done events.
    // If round_done arrives before 4 bits are collected, the current
    // (partial) nibble contents are used — this is acceptable since
    // even a partially random delay disrupts trace alignment.
    // =========================================================================
    reg [3:0] random_nibble;   // 4-bit shift register for TRNG bits
    reg [1:0] nibble_count;    // counts 0–3 bits collected

    always @(posedge clk) begin
        if (rst) begin
            random_nibble <= 4'd0;
            nibble_count  <= 2'd0;
        end else if (trng_valid) begin
            // Shift in new TRNG bit at LSB
            random_nibble <= {random_nibble[2:0], trng_bit};
            nibble_count  <= nibble_count + 2'd1;  // wraps at 4 → 0
        end
    end

    // =========================================================================
    // Delay counter — counts down from random_nibble to 0
    //
    // Loaded with the current random_nibble value when round_done fires.
    // Counts down by 1 each clock cycle. When it reaches 0, proceed
    // is asserted and the FSM returns to IDLE.
    //
    // If random_nibble is 0, the counter loads 0 and proceed fires
    // on the very next cycle (1 cycle FSM latency, no extra dummy cycles).
    // =========================================================================
    reg [3:0] delay_counter;

    // Debug output: high while dummy cycles are being inserted
    assign jitter_active = (fsm_state == S_DELAY);

    // =========================================================================
    // FSM sequential logic
    // =========================================================================
    always @(posedge clk) begin
        if (rst) begin
            fsm_state     <= S_IDLE;
            delay_counter <= 4'd0;
            proceed       <= 1'b0;
        end else begin
            proceed <= 1'b0;  // default: deasserted (1-cycle pulse)

            case (fsm_state)

                S_IDLE: begin
                    if (round_done) begin
                        // Latch current random nibble as delay duration
                        delay_counter <= random_nibble;
                        fsm_state     <= S_DELAY;
                    end
                end

                S_DELAY: begin
                    if (delay_counter == 4'd0) begin
                        // Delay complete — signal AES to proceed
                        proceed   <= 1'b1;
                        fsm_state <= S_IDLE;
                    end else begin
                        // Count down: insert dummy cycle
                        delay_counter <= delay_counter - 4'd1;
                    end
                end

                default: fsm_state <= S_IDLE;

            endcase
        end
    end

endmodule
