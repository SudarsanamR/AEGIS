// =============================================================================
// Module:      ring_oscillator_trng
// File:        rtl/countermeasures/ring_oscillator_trng.v
// Project:     AEGIS — Act 3, Step 5.1
//
// Purpose:     True Random Number Generator based on 8 parallel ring
//              oscillators exploiting jitter from PVT (Process, Voltage,
//              Temperature) variations in the Spartan-7 XC7S50 fabric.
//
// Architecture:
//
//   ┌──────────────────────────────────────────────────────────┐
//   │                 RING OSCILLATOR TRNG                     │
//   │                                                         │
//   │  ┌─────┐  ┌─────┐  ┌─────┐         ┌─────┐            │
//   │  │ RO0 │  │ RO1 │  │ RO2 │  . . .  │ RO7 │  ← 8 ROs  │
//   │  └──┬──┘  └──┬──┘  └──┬──┘         └──┬──┘            │
//   │     │        │        │               │                │
//   │     └────┬───┘────┬───┘───── . . . ───┘                │
//   │          │        │                                     │
//   │       ┌──┴────────┴──┐                                  │
//   │       │  8-input XOR │  ← entropy combiner              │
//   │       └──────┬───────┘                                  │
//   │              │                                          │
//   │       ┌──────┴───────┐                                  │
//   │       │ 1MHz Sampler │  ← sample_ctr divides 100→1MHz  │
//   │       └──────┬───────┘                                  │
//   │              │                                          │
//   │        trng_bit  trng_valid                             │
//   └──────────────────────────────────────────────────────────┘
//
// Ring Oscillator Design:
//   Each RO is a 3-stage inverter loop built from LUT1 primitives
//   configured as inverters (INIT = 2'b01: out = ~in).
//
//   The odd number of inversions (3) ensures the loop is unstable
//   and oscillates continuously. The frequency depends on:
//     - LUT propagation delay (~300ps per LUT on Spartan-7)
//     - Routing delay (varies by placement — hence Pblock constraint)
//   Estimated frequency: ~500 MHz per ring (too fast to observe directly)
//
// Entropy Source:
//   Phase jitter between the 8 ROs accumulates over the 1µs sampling
//   period (100 clock cycles at 100MHz). The XOR of all 8 outputs
//   collapses this jitter into a single random bit. Even if 7 oscillators
//   are deterministic, one jittery RO produces a random XOR output.
//
// Sampling:
//   A 7-bit counter divides the 100MHz clock by 100 to produce a 1MHz
//   sampling strobe (sample_tick). On each tick, the XOR output is
//   latched into trng_bit and trng_valid pulses high for one cycle.
//
// CRITICAL SYNTHESIS ATTRIBUTES:
//   (* KEEP = "TRUE" *)        on all oscillator wires — prevents
//                               Vivado from merging/removing nets
//   (* DONT_TOUCH = "TRUE" *)  on all LUT1 instances — prevents
//                               Vivado from optimizing away the
//                               combinational loops
//
//   Without BOTH attributes, Vivado WILL eliminate the ring oscillators
//   during synthesis optimization (verified experimentally).
//
// SIMULATION NOTE:
//   In behavioral simulation, LUT1 primitives resolve the combinational
//   loop to X (unknown). This is EXPECTED. The trng_bit output will be X
//   in simulation. On real hardware, thermal noise drives the oscillation.
//   Test the TRNG on hardware using the trng_validator module (Step 5.2).
//
// PBLOCK (added to XDC in Step 5.5):
//   All 8 ring oscillators are placed in SLICE_X0Y0:SLICE_X3Y3 to:
//   1. Maximize thermal coupling (nearby LUTs share temperature)
//   2. Minimize routing delay variation (consistent oscillation)
//   3. Isolate ROs from AES logic (prevent cross-talk)
//
// Resource Usage:
//   8 ROs × 3 LUT1s = 24 LUTs
//   1 sample counter = 7 FFs
//   2 output registers = 2 FFs
//   Total: ~24 LUTs, ~9 FFs (well within the 500-LUT budget)
//
// Interface:
//   clk        — 100 MHz system clock (pin E3 on Arty S7)
//   rst        — synchronous reset, active high
//   trng_bit   — random bit output (valid when trng_valid = 1)
//   trng_valid — pulses high for 1 clock cycle at 1MHz rate
// =============================================================================

module ring_oscillator_trng (
    input  wire clk,        // 100 MHz system clock
    input  wire rst,        // synchronous reset, active high
    output reg  trng_bit,   // random bit output
    output reg  trng_valid  // pulses high for 1 cycle when new bit ready
);

    // =========================================================================
    // 1 MHz sampling clock from 100 MHz system clock
    //
    // WHY 1 MHz: At ~500 MHz oscillation, 100 system clock cycles span ~50,000
    // oscillator cycles. Phase jitter of ~1ps RMS accumulates as sqrt(50000)
    // × 1ps ≈ 224ps — roughly half a ring oscillator period. This provides
    // near-maximum entropy per sample. Faster sampling reduces jitter
    // accumulation; slower sampling wastes bandwidth without gain.
    //
    // Counter counts 0 to 99 (100 cycles) and asserts sample_tick at 99.
    // =========================================================================
    reg [6:0] sample_ctr;   // 7 bits for range 0–99
    wire      sample_tick;

    assign sample_tick = (sample_ctr == 7'd99);

    always @(posedge clk) begin
        if (rst)
            sample_ctr <= 7'd0;
        else if (sample_tick)
            sample_ctr <= 7'd0;  // wrap to 0 after reaching 99
        else
            sample_ctr <= sample_ctr + 7'd1;
    end

    // =========================================================================
    // 8 Ring Oscillators
    //
    // Each RO uses 3 LUT1 inverters in a feedback loop:
    //
    //   stage[0] = ~stage[2]   (feedback from output to input)
    //   stage[1] = ~stage[0]
    //   stage[2] = ~stage[1]   (output of this RO)
    //
    // The odd number of inversions guarantees instability → oscillation.
    //
    // LUT1 with INIT = 2'b01 implements: O = ~I0
    //   INIT[0] = 1 → when I0=0, output=1
    //   INIT[1] = 0 → when I0=1, output=0
    //
    // KEEP on wires prevents net merging across oscillators.
    // DONT_TOUCH on LUT1 instances prevents removal during optimization.
    // =========================================================================

    // Oscillator output wires — KEEP prevents Vivado from optimizing
    (* KEEP = "TRUE" *) wire [7:0] osc_out;

    // XOR all 8 oscillator outputs — entropy combiner
    // If ANY single oscillator has good jitter, the XOR output is random.
    // This is the standard Von Neumann / XOR entropy mixing approach.
    wire xor_all;
    assign xor_all = ^osc_out;  // 8-input XOR reduction operator

    // Generate 8 independent ring oscillators
    genvar i;
    generate
        for (i = 0; i < 8; i = i + 1) begin : RO

            // Internal oscillator stage wires — KEEP prevents merging
            (* KEEP = "TRUE" *) wire [2:0] stage;

            // Stage 0: inverts stage[2] (feedback path from output)
            // This is the critical feedback connection that creates the loop.
            (* DONT_TOUCH = "TRUE" *)
            LUT1 #(.INIT(2'b01)) inv0 (
                .O  (stage[0]),
                .I0 (stage[2])
            );

            // Stage 1: inverts stage[0]
            (* DONT_TOUCH = "TRUE" *)
            LUT1 #(.INIT(2'b01)) inv1 (
                .O  (stage[1]),
                .I0 (stage[0])
            );

            // Stage 2: inverts stage[1] — this is the RO output
            (* DONT_TOUCH = "TRUE" *)
            LUT1 #(.INIT(2'b01)) inv2 (
                .O  (stage[2]),
                .I0 (stage[1])
            );

            // Tap the last stage as this oscillator's output
            assign osc_out[i] = stage[2];

        end
    endgenerate

    // =========================================================================
    // Output sampling register
    //
    // On every sample_tick (1 MHz), latch the XOR of all oscillator outputs
    // into trng_bit and pulse trng_valid high for exactly one clock cycle.
    //
    // TIMING: trng_bit is registered (no combinational path to output).
    //         trng_valid is also registered and self-clearing (1-cycle pulse).
    // =========================================================================
    always @(posedge clk) begin
        if (rst) begin
            trng_bit   <= 1'b0;
            trng_valid <= 1'b0;
        end else begin
            trng_valid <= 1'b0;         // default: deasserted

            if (sample_tick) begin
                trng_bit   <= xor_all;  // latch XOR of all 8 oscillators
                trng_valid <= 1'b1;     // pulse valid for 1 cycle
            end
        end
    end

endmodule
