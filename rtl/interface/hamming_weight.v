// =============================================================================
// Module:      hamming_weight
// Project:     AEGIS — Adaptive FPGA-Based Side-Channel Defense
// File:        rtl/interface/hamming_weight.v
// Description: Counts the number of 1-bits in a 128-bit input word.
//              Used to model power consumption (Hamming Weight leakage model)
//              for the DPA and neural network side-channel attacks.
//
//              The output is REGISTERED — valid one clock cycle after load
//              is asserted. This keeps the critical path short on Spartan-7
//              and lets the control FSM treat hw_valid as a clean handshake.
//
// Target:      Xilinx Spartan-7 XC7S50 (Arty S7)
// Clock:       100 MHz, synchronous reset active-high
// LUT budget:  ~80 LUTs (well within the 500-LUT interface budget)
//
// Port summary:
//   clk       — 100 MHz system clock
//   rst       — synchronous reset, active high
//   load      — pulse high for one cycle to latch data_in and start count
//   data_in   — 128-bit value to count (SubBytes output in practice)
//   hw_out    — 8-bit result, range 0–128
//   hw_valid  — asserted one cycle after load, stays high until next load
//
// Timing:
//   cycle 0: load = 1, data_in captured into register
//   cycle 1: hw_out stable, hw_valid = 1
// =============================================================================

module hamming_weight (
    input  wire         clk,
    input  wire         rst,
    input  wire         load,       // strobe: capture data_in this cycle
    input  wire [127:0] data_in,    // 128-bit value (SubBytes output)
    output reg  [7:0]   hw_out,     // popcount result, 0–128
    output reg          hw_valid    // high one cycle after load
);

    // -------------------------------------------------------------------------
    // Stage 0: Latch input on load
    // Prevents glitches on data_in from corrupting the adder tree mid-count.
    // -------------------------------------------------------------------------
    reg [127:0] data_reg;

    always @(posedge clk) begin
        if (rst) begin
            data_reg <= 128'b0;
        end else if (load) begin
            data_reg <= data_in;  // capture snapshot; data_in may change next cycle
        end
    end

    // -------------------------------------------------------------------------
    // Stage 1: Per-byte popcount — 16 independent 4-bit counts
    //
    // Each byte contributes 0–8 ones → needs 4 bits to represent.
    // Vivado maps an 8-bit popcount onto ~2 LUTs using carry chain inference.
    // Doing all 16 in parallel gives maximum throughput.
    // -------------------------------------------------------------------------
    wire [3:0] byte_hw [0:15];   // popcount of each byte, 0–8

    genvar i;
    generate
        for (i = 0; i < 16; i = i + 1) begin : gen_byte_hw
            // Extract byte i from the registered snapshot.
            // Column-major ordering: byte 0 = data_reg[127:120], etc.
            // The HW count does not depend on ordering — sum is commutative.
            assign byte_hw[i] = data_reg[127 - i*8] +
                                 data_reg[126 - i*8] +
                                 data_reg[125 - i*8] +
                                 data_reg[124 - i*8] +
                                 data_reg[123 - i*8] +
                                 data_reg[122 - i*8] +
                                 data_reg[121 - i*8] +
                                 data_reg[120 - i*8];
            // Verilog adds booleans as integers; result fits in 4 bits (max 8)
        end
    endgenerate

    // -------------------------------------------------------------------------
    // Stage 2–4: Adder tree — reduce 16 × 4-bit values to one 8-bit sum
    //
    // All intermediate values are module-level wires (continuous assignments).
    // Vivado-2001 does NOT allow reg declarations inside unnamed always blocks
    // (VRFC 10-8885), so the tree must live at module scope as wire assigns.
    //
    // Widths grow to prevent overflow at each level:
    //   Level 1:  pairs of 4-bit  → 5-bit  (max 16, fits 5 bits)
    //   Level 2:  pairs of 5-bit  → 6-bit  (max 32, fits 6 bits)
    //   Level 3:  pairs of 6-bit  → 7-bit  (max 64, fits 7 bits)
    //   Level 4:  two  7-bit      → 8-bit  (max 128, fits 8 bits)
    // -------------------------------------------------------------------------

    // Level 1: 16 → 8 partial sums (5-bit each)  // MODIFIED
    wire [4:0] l1_0 = byte_hw[0]  + byte_hw[1];   // MODIFIED
    wire [4:0] l1_1 = byte_hw[2]  + byte_hw[3];   // MODIFIED
    wire [4:0] l1_2 = byte_hw[4]  + byte_hw[5];   // MODIFIED
    wire [4:0] l1_3 = byte_hw[6]  + byte_hw[7];   // MODIFIED
    wire [4:0] l1_4 = byte_hw[8]  + byte_hw[9];   // MODIFIED
    wire [4:0] l1_5 = byte_hw[10] + byte_hw[11];  // MODIFIED
    wire [4:0] l1_6 = byte_hw[12] + byte_hw[13];  // MODIFIED
    wire [4:0] l1_7 = byte_hw[14] + byte_hw[15];  // MODIFIED

    // Level 2: 8 → 4 partial sums (6-bit each)   // MODIFIED
    wire [5:0] l2_0 = l1_0 + l1_1;                // MODIFIED
    wire [5:0] l2_1 = l1_2 + l1_3;                // MODIFIED
    wire [5:0] l2_2 = l1_4 + l1_5;                // MODIFIED
    wire [5:0] l2_3 = l1_6 + l1_7;                // MODIFIED

    // Level 3: 4 → 2 partial sums (7-bit each)   // MODIFIED
    wire [6:0] l3_0 = l2_0 + l2_1;                // MODIFIED
    wire [6:0] l3_1 = l2_2 + l2_3;                // MODIFIED

    // Level 4: final 8-bit sum (max 128 = 8'h80) // MODIFIED
    wire [7:0] hw_comb = l3_0 + l3_1;             // MODIFIED

    // -------------------------------------------------------------------------
    // Output register: capture result and assert hw_valid.
    //
    // hw_valid is STICKY — asserts 2 cycles after load and holds until the
    // next load. This avoids the one-cycle-pulse race that caused prior
    // testbench failures.
    //
    // Pipeline:
    //   posedge B (load=1):  data_reg latches; load_d1 stays 0
    //   posedge C:           load_d1 goes 1; hw_out <= hw_comb (now valid)
    //   posedge D:           hw_valid goes 1 (sticky); stays until next load
    //   next load:           hw_valid cleared immediately (load takes priority)
    // -------------------------------------------------------------------------
    reg load_d1;

    always @(posedge clk) begin
        if (rst) begin
            load_d1  <= 1'b0;
            hw_out   <= 8'b0;
            hw_valid <= 1'b0;
        end else begin
            load_d1 <= load;       // pipeline stage: delay load by 1 cycle
            hw_out  <= hw_comb;    // always register result

            // Sticky valid: set on load_d1 rising, cleared by next load
            if (load)              // new computation starting — clear old valid
                hw_valid <= 1'b0;
            else if (load_d1)      // result settled this cycle — assert valid
                hw_valid <= 1'b1;
            // else: hold (sticky until next load)
        end
    end

endmodule
