// =============================================================================
// Testbench:   tb_trng_validator
// File:        sim/tb_trng_validator.v
// Project:     AEGIS — Act 3, Step 5.2
//
// Purpose:     Verify that trng_validator correctly accepts healthy TRNG
//              output and rejects biased or stuck-at bitstreams.
//
// Tests:
//   1. Reset state: entropy_valid = 0
//   2. Healthy bitstream (50% ones): entropy_valid → 1 after window
//   3. Biased bitstream (all-ones): entropy_valid → 0
//   4. Stuck-at-zero bitstream: entropy_valid → 0
//   5. Marginal pass (exactly 45% ones): entropy_valid → 1
//   6. Marginal fail (44.9% ones): entropy_valid → 0
//   7. Passthrough gating: trng_valid_out = 0 when entropy_valid = 0
// =============================================================================

`timescale 1ns / 1ps

module tb_trng_validator;

    // =========================================================================
    // Clock and reset
    // =========================================================================
    reg clk;
    reg rst;

    initial clk = 0;
    always #5 clk = ~clk;  // 100 MHz

    // =========================================================================
    // DUT signals
    // =========================================================================
    reg        bit_in;
    reg        bit_valid;
    wire       entropy_valid;
    wire       trng_bit_out;
    wire       trng_valid_out;

    // =========================================================================
    // DUT instantiation
    // =========================================================================
    trng_validator uut (
        .clk            (clk),
        .rst            (rst),
        .bit_in         (bit_in),
        .bit_valid      (bit_valid),
        .entropy_valid  (entropy_valid),
        .trng_bit_out   (trng_bit_out),
        .trng_valid_out (trng_valid_out)
    );

    // =========================================================================
    // Helper task: feed N bits with a given ones ratio
    //
    // Sends exactly `total_bits` to the validator, of which `ones_count`
    // are 1 (sent first) and the remainder are 0.
    //
    // WHY ones-first: The validator checks after exactly 10,000 bits
    // regardless of ordering. Sending 1s first then 0s is simplest.
    // =========================================================================
    integer feed_i;

    task feed_bits;
        input integer total_bits;
        input integer ones_count;
        begin
            for (feed_i = 0; feed_i < total_bits; feed_i = feed_i + 1) begin
                @(posedge clk);
                bit_valid <= 1'b1;

                if (feed_i < ones_count)
                    bit_in <= 1'b1;
                else
                    bit_in <= 1'b0;

                @(posedge clk);
                bit_valid <= 1'b0;  // deassert for realistic 1-cycle pulses
            end
        end
    endtask

    // =========================================================================
    // Test variables
    // =========================================================================
    integer errors;

    // =========================================================================
    // Test sequence
    // =========================================================================
    initial begin
        $display("===========================================================");
        $display("  AEGIS — tb_trng_validator");
        $display("  Entropy validation with 10,000-bit window");
        $display("===========================================================");
        $display("");

        errors    = 0;
        bit_in    = 0;
        bit_valid = 0;

        // -----------------------------------------------------------------
        // TEST 1: Reset state — entropy_valid must be 0
        // -----------------------------------------------------------------
        $display("[TEST 1] Reset state: entropy_valid = 0");
        rst = 1;
        repeat (10) @(posedge clk);

        if (entropy_valid !== 1'b0) begin
            $display("  FAIL: entropy_valid = %b (expected 0)", entropy_valid);
            errors = errors + 1;
        end else begin
            $display("  PASS: entropy_valid = 0 after reset");
        end

        rst = 0;
        @(posedge clk);

        // -----------------------------------------------------------------
        // TEST 2: Healthy bitstream — 50% ones (5000 out of 10000)
        //         Expected: entropy_valid → 1
        // -----------------------------------------------------------------
        $display("");
        $display("[TEST 2] Healthy bitstream: 5000 ones / 10000 bits (50%%)");

        feed_bits(10000, 5000);
        repeat (5) @(posedge clk);  // settle

        if (entropy_valid !== 1'b1) begin
            $display("  FAIL: entropy_valid = %b (expected 1)", entropy_valid);
            errors = errors + 1;
        end else begin
            $display("  PASS: entropy_valid = 1 (healthy TRNG accepted)");
        end

        // -----------------------------------------------------------------
        // TEST 3: All-ones biased bitstream — 100% ones
        //         Expected: entropy_valid → 0
        // -----------------------------------------------------------------
        $display("");
        $display("[TEST 3] Biased bitstream: 10000 ones / 10000 bits (100%%)");

        feed_bits(10000, 10000);
        repeat (5) @(posedge clk);

        if (entropy_valid !== 1'b0) begin
            $display("  FAIL: entropy_valid = %b (expected 0)", entropy_valid);
            errors = errors + 1;
        end else begin
            $display("  PASS: entropy_valid = 0 (biased TRNG rejected)");
        end

        // -----------------------------------------------------------------
        // TEST 4: Stuck-at-zero — 0% ones
        //         Expected: entropy_valid → 0
        // -----------------------------------------------------------------
        $display("");
        $display("[TEST 4] Stuck-at-zero: 0 ones / 10000 bits (0%%)");

        feed_bits(10000, 0);
        repeat (5) @(posedge clk);

        if (entropy_valid !== 1'b0) begin
            $display("  FAIL: entropy_valid = %b (expected 0)", entropy_valid);
            errors = errors + 1;
        end else begin
            $display("  PASS: entropy_valid = 0 (stuck-at-zero rejected)");
        end

        // -----------------------------------------------------------------
        // TEST 5: Marginal pass — exactly 45% ones (4500/10000)
        //         Expected: entropy_valid → 1 (boundary is inclusive)
        // -----------------------------------------------------------------
        $display("");
        $display("[TEST 5] Marginal pass: 4500 ones / 10000 bits (45%%)");

        feed_bits(10000, 4500);
        repeat (5) @(posedge clk);

        if (entropy_valid !== 1'b1) begin
            $display("  FAIL: entropy_valid = %b (expected 1)", entropy_valid);
            errors = errors + 1;
        end else begin
            $display("  PASS: entropy_valid = 1 (45%% boundary accepted)");
        end

        // -----------------------------------------------------------------
        // TEST 6: Marginal pass — exactly 55% ones (5500/10000)
        //         Expected: entropy_valid → 1 (boundary is inclusive)
        // -----------------------------------------------------------------
        $display("");
        $display("[TEST 6] Marginal pass: 5500 ones / 10000 bits (55%%)");

        feed_bits(10000, 5500);
        repeat (5) @(posedge clk);

        if (entropy_valid !== 1'b1) begin
            $display("  FAIL: entropy_valid = %b (expected 1)", entropy_valid);
            errors = errors + 1;
        end else begin
            $display("  PASS: entropy_valid = 1 (55%% boundary accepted)");
        end

        // -----------------------------------------------------------------
        // TEST 7: Marginal fail — 4499 ones (just under 45%)
        //         Expected: entropy_valid → 0
        // -----------------------------------------------------------------
        $display("");
        $display("[TEST 7] Marginal fail: 4499 ones / 10000 bits (44.99%%)");

        feed_bits(10000, 4499);
        repeat (5) @(posedge clk);

        if (entropy_valid !== 1'b0) begin
            $display("  FAIL: entropy_valid = %b (expected 0)", entropy_valid);
            errors = errors + 1;
        end else begin
            $display("  PASS: entropy_valid = 0 (just under 45%% rejected)");
        end

        // -----------------------------------------------------------------
        // TEST 8: Passthrough gating — trng_valid_out = 0 when invalid
        // -----------------------------------------------------------------
        $display("");
        $display("[TEST 8] Passthrough gating");

        // entropy_valid is currently 0 (from test 7 failure)
        @(posedge clk);
        bit_in    = 1'b1;
        bit_valid = 1'b1;
        @(posedge clk);

        if (trng_valid_out !== 1'b0) begin
            $display("  FAIL: trng_valid_out = %b when entropy_valid = 0",
                     trng_valid_out);
            errors = errors + 1;
        end else begin
            $display("  PASS: trng_valid_out gated off when entropy_valid = 0");
        end

        // Now feed a healthy window to restore entropy_valid
        bit_valid = 0;
        feed_bits(10000, 5000);
        repeat (5) @(posedge clk);

        // Now entropy_valid should be 1, test passthrough
        @(posedge clk);
        bit_in    = 1'b1;
        bit_valid = 1'b1;
        @(posedge clk);

        if (trng_valid_out !== 1'b1) begin
            $display("  FAIL: trng_valid_out = %b when entropy_valid = 1",
                     trng_valid_out);
            errors = errors + 1;
        end else begin
            $display("  PASS: trng_valid_out passes through when entropy_valid = 1");
        end

        bit_valid = 0;

        // Check bit passthrough
        @(posedge clk);
        bit_in = 1'b1;
        @(posedge clk);
        if (trng_bit_out !== 1'b1) begin
            $display("  FAIL: trng_bit_out not passing through bit_in");
            errors = errors + 1;
        end else begin
            $display("  PASS: trng_bit_out mirrors bit_in");
        end

        // -----------------------------------------------------------------
        // TEST 9: Recovery — healthy window after failure restores valid
        // -----------------------------------------------------------------
        $display("");
        $display("[TEST 9] Recovery after failure");

        // Force a bad window
        feed_bits(10000, 10000);
        repeat (5) @(posedge clk);

        if (entropy_valid !== 1'b0) begin
            $display("  FAIL: entropy_valid should be 0 after bad window");
            errors = errors + 1;
        end

        // Feed a good window — should recover
        feed_bits(10000, 5000);
        repeat (5) @(posedge clk);

        if (entropy_valid !== 1'b1) begin
            $display("  FAIL: entropy_valid = %b (expected 1 after recovery)",
                     entropy_valid);
            errors = errors + 1;
        end else begin
            $display("  PASS: entropy_valid recovers to 1 after healthy window");
        end

        // -----------------------------------------------------------------
        // Summary
        // -----------------------------------------------------------------
        $display("");
        $display("===========================================================");
        if (errors == 0) begin
            $display("  ALL TESTS PASSED");
        end else begin
            $display("  FAIL: %0d test(s) failed", errors);
        end
        $display("===========================================================");

        $finish;
    end

endmodule
