// =============================================================================
// Testbench:   tb_timing_randomizer
// File:        sim/tb_timing_randomizer.v
// Project:     AEGIS — Act 3, Step 5.3
//
// Purpose:     Verify the timing randomizer correctly inserts 0–15 dummy
//              cycles between AES rounds and properly handshakes via
//              round_done / proceed.
//
// Tests:
//   1. Reset state: proceed = 0, jitter_active = 0
//   2. Zero delay: random_nibble = 0 → proceed in 1 cycle
//   3. Fixed delay: pre-load nibble, verify exact countdown
//   4. Maximum delay: 15 dummy cycles
//   5. Back-to-back rounds: multiple round_done in sequence
//   6. TRNG bit accumulation: shift register collects 4 bits
//   7. Proceed is exactly 1 cycle wide
// =============================================================================

`timescale 1ns / 1ps

module tb_timing_randomizer;

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
    reg  trng_bit;
    reg  trng_valid;
    reg  round_done;
    wire proceed;
    wire jitter_active;

    // =========================================================================
    // DUT instantiation
    // =========================================================================
    timing_randomizer uut (
        .clk           (clk),
        .rst           (rst),
        .trng_bit      (trng_bit),
        .trng_valid    (trng_valid),
        .round_done    (round_done),
        .proceed       (proceed),
        .jitter_active (jitter_active)
    );

    // =========================================================================
    // Helper task: feed 4 TRNG bits to form a specific nibble
    //
    // Sends MSB first: nibble[3], nibble[2], nibble[1], nibble[0]
    // After this task, random_nibble in the DUT equals `nibble`.
    // =========================================================================
    task load_nibble;
        input [3:0] nibble;
        integer k;
        begin
            for (k = 3; k >= 0; k = k - 1) begin
                @(posedge clk);
                trng_bit   <= nibble[k];
                trng_valid <= 1'b1;
                @(posedge clk);
                trng_valid <= 1'b0;
            end
        end
    endtask

    // =========================================================================
    // Helper task: pulse round_done for 1 cycle and wait for proceed
    //
    // Returns the number of clock cycles between round_done and proceed.
    // =========================================================================
    integer measured_delay;

    task do_round_and_measure;
        begin
            @(posedge clk);
            round_done <= 1'b1;
            @(posedge clk);
            round_done <= 1'b0;

            measured_delay = 0;
            while (proceed !== 1'b1) begin
                @(posedge clk);
                measured_delay = measured_delay + 1;
                if (measured_delay > 100) begin
                    $display("  TIMEOUT: proceed never asserted");
                    disable do_round_and_measure;
                end
            end
        end
    endtask

    // =========================================================================
    // Test variables
    // =========================================================================
    integer errors;
    integer proceed_width;

    // =========================================================================
    // Test sequence
    // =========================================================================
    initial begin
        $display("===========================================================");
        $display("  AEGIS — tb_timing_randomizer");
        $display("  Timing jitter insertion between AES rounds");
        $display("===========================================================");
        $display("");

        errors     = 0;
        trng_bit   = 0;
        trng_valid = 0;
        round_done = 0;

        // -----------------------------------------------------------------
        // TEST 1: Reset state
        // -----------------------------------------------------------------
        $display("[TEST 1] Reset state");
        rst = 1;
        repeat (5) @(posedge clk);

        if (proceed !== 1'b0) begin
            $display("  FAIL: proceed = %b during reset (expected 0)", proceed);
            errors = errors + 1;
        end else begin
            $display("  PASS: proceed = 0 during reset");
        end

        if (jitter_active !== 1'b0) begin
            $display("  FAIL: jitter_active = %b during reset (expected 0)",
                     jitter_active);
            errors = errors + 1;
        end else begin
            $display("  PASS: jitter_active = 0 during reset");
        end

        rst = 0;
        repeat (3) @(posedge clk);

        // -----------------------------------------------------------------
        // TEST 2: Zero delay — random_nibble = 0
        //         Proceed should fire 1 cycle after entering DELAY state.
        //         Total: round_done → 1 cycle to load → 1 cycle to proceed = 2 cycles
        // -----------------------------------------------------------------
        $display("");
        $display("[TEST 2] Zero delay (random_nibble = 0)");

        // Pre-load nibble with 0000
        load_nibble(4'b0000);
        repeat (3) @(posedge clk);

        do_round_and_measure;

        // With delay=0: enter S_DELAY on cycle after round_done,
        // delay_counter is already 0, so proceed fires immediately = 1 cycle
        $display("  Measured delay: %0d cycles", measured_delay);
        if (measured_delay == 1) begin
            $display("  PASS: zero delay = 1 cycle (FSM latency only)");
        end else begin
            $display("  FAIL: expected 1 cycle, got %0d", measured_delay);
            errors = errors + 1;
        end

        // -----------------------------------------------------------------
        // TEST 3: Fixed delay = 5
        //         Expected: 5 countdown + 1 FSM cycle = 6 cycles
        // -----------------------------------------------------------------
        $display("");
        $display("[TEST 3] Fixed delay = 5 (expect 6 cycles total)");

        load_nibble(4'd5);
        repeat (3) @(posedge clk);

        do_round_and_measure;

        $display("  Measured delay: %0d cycles", measured_delay);
        if (measured_delay == 6) begin
            $display("  PASS: delay of 5 = 6 total cycles");
        end else begin
            $display("  FAIL: expected 6, got %0d", measured_delay);
            errors = errors + 1;
        end

        // -----------------------------------------------------------------
        // TEST 4: Maximum delay = 15
        //         Expected: 15 countdown + 1 FSM cycle = 16 cycles
        // -----------------------------------------------------------------
        $display("");
        $display("[TEST 4] Maximum delay = 15 (expect 16 cycles total)");

        load_nibble(4'b1111);
        repeat (3) @(posedge clk);

        do_round_and_measure;

        $display("  Measured delay: %0d cycles", measured_delay);
        if (measured_delay == 16) begin
            $display("  PASS: delay of 15 = 16 total cycles");
        end else begin
            $display("  FAIL: expected 16, got %0d", measured_delay);
            errors = errors + 1;
        end

        // -----------------------------------------------------------------
        // TEST 5: Back-to-back rounds with different delays
        // -----------------------------------------------------------------
        $display("");
        $display("[TEST 5] Back-to-back rounds (delays 3, 7, 1)");

        // Round A: delay 3
        load_nibble(4'd3);
        repeat (2) @(posedge clk);
        do_round_and_measure;
        $display("  Round A: measured %0d cycles (expected 4)", measured_delay);
        if (measured_delay != 4) begin
            errors = errors + 1;
            $display("  FAIL");
        end else $display("  PASS");

        // Round B: delay 7
        load_nibble(4'd7);
        repeat (2) @(posedge clk);
        do_round_and_measure;
        $display("  Round B: measured %0d cycles (expected 8)", measured_delay);
        if (measured_delay != 8) begin
            errors = errors + 1;
            $display("  FAIL");
        end else $display("  PASS");

        // Round C: delay 1
        load_nibble(4'd1);
        repeat (2) @(posedge clk);
        do_round_and_measure;
        $display("  Round C: measured %0d cycles (expected 2)", measured_delay);
        if (measured_delay != 2) begin
            errors = errors + 1;
            $display("  FAIL");
        end else $display("  PASS");

        // -----------------------------------------------------------------
        // TEST 6: TRNG bit accumulation — verify shift register
        // -----------------------------------------------------------------
        $display("");
        $display("[TEST 6] TRNG bit accumulation");

        rst = 1;
        repeat (3) @(posedge clk);
        rst = 0;
        repeat (3) @(posedge clk);

        // Feed bits: 1, 0, 1, 1 → nibble should be 4'b1011 = 11
        load_nibble(4'b1011);

        if (uut.random_nibble == 4'b1011) begin
            $display("  PASS: random_nibble = 4'b%04b (expected 1011)",
                     uut.random_nibble);
        end else begin
            $display("  FAIL: random_nibble = 4'b%04b (expected 1011)",
                     uut.random_nibble);
            errors = errors + 1;
        end

        // -----------------------------------------------------------------
        // TEST 7: Proceed pulse is exactly 1 cycle wide
        // -----------------------------------------------------------------
        $display("");
        $display("[TEST 7] Proceed pulse width");

        load_nibble(4'd2);
        repeat (2) @(posedge clk);

        // Fire round_done
        @(posedge clk);
        round_done <= 1'b1;
        @(posedge clk);
        round_done <= 1'b0;

        // Wait for proceed
        while (proceed !== 1'b1) @(posedge clk);

        // Measure width
        proceed_width = 0;
        while (proceed === 1'b1) begin
            proceed_width = proceed_width + 1;
            @(posedge clk);
        end

        if (proceed_width == 1) begin
            $display("  PASS: proceed pulse is exactly 1 cycle wide");
        end else begin
            $display("  FAIL: proceed pulse width = %0d (expected 1)",
                     proceed_width);
            errors = errors + 1;
        end

        // -----------------------------------------------------------------
        // TEST 8: jitter_active asserted during countdown
        // -----------------------------------------------------------------
        $display("");
        $display("[TEST 8] jitter_active during countdown");

        load_nibble(4'd4);
        repeat (2) @(posedge clk);

        // Verify idle before round_done
        if (jitter_active !== 1'b0) begin
            $display("  FAIL: jitter_active high in IDLE state");
            errors = errors + 1;
        end

        @(posedge clk);
        round_done <= 1'b1;
        @(posedge clk);
        round_done <= 1'b0;

        // jitter_active should now be high
        @(posedge clk);
        if (jitter_active !== 1'b1) begin
            $display("  FAIL: jitter_active not asserted during delay");
            errors = errors + 1;
        end else begin
            $display("  PASS: jitter_active asserted during countdown");
        end

        // Wait for proceed, then check jitter_active clears
        while (proceed !== 1'b1) @(posedge clk);
        @(posedge clk);

        if (jitter_active !== 1'b0) begin
            $display("  FAIL: jitter_active not cleared after proceed");
            errors = errors + 1;
        end else begin
            $display("  PASS: jitter_active cleared after proceed");
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
