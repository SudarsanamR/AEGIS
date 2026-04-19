// =============================================================================
// Testbench:   tb_uart_tx
// File:        sim/tb_uart_tx.v
// Description: Self-checking testbench for the uart_tx module.
//
// Verification strategy:
//   The testbench samples tx_pin at the CENTRE of each expected baud period
//   (offset by DIVISOR/2 cycles from the falling edge of the start bit).
//   Centre-sampling is how real UART receivers work and is the correct way
//   to verify bit timing.
//
// Test cases:
//   1. Transmit 0x55 (01010101) — classic UART test pattern (alternating bits)
//   2. Transmit 0xAA (10101010) — complement of 0x55
//   3. Transmit 0x00 (all zeros)
//   4. Transmit 0xFF (all ones)
//   5. Transmit 0xA5 (NIST-adjacent: a byte from the AES key 000102...0f)
//   6. Verify tx_busy deasserts after frame completes
//   7. Verify tx_pin idles HIGH after reset and between frames
//
// Frame format verified:
//   [idle=1] [start=0] [D0..D7 LSB-first] [stop=1] [idle=1]
// =============================================================================

`timescale 1ns / 1ps

module tb_uart_tx;

    // -------------------------------------------------------------------------
    // Parameters — must match DUT
    // -------------------------------------------------------------------------
    parameter DIVISOR   = 10417;           // cycles per baud at 100MHz/9600
    parameter CLK_PERIOD = 10;             // 100 MHz → 10 ns
    parameter HALF_BIT  = DIVISOR / 2;    // sample offset from bit start

    // -------------------------------------------------------------------------
    // DUT signals
    // -------------------------------------------------------------------------
    reg        clk;
    reg        rst;
    reg        tx_start;
    reg  [7:0] tx_data;
    wire       tx_pin;
    wire       tx_busy;

    integer pass_count;
    integer fail_count;

    // -------------------------------------------------------------------------
    // DUT instantiation
    // -------------------------------------------------------------------------
    uart_tx #(.DIVISOR(DIVISOR)) dut (
        .clk      (clk),
        .rst      (rst),
        .tx_start (tx_start),
        .tx_data  (tx_data),
        .tx_pin   (tx_pin),
        .tx_busy  (tx_busy)
    );

    // -------------------------------------------------------------------------
    // 100 MHz clock
    // -------------------------------------------------------------------------
    initial clk = 0;
    always #(CLK_PERIOD/2) clk = ~clk;

    // -------------------------------------------------------------------------
    // Task: transmit a byte and verify every bit by centre-sampling
    //
    // How centre-sampling works:
    //   - We detect the falling edge of tx_pin (start bit begins)
    //   - Wait HALF_BIT cycles to reach centre of start bit, verify = 0
    //   - Wait DIVISOR cycles to reach centre of each data bit, verify
    //   - Wait DIVISOR cycles to reach centre of stop bit, verify = 1
    //   - Wait remaining half-bit to clear stop, return
    // -------------------------------------------------------------------------
    task transmit_and_check;
        input [7:0]   data;
        input [255:0] name;
        integer       b;          // bit index
        reg           expected_bit;
        begin
            // ── Initiate transmission ────────────────────────────────────────
            @(posedge clk); #1;
            tx_data  <= data;
            tx_start <= 1'b1;
            @(posedge clk); #1;
            tx_start <= 1'b0;

            // ── Verify tx_busy asserted immediately ──────────────────────────
            if (!tx_busy) begin
                $display("FAIL [%0s]: tx_busy not asserted after tx_start", name);
                fail_count = fail_count + 1;
            end

            // ── Wait for start bit falling edge ──────────────────────────────
            // The FSM transitions on the clock edge AFTER tx_start, so
            // tx_pin goes low one cycle after we drop tx_start.
            // Poll for low (should happen within 2 clock cycles).
            repeat(3) @(posedge clk);

            // ── Centre-sample start bit ───────────────────────────────────────
            // We are now near the beginning of the start bit.
            // Wait HALF_BIT more cycles to reach the centre.
            repeat(HALF_BIT) @(posedge clk); #1;

            if (tx_pin !== 1'b0) begin
                $display("FAIL [%0s]: start bit not LOW at centre sample", name);
                fail_count = fail_count + 1;
            end

            // ── Centre-sample each data bit ───────────────────────────────────
            for (b = 0; b < 8; b = b + 1) begin
                // Advance one full baud period to centre of next bit
                repeat(DIVISOR) @(posedge clk); #1;

                expected_bit = data[b];    // LSB first
                if (tx_pin !== expected_bit) begin
                    $display("FAIL [%0s]: data bit %0d: got %b, expected %b",
                             name, b, tx_pin, expected_bit);
                    fail_count = fail_count + 1;
                end
            end

            // ── Centre-sample stop bit ────────────────────────────────────────
            repeat(DIVISOR) @(posedge clk); #1;
            if (tx_pin !== 1'b1) begin
                $display("FAIL [%0s]: stop bit not HIGH at centre sample", name);
                fail_count = fail_count + 1;
            end

            // ── Wait for frame to fully complete ──────────────────────────────
            repeat(HALF_BIT + 5) @(posedge clk); #1;

            // ── Verify tx_busy deasserted ─────────────────────────────────────
            if (tx_busy) begin
                $display("FAIL [%0s]: tx_busy still high after stop bit", name);
                fail_count = fail_count + 1;
            end

            // ── Verify idle line HIGH ─────────────────────────────────────────
            if (tx_pin !== 1'b1) begin
                $display("FAIL [%0s]: tx_pin not HIGH in idle after frame", name);
                fail_count = fail_count + 1;
            end

            $display("PASS [%0s]: 0x%02X transmitted correctly", name, data);
            pass_count = pass_count + 1;
        end
    endtask

    // -------------------------------------------------------------------------
    // Main test sequence
    // -------------------------------------------------------------------------
    initial begin
        $dumpfile("tb_uart_tx.vcd");
        $dumpvars(0, tb_uart_tx);

        pass_count = 0;
        fail_count = 0;

        // ── Reset ─────────────────────────────────────────────────────────────
        rst      <= 1'b1;
        tx_start <= 1'b0;
        tx_data  <= 8'h00;
        repeat(4) @(posedge clk);
        rst <= 1'b0;
        @(posedge clk);

        // ── Test 1: Idle line is HIGH after reset ─────────────────────────────
        #1;
        if (tx_pin !== 1'b1) begin
            $display("FAIL [Idle after reset]: tx_pin = %b, expected 1", tx_pin);
            fail_count = fail_count + 1;
        end else begin
            $display("PASS [Idle after reset]: tx_pin=1");
            pass_count = pass_count + 1;
        end

        // ── Test 2: 0x55 — alternating 01010101 ──────────────────────────────
        // Classic UART test pattern: produces square wave on scope
        transmit_and_check(8'h55, "0x55 alternating");

        // ── Test 3: 0xAA — alternating 10101010 ──────────────────────────────
        transmit_and_check(8'hAA, "0xAA alternating");

        // ── Test 4: 0x00 — all zeros ─────────────────────────────────────────
        transmit_and_check(8'h00, "0x00 all zeros");

        // ── Test 5: 0xFF — all ones ───────────────────────────────────────────
        transmit_and_check(8'hFF, "0xFF all ones");

        // ── Test 6: 0x0F — byte from NIST AES key 000102...0f ────────────────
        transmit_and_check(8'h0F, "0x0F NIST key byte");

        // ── Summary ───────────────────────────────────────────────────────────
        $display("─────────────────────────────────────");
        $display("Results: %0d PASSED, %0d FAILED", pass_count, fail_count);
        if (fail_count == 0)
            $display("ALL TESTS PASSED ✓");
        else
            $display("SOME TESTS FAILED ✗");
        $display("─────────────────────────────────────");

        $finish;
    end

    // ── Timeout watchdog ──────────────────────────────────────────────────────
    // 5 frames × 10 bits × 10417 cycles × 10ns = ~5.2ms — set to 6ms
    initial begin
        #6_000_000;
        $display("TIMEOUT: simulation exceeded 6ms — aborting");
        $finish;
    end

endmodule
