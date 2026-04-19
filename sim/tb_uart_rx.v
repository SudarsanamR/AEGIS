// =============================================================================
// Testbench:   tb_uart_rx
// File:        sim/tb_uart_rx.v
// Description: Self-checking testbench for the uart_rx module.
//
// Verification strategy:
//   The testbench drives rx_pin directly, constructing valid 8N1 frames
//   bit-by-bit at the correct baud period. After each frame, it waits
//   for rx_valid and checks rx_data matches the sent byte.
//
// Test cases:
//   1. Receive 0x55 (01010101) — alternating bits
//   2. Receive 0xAA (10101010) — complement
//   3. Receive 0x00 (all zeros)
//   4. Receive 0xFF (all ones)
//   5. Receive 0x0F — NIST key byte
//   6. Glitch rejection: short LOW pulse shorter than HALF_DIVISOR cycles
//      should NOT trigger a receive
//   7. Back-to-back frames with no gap — verify both received correctly
//
// Frame construction:
//   drive_frame task drives rx_pin LOW for start, then each data bit
//   LSB-first for DIVISOR cycles each, then HIGH for stop bit.
// =============================================================================

`timescale 1ns / 1ps

module tb_uart_rx;

    // -------------------------------------------------------------------------
    // Parameters — must match DUT
    // -------------------------------------------------------------------------
    parameter DIVISOR    = 10417;
    parameter CLK_PERIOD = 10;

    // -------------------------------------------------------------------------
    // DUT signals
    // -------------------------------------------------------------------------
    reg        clk;
    reg        rst;
    reg        rx_pin;
    wire [7:0] rx_data;
    wire       rx_valid;

    integer pass_count;
    integer fail_count;

    // -------------------------------------------------------------------------
    // DUT instantiation
    // -------------------------------------------------------------------------
    uart_rx #(.DIVISOR(DIVISOR)) dut (
        .clk      (clk),
        .rst      (rst),
        .rx_pin   (rx_pin),
        .rx_data  (rx_data),
        .rx_valid (rx_valid)
    );

    // -------------------------------------------------------------------------
    // 100 MHz clock
    // -------------------------------------------------------------------------
    initial clk = 0;
    always #(CLK_PERIOD/2) clk = ~clk;

    // -------------------------------------------------------------------------
    // Task: drive a single byte as a valid 8N1 UART frame onto rx_pin
    // Bit order: start(0), D0, D1, D2, D3, D4, D5, D6, D7, stop(1)
    // Each bit held for exactly DIVISOR clock cycles.
    // -------------------------------------------------------------------------
    task drive_frame;
        input [7:0] data;
        integer     b;
        begin
            // Start bit: LOW for one baud period
            rx_pin = 1'b0;
            repeat(DIVISOR) @(posedge clk);

            // Data bits: LSB first, one per baud period
            for (b = 0; b < 8; b = b + 1) begin
                rx_pin = data[b];
                repeat(DIVISOR) @(posedge clk);
            end

            // Stop bit: HIGH for one baud period
            rx_pin = 1'b1;
            repeat(DIVISOR) @(posedge clk);
        end
    endtask

    // -------------------------------------------------------------------------
    // Task: drive frame and verify rx_data matches expected.
    //
    // rx_valid is a ONE-CYCLE PULSE fired during the stop bit sample.
    // The monitor must run CONCURRENTLY with drive_frame using fork..join,
    // otherwise the pulse fires and disappears before the polling loop runs.
    // -------------------------------------------------------------------------
    task receive_and_check;
        input [7:0]   data;
        input [255:0] name;
        reg           got_valid;
        reg [7:0]     captured_data;
        integer       timeout;
        begin
            got_valid     = 0;
            captured_data = 0;

            // Drive the frame and monitor rx_valid in parallel.
            // The monitor runs for the full frame duration + 2×DIVISOR margin.
            fork
                // Thread 1: drive the serial frame onto rx_pin
                drive_frame(data);

                // Thread 2: watch for rx_valid pulse (runs concurrently)
                begin
                    timeout = 0;
                    // Total frame = 10 bits × DIVISOR cycles; add 2× margin
                    while (!got_valid && timeout < DIVISOR * 12) begin
                        @(posedge clk); #1;
                        if (rx_valid) begin
                            got_valid     = 1;
                            captured_data = rx_data;
                        end
                        timeout = timeout + 1;
                    end
                end
            join

            // Both threads have finished — evaluate result
            if (!got_valid) begin
                $display("FAIL [%0s]: rx_valid never asserted", name);
                fail_count = fail_count + 1;
            end else if (captured_data !== data) begin
                $display("FAIL [%0s]: got 0x%02X, expected 0x%02X",
                         name, captured_data, data);
                fail_count = fail_count + 1;
            end else begin
                $display("PASS [%0s]: received 0x%02X correctly", name, data);
                pass_count = pass_count + 1;
            end

            // Small inter-frame gap — idle line stays HIGH
            repeat(10) @(posedge clk);
        end
    endtask

    // -------------------------------------------------------------------------
    // Main test sequence
    // -------------------------------------------------------------------------
    initial begin
        $dumpfile("tb_uart_rx.vcd");
        $dumpvars(0, tb_uart_rx);

        pass_count = 0;
        fail_count = 0;

        // ── Reset ─────────────────────────────────────────────────────────────
        rst    = 1'b1;
        rx_pin = 1'b1;   // idle HIGH during reset
        repeat(4) @(posedge clk);
        rst = 1'b0;
        repeat(2) @(posedge clk);

        // ── Test 1: Idle line stays HIGH, rx_valid not asserted ───────────────
        repeat(20) @(posedge clk);
        if (rx_valid) begin
            $display("FAIL [Idle check]: rx_valid asserted with no frame");
            fail_count = fail_count + 1;
        end else begin
            $display("PASS [Idle check]: rx_valid correctly deasserted");
            pass_count = pass_count + 1;
        end

        // ── Test 2: Glitch rejection ──────────────────────────────────────────
        // Drive rx_pin LOW for only DIVISOR/4 cycles (shorter than half-bit).
        // The FSM should abort in START state (centre sample will see HIGH
        // because we've already released the pin by then).
        rx_pin = 1'b0;
        repeat(DIVISOR / 4) @(posedge clk);  // short glitch
        rx_pin = 1'b1;
        // Wait long enough for the FSM to process and reject
        repeat(DIVISOR * 2) @(posedge clk);
        if (rx_valid) begin
            $display("FAIL [Glitch rejection]: rx_valid asserted on glitch");
            fail_count = fail_count + 1;
        end else begin
            $display("PASS [Glitch rejection]: short pulse correctly ignored");
            pass_count = pass_count + 1;
        end

        // ── Test 3: 0x55 — alternating 01010101 ──────────────────────────────
        receive_and_check(8'h55, "0x55 alternating");

        // ── Test 4: 0xAA — alternating 10101010 ──────────────────────────────
        receive_and_check(8'hAA, "0xAA alternating");

        // ── Test 5: 0x00 — all zeros ──────────────────────────────────────────
        receive_and_check(8'h00, "0x00 all zeros");

        // ── Test 6: 0xFF — all ones ───────────────────────────────────────────
        receive_and_check(8'hFF, "0xFF all ones");

        // ── Test 7: 0x0F — NIST AES key byte ─────────────────────────────────
        receive_and_check(8'h0F, "0x0F NIST key byte");

        // ── Test 8: Back-to-back frames with no inter-frame gap ───────────────
        // Drive two frames immediately one after the other (stop bit of
        // frame 1 is immediately followed by start bit of frame 2).
        // Both must be received correctly.
        begin : back_to_back
            reg       got_v1, got_v2;
            reg [7:0] cap1,   cap2;
            integer   tbb;

            got_v1 = 0; got_v2 = 0;
            cap1   = 0; cap2   = 0;

            fork
                // Thread 1: drive both frames back-to-back
                begin
                    drive_frame(8'hA5);
                    drive_frame(8'h5A);
                end

                // Thread 2: monitor for both rx_valid pulses
                begin
                    tbb = 0;
                    while ((!got_v1 || !got_v2) && tbb < DIVISOR * 24) begin
                        @(posedge clk); #1;
                        if (rx_valid) begin
                            if (!got_v1) begin
                                got_v1 = 1;
                                cap1   = rx_data;
                            end else if (!got_v2) begin
                                got_v2 = 1;
                                cap2   = rx_data;
                            end
                        end
                        tbb = tbb + 1;
                    end
                end
            join

            if (!got_v1 || cap1 !== 8'hA5) begin
                $display("FAIL [Back-to-back frame 1]: got 0x%02X valid=%b",
                         cap1, got_v1);
                fail_count = fail_count + 1;
            end else begin
                $display("PASS [Back-to-back frame 1]: 0xA5 received correctly");
                pass_count = pass_count + 1;
            end

            if (!got_v2 || cap2 !== 8'h5A) begin
                $display("FAIL [Back-to-back frame 2]: got 0x%02X valid=%b",
                         cap2, got_v2);
                fail_count = fail_count + 1;
            end else begin
                $display("PASS [Back-to-back frame 2]: 0x5A received correctly");
                pass_count = pass_count + 1;
            end
        end

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
    // 9 frames × 10 bits × 10417 cycles × 10ns ≈ 9.4ms — set to 12ms
    initial begin
        #12_000_000;
        $display("TIMEOUT: simulation exceeded 12ms — aborting");
        $finish;
    end

endmodule
