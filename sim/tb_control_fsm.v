// =============================================================================
// Testbench:   tb_control_fsm
// File:        sim/tb_control_fsm.v
// Description: Self-checking testbench for control_fsm.
//
// This testbench instantiates the control_fsm and provides behavioural
// models for uart_rx, uart_tx, aes_core, and hamming_weight rather than
// instantiating the real modules. This isolates the FSM logic and runs
// much faster than a full system simulation.
//
// Test cases:
//   1. Full protocol loopback with NIST vector:
//      PT  = 00112233445566778899aabbccddeeff
//      Key = 000102030405060708090a0b0c0d0e0f
//      CT  = 69c4e0d86a7b0430d8cdb78070b4c55a  (verified NIST result)
//      HW  = known value from mock AES model
//   2. Second encryption — verify FSM returns to WAIT_DATA correctly
//   3. Verify led_busy toggles correctly (low in WAIT_DATA, high during work)
//
// Behavioural models used (not the real modules):
//   - rx_driver:  drives rx_valid/rx_data pulses to simulate uart_rx
//   - tx_monitor: watches tx_start/tx_data, simulates tx_busy, captures bytes
//   - aes_model:  responds to aes_start with aes_done + known ciphertext
//   - hw_model:   responds to hw_load with hw_valid + known hw_out
// =============================================================================

`timescale 1ns / 1ps

module tb_control_fsm;

    // -------------------------------------------------------------------------
    // Parameters
    // -------------------------------------------------------------------------
    parameter CLK_PERIOD  = 10;      // 100 MHz
    // Simulated UART byte time — drastically reduced for testbench speed.
    // Real UART = 10417 cycles; use 20 cycles here so the FSM doesn't wait
    // 1ms per byte. The FSM only cares about tx_busy deasserting, not timing.
    parameter UART_DELAY  = 20;

    // -------------------------------------------------------------------------
    // DUT ports
    // -------------------------------------------------------------------------
    reg         clk, rst;

    // UART RX → FSM
    reg         rx_valid;
    reg  [7:0]  rx_data;

    // FSM → UART TX
    wire        tx_start;
    wire [7:0]  tx_data;
    reg         tx_busy;

    // FSM → AES core
    wire        aes_start;
    wire [127:0] aes_plaintext;
    wire [127:0] aes_key;
    reg         aes_done;
    reg  [127:0] aes_ciphertext;

    // FSM → HW monitor
    wire        hw_load;
    reg         hw_valid;
    reg  [7:0]  hw_out;

    // FSM status
    wire        led_busy;

    integer pass_count, fail_count;

    // -------------------------------------------------------------------------
    // DUT instantiation
    // -------------------------------------------------------------------------
    control_fsm dut (
        .clk          (clk),
        .rst          (rst),
        .rx_valid     (rx_valid),
        .rx_data      (rx_data),
        .tx_busy      (tx_busy),
        .tx_start     (tx_start),
        .tx_data      (tx_data),
        .aes_start    (aes_start),
        .aes_plaintext(aes_plaintext),
        .aes_key      (aes_key),
        .aes_done     (aes_done),
        .aes_ciphertext(aes_ciphertext),
        .hw_load      (hw_load),
        .hw_valid     (hw_valid),
        .hw_out       (hw_out),
        .led_busy     (led_busy)
    );

    // -------------------------------------------------------------------------
    // Clock
    // -------------------------------------------------------------------------
    initial clk = 0;
    always #(CLK_PERIOD/2) clk = ~clk;

    // -------------------------------------------------------------------------
    // AES behavioural model
    // Responds to aes_start with aes_done after a short delay.
    // Returns the NIST ciphertext for the NIST key/plaintext pair.
    // For all other inputs, returns a fixed dummy ciphertext.
    // -------------------------------------------------------------------------
    always @(posedge clk) begin
        aes_done <= 1'b0;  // default
        if (aes_start) begin
            // Simulate ~12 clock cycles of AES computation
            repeat(12) @(posedge clk);
            // Return NIST ciphertext regardless of input (model is simplified)
            aes_ciphertext <= 128'h69c4e0d8_6a7b0430_d8cdb780_70b4c55a;
            aes_done <= 1'b1;
            @(posedge clk);
            aes_done <= 1'b0;
        end
    end

    // -------------------------------------------------------------------------
    // HW monitor behavioural model
    // Responds to hw_load with hw_valid after 2 cycles (matches real module).
    // Returns a fixed HW value of 58 (matching NIST SubBytes output).
    // -------------------------------------------------------------------------
    always @(posedge clk) begin
        hw_valid <= 1'b0;
        if (hw_load) begin
            @(posedge clk);
            @(posedge clk);
            hw_out   <= 8'd58;
            hw_valid <= 1'b1;   // sticky — hold high
        end
    end

    // -------------------------------------------------------------------------
    // UART TX behavioural model
    // When tx_start asserts: capture tx_data, assert tx_busy for UART_DELAY
    // cycles, then deassert. Stores captured bytes for verification.
    // -------------------------------------------------------------------------
    reg [7:0] tx_captured [0:16];  // up to 17 bytes (16 CT + 1 HW)
    integer   tx_count;
    integer   tx_done;             // flag: all 17 bytes received

    initial begin
        tx_busy    = 0;
        tx_count   = 0;
        tx_done    = 0;
    end

    always @(posedge clk) begin
        if (tx_start && !tx_busy) begin
            tx_captured[tx_count] = tx_data;
            tx_count = tx_count + 1;
            if (tx_count == 17) tx_done = 1;
            tx_busy = 1;
            repeat(UART_DELAY) @(posedge clk);
            tx_busy = 0;
        end
    end

    // -------------------------------------------------------------------------
    // Task: send one byte to FSM via rx_valid/rx_data
    // -------------------------------------------------------------------------
    task send_byte;
        input [7:0] b;
        begin
            @(posedge clk); #1;
            rx_data  <= b;
            rx_valid <= 1'b1;
            @(posedge clk); #1;
            rx_valid <= 1'b0;
        end
    endtask

    // -------------------------------------------------------------------------
    // Task: send 32-byte frame (16 plaintext + 16 key bytes)
    // -------------------------------------------------------------------------
    task send_frame;
        input [127:0] pt;
        input [127:0] key;
        integer       k;
        begin
            // Send plaintext bytes 0–15 (MSB first = byte 0 first)
            for (k = 0; k < 16; k = k + 1)
                send_byte(pt[(127 - k*8) -: 8]);
            // Send key bytes 0–15
            for (k = 0; k < 16; k = k + 1)
                send_byte(key[(127 - k*8) -: 8]);
        end
    endtask

    // -------------------------------------------------------------------------
    // Task: wait for all 17 TX bytes with timeout
    // -------------------------------------------------------------------------
    task wait_for_result;
        integer timeout;
        begin
            timeout = 0;
            tx_done = 0;
            tx_count = 0;
            while (!tx_done && timeout < 5000) begin
                @(posedge clk);
                timeout = timeout + 1;
            end
            if (!tx_done) begin
                $display("FAIL: Timed out waiting for 17 TX bytes (got %0d)",
                         tx_count);
                fail_count = fail_count + 1;
            end
        end
    endtask

    // -------------------------------------------------------------------------
    // Main test sequence
    // -------------------------------------------------------------------------
    initial begin
        $dumpfile("tb_control_fsm.vcd");
        $dumpvars(0, tb_control_fsm);

        pass_count = 0;
        fail_count = 0;

        // Initialise inputs
        rx_valid     = 0;
        rx_data      = 0;
        tx_busy      = 0;
        aes_done     = 0;
        aes_ciphertext = 128'd0;
        hw_valid     = 0;
        hw_out       = 0;

        // ── Reset ─────────────────────────────────────────────────────────────
        rst = 1;
        repeat(4) @(posedge clk);
        rst = 0;
        repeat(2) @(posedge clk);

        // ── Verify idle state ─────────────────────────────────────────────────
        #1;
        if (led_busy !== 1'b0) begin
            $display("FAIL [Idle]: led_busy should be 0 in WAIT_DATA");
            fail_count = fail_count + 1;
        end else begin
            $display("PASS [Idle]: led_busy=0 in WAIT_DATA");
            pass_count = pass_count + 1;
        end

        // ── Test 1: NIST vector encryption ────────────────────────────────────
        $display("INFO: Sending NIST vector frame...");
        send_frame(
            128'h00112233_44556677_8899aabb_ccddeeff,  // plaintext
            128'h00010203_04050607_08090a0b_0c0d0e0f   // key
        );

        // Wait for led_busy to assert (FSM left WAIT_DATA)
        repeat(5) @(posedge clk); #1;
        if (!led_busy) begin
            $display("FAIL [Busy]: led_busy should assert after frame received");
            fail_count = fail_count + 1;
        end else begin
            $display("PASS [Busy]: led_busy asserted during encryption");
            pass_count = pass_count + 1;
        end

        // Wait for all 17 bytes to be transmitted
        wait_for_result;

        // ── Verify ciphertext bytes 0–15 ──────────────────────────────────────
        begin : check_ct
            reg [127:0] expected_ct;
            reg [127:0] got_ct;
            integer     m;
            expected_ct = 128'h69c4e0d8_6a7b0430_d8cdb780_70b4c55a;
            got_ct = 128'd0;
            for (m = 0; m < 16; m = m + 1)
                got_ct[(127 - m*8) -: 8] = tx_captured[m];

            if (got_ct !== expected_ct) begin
                $display("FAIL [Ciphertext]: got %032x, expected %032x",
                         got_ct, expected_ct);
                fail_count = fail_count + 1;
            end else begin
                $display("PASS [Ciphertext]: 69c4e0d86a7b0430d8cdb78070b4c55a");
                pass_count = pass_count + 1;
            end
        end

        // ── Verify HW byte (byte 16) ──────────────────────────────────────────
        if (tx_captured[16] !== 8'd58) begin
            $display("FAIL [HW byte]: got %0d, expected 58", tx_captured[16]);
            fail_count = fail_count + 1;
        end else begin
            $display("PASS [HW byte]: HW=58 transmitted correctly");
            pass_count = pass_count + 1;
        end

        // ── Test 2: Second frame — verify FSM returned to WAIT_DATA ───────────
        // Wait for led_busy to clear (FSM back in WAIT_DATA)
        repeat(50) @(posedge clk);
        if (led_busy) begin
            $display("FAIL [Return to WAIT_DATA]: led_busy still high");
            fail_count = fail_count + 1;
        end else begin
            $display("PASS [Return to WAIT_DATA]: led_busy deasserted");
            pass_count = pass_count + 1;
        end

        // Send a second frame and verify it completes
        $display("INFO: Sending second frame to verify FSM reset...");
        send_frame(
            128'hdeadbeef_cafebabe_12345678_9abcdef0,
            128'h000102030405060708090a0b0c0d0e0f
        );
        wait_for_result;

        if (tx_done) begin
            $display("PASS [Second frame]: FSM completed second encryption");
            pass_count = pass_count + 1;
        end else begin
            $display("FAIL [Second frame]: FSM did not complete");
            fail_count = fail_count + 1;
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
    initial begin
        #10_000_000;
        $display("TIMEOUT: simulation exceeded 10ms — aborting");
        $finish;
    end

endmodule
