// =============================================================================
// Testbench:   tb_aes_vulnerable
// File:        sim/tb_aes_vulnerable.v
// Description: System-level testbench for aes_vulnerable top-level.
//              Instantiates the FULL design (all real modules) and drives
//              the UART RX pin directly, then receives and verifies the
//              UART TX output.
//
// This test exercises the complete datapath end-to-end:
//   PC(sim) → UART RX → Control FSM → AES Core → HW Monitor
//          → Control FSM → UART TX → PC(sim)
//
// DIVISOR is overridden to 20 cycles for simulation speed.
// All modules are instantiated via aes_vulnerable, which uses the real
// DIVISOR parameter — we override it at the top module level.
//
// Test:
//   Send NIST vector (PT + Key over UART), receive CT + HW byte.
//   Verify CT = 69c4e0d86a7b0430d8cdb78070b4c55a  (verified: OpenSSL AES-128-ECB)
//   Verify HW byte is non-zero (exact value depends on round-10 SubBytes)
// =============================================================================

`timescale 1ns / 1ps

module tb_aes_vulnerable;

    // -------------------------------------------------------------------------
    // Override DIVISOR for sim speed — 20 cycles instead of 10417
    // This is passed into aes_vulnerable via defparam on the sub-instances.
    // Since aes_vulnerable doesn't expose DIVISOR as a parameter, we use
    // defparam to reach into the UART instances.
    // -------------------------------------------------------------------------
    parameter SIM_DIVISOR = 20;
    parameter CLK_PERIOD  = 10;

    // -------------------------------------------------------------------------
    // DUT ports
    // -------------------------------------------------------------------------
    reg  clk, rst;
    reg  rx_pin;
    wire tx_pin;
    wire led_busy;

    integer pass_count, fail_count;

    // -------------------------------------------------------------------------
    // DUT instantiation
    // -------------------------------------------------------------------------
    aes_vulnerable u_dut (
        .clk     (clk),
        .rst     (rst),
        .rx_pin  (rx_pin),
        .tx_pin  (tx_pin),
        .led_busy(led_busy)
    );

    // Override UART baud divisor for simulation speed
    defparam u_dut.u_uart_rx.DIVISOR = SIM_DIVISOR;
    defparam u_dut.u_uart_tx.DIVISOR = SIM_DIVISOR;

    // -------------------------------------------------------------------------
    // Clock
    // -------------------------------------------------------------------------
    initial clk = 0;
    always #(CLK_PERIOD/2) clk = ~clk;

    // -------------------------------------------------------------------------
    // Task: drive one byte as a UART frame onto rx_pin (sim baud rate)
    // -------------------------------------------------------------------------
    task uart_send_byte;
        input [7:0] data;
        integer     b;
        begin
            rx_pin = 1'b0;                        // start bit
            repeat(SIM_DIVISOR) @(posedge clk);
            for (b = 0; b < 8; b = b + 1) begin   // data bits LSB first
                rx_pin = data[b];
                repeat(SIM_DIVISOR) @(posedge clk);
            end
            rx_pin = 1'b1;                        // stop bit
            repeat(SIM_DIVISOR) @(posedge clk);
        end
    endtask

    // -------------------------------------------------------------------------
    // Task: receive one byte from tx_pin by centre-sampling
    // Returns received byte in out_byte.
    // -------------------------------------------------------------------------
    task uart_recv_byte;
        output [7:0] out_byte;
        integer      b;
        reg [7:0]    rxd;
        begin
            // Wait for start bit (falling edge)
            @(negedge tx_pin);
            // Wait to centre of start bit
            repeat(SIM_DIVISOR/2) @(posedge clk);
            // Sample 8 data bits
            rxd = 8'h00;
            for (b = 0; b < 8; b = b + 1) begin
                repeat(SIM_DIVISOR) @(posedge clk); #1;
                rxd[b] = tx_pin;
            end
            // Wait through stop bit
            repeat(SIM_DIVISOR) @(posedge clk);
            out_byte = rxd;
        end
    endtask

    // -------------------------------------------------------------------------
    // Main test
    // -------------------------------------------------------------------------
    reg [7:0]   rx_bytes [0:16];  // received CT (16) + HW (1)
    reg [127:0] rx_ct;
    integer     k;

    initial begin
        $dumpfile("tb_aes_vulnerable.vcd");
        $dumpvars(0, tb_aes_vulnerable);

        pass_count = 0;
        fail_count = 0;
        rx_pin = 1'b1;   // idle HIGH

        // ── Reset ─────────────────────────────────────────────────────────────
        rst = 1;
        repeat(4) @(posedge clk);
        rst = 0;
        repeat(4) @(posedge clk);

        // ── Send NIST plaintext (16 bytes) ────────────────────────────────────
        $display("INFO: Sending NIST plaintext...");
        uart_send_byte(8'h00); uart_send_byte(8'h11);
        uart_send_byte(8'h22); uart_send_byte(8'h33);
        uart_send_byte(8'h44); uart_send_byte(8'h55);
        uart_send_byte(8'h66); uart_send_byte(8'h77);
        uart_send_byte(8'h88); uart_send_byte(8'h99);
        uart_send_byte(8'haa); uart_send_byte(8'hbb);
        uart_send_byte(8'hcc); uart_send_byte(8'hdd);
        uart_send_byte(8'hee); uart_send_byte(8'hff);

        // ── Send NIST key (16 bytes) ──────────────────────────────────────────
        $display("INFO: Sending NIST key...");
        uart_send_byte(8'h00); uart_send_byte(8'h01);
        uart_send_byte(8'h02); uart_send_byte(8'h03);
        uart_send_byte(8'h04); uart_send_byte(8'h05);
        uart_send_byte(8'h06); uart_send_byte(8'h07);
        uart_send_byte(8'h08); uart_send_byte(8'h09);
        uart_send_byte(8'h0a); uart_send_byte(8'h0b);
        uart_send_byte(8'h0c); uart_send_byte(8'h0d);
        uart_send_byte(8'h0e); uart_send_byte(8'h0f);

        // ── Receive 17 bytes (16 CT + 1 HW) ──────────────────────────────────
        $display("INFO: Receiving ciphertext + HW byte...");
        for (k = 0; k < 17; k = k + 1)
            uart_recv_byte(rx_bytes[k]);

        // ── Verify ciphertext ─────────────────────────────────────────────────
        rx_ct = 128'd0;
        for (k = 0; k < 16; k = k + 1)
            rx_ct[(127 - k*8) -: 8] = rx_bytes[k];

        // MODIFIED: correct ciphertext verified by OpenSSL AES-128-ECB
        // AES-128(key=000102..0f, pt=001122..ff) = 69c4e0d86a7b0430d8cdb78070b4c55a
        if (rx_ct !== 128'h69c4e0d8_6a7b0430_d8cdb780_70b4c55a) begin
            $display("FAIL [Ciphertext]: got      %032x", rx_ct);
            $display("     expected:               69c4e0d86a7b0430d8cdb78070b4c55a");
            fail_count = fail_count + 1;
        end else begin
            $display("PASS [Ciphertext]: %032x", rx_ct);
            pass_count = pass_count + 1;
        end

        // ── Verify HW byte is non-zero ────────────────────────────────────────
        // Exact value depends on which round's SubBytes is captured.
        // We verify non-zero (all-zero would indicate a wiring bug).
        $display("INFO: HW byte received = %0d (0x%02x)",
                 rx_bytes[16], rx_bytes[16]);
        if (rx_bytes[16] === 8'h00) begin
            $display("FAIL [HW byte]: HW=0 suggests wiring error");
            fail_count = fail_count + 1;
        end else begin
            $display("PASS [HW byte]: HW=%0d (non-zero, leakage present)",
                     rx_bytes[16]);
            pass_count = pass_count + 1;
        end

        // ── Verify led_busy deasserted ────────────────────────────────────────
        repeat(10) @(posedge clk); #1;
        if (led_busy) begin
            $display("FAIL [led_busy]: still high after result sent");
            fail_count = fail_count + 1;
        end else begin
            $display("PASS [led_busy]: deasserted after result sent");
            pass_count = pass_count + 1;
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
    // 33 frames × SIM_DIVISOR × 10 bits × 10 ns = ~66,000 ns + AES overhead
    initial begin
        #500_000;
        $display("TIMEOUT: simulation exceeded 500us — aborting");
        $finish;
    end

endmodule
