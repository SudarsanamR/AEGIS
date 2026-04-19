// =============================================================================
// Testbench: tb_aes_core_masked
// File:      sim/tb_aes_core_masked.v
// Project:   AEGIS — Act 2, Step 4.4
//
// Tests:
//   Test 1 — NIST vector:
//     pt=00112233445566778899aabbccddeeff, key=000102030405060708090a0b0c0d0e0f
//     Expected ciphertext: 69c4e0d86a7b0430d8cdb78070b4c55a
//     (Verified against Python cryptography library.)
//
//   Test 2 — All-zero plaintext and key:
//     Expected: 66e94bd4ef8a2c3b884cfa59ca342b2e
//     (Verified against Python cryptography library.)
//
//   Test 3 — All-FF plaintext, all-zero key:
//     Expected: 3f5b8cc9ea855a0afa7347d23e8d664e
//
//   Test 4 — Consecutive encryptions, no re-assertion of reset.
//     The mask state is not reset between Test 3 and 4.
//     Result must still be correct (mask sequence continues from where it left off).
//     pt=00112233445566778899aabbccddeeff again → same ciphertext as Test 1
//     (mask value doesn't affect correctness, only power trace appearance).
//
//   Test 5 — done deasserts one cycle after assertion.
//
//   Test 6 — Latency: done must assert exactly 12 cycles after start.
//     FSM: IDLE(start)→INIT(1)→ROUND×9(9)→FINAL(1)→DONE(1) = 12 cycles
// =============================================================================

`timescale 1ns / 1ps

module tb_aes_core_masked;

    // =========================================================================
    // DUT ports
    // =========================================================================
    reg         clk;
    reg         rst;
    reg         start;
    reg  [127:0] plaintext;
    reg  [127:0] key;
    wire [127:0] ciphertext;
    wire         done;

    // =========================================================================
    // DUT instantiation
    // =========================================================================
    aes_core_masked dut (
        .clk        (clk),
        .rst        (rst),
        .start      (start),
        .plaintext  (plaintext),
        .key        (key),
        .ciphertext (ciphertext),
        .done       (done)
    );

    // =========================================================================
    // 100 MHz clock
    // =========================================================================
    initial clk = 0;
    always #5 clk = ~clk;

    // =========================================================================
    // Test infrastructure
    // =========================================================================
    integer fail_count;
    integer cycle_count;
    integer i;

    // Helper: run one encryption and check result
    task run_and_check;
        input [127:0] pt;
        input [127:0] k;
        input [127:0] expected_ct;
        input integer  t_num;
        begin
            @(negedge clk);
            plaintext = pt;
            key       = k;
            start     = 1'b1;
            @(posedge clk); #1;
            start = 1'b0;

            // Wait for done
            @(posedge done); #1;

            if (ciphertext !== expected_ct) begin
                $display("FAIL  Test %0d: got      %h", t_num, ciphertext);
                $display("              expected  %h", expected_ct);
                fail_count = fail_count + 1;
            end else begin
                $display("PASS  Test %0d: ct=%h", t_num, ciphertext);
            end
        end
    endtask

    // =========================================================================
    // Stimulus
    // =========================================================================
    initial begin
        fail_count = 0;

        // Reset
        rst   = 1;
        start = 0;
        plaintext = 128'd0;
        key       = 128'd0;
        repeat (4) @(posedge clk);
        @(negedge clk); rst = 0;

        // -----------------------------------------------------------------
        // Test 1 — NIST primary vector
        // Expected: 69c4e0d86a7b0430d8cdb78070b4c55a
        // (Cryptography library verified; original spec had wrong value.)
        // -----------------------------------------------------------------
        run_and_check(
            128'h00112233445566778899aabbccddeeff,
            128'h000102030405060708090a0b0c0d0e0f,
            128'h69c4e0d86a7b0430d8cdb78070b4c55a,
            1);

        // Wait one idle cycle between encryptions
        repeat(2) @(posedge clk);

        // -----------------------------------------------------------------
        // Test 2 — All-zero plaintext and key
        // Expected: 66e94bd4ef8a2c3b884cfa59ca342b2e
        // -----------------------------------------------------------------
        run_and_check(
            128'h00000000000000000000000000000000,
            128'h00000000000000000000000000000000,
            128'h66e94bd4ef8a2c3b884cfa59ca342b2e,
            2);

        repeat(2) @(posedge clk);

        // -----------------------------------------------------------------
        // Test 3 — All-FF plaintext, all-zero key
        // Expected: 3f5b8cc9ea855a0afa7347d23e8d664e
        // -----------------------------------------------------------------
        run_and_check(
            128'hffffffffffffffffffffffffffffffff,
            128'h00000000000000000000000000000000,
            128'h3f5b8cc9ea855a0afa7347d23e8d664e,
            3);

        repeat(2) @(posedge clk);

        // -----------------------------------------------------------------
        // Test 4 — Consecutive encryption without re-reset
        //   Mask sequence continues where it left off.
        //   Correctness must be independent of mask value.
        // -----------------------------------------------------------------
        run_and_check(
            128'h00112233445566778899aabbccddeeff,
            128'h000102030405060708090a0b0c0d0e0f,
            128'h69c4e0d86a7b0430d8cdb78070b4c55a,
            4);

        repeat(2) @(posedge clk);

        // -----------------------------------------------------------------
        // Test 5 — done deasserts one cycle after assertion
        // -----------------------------------------------------------------
        @(negedge clk);
        plaintext = 128'h00112233445566778899aabbccddeeff;
        key       = 128'h000102030405060708090a0b0c0d0e0f;
        start     = 1'b1;
        @(posedge clk); #1; start = 1'b0;
        @(posedge done); #1;  // done is high NOW

        @(posedge clk); #1;   // one cycle later
        if (done !== 1'b0) begin
            $display("FAIL  Test 5: done should deassert after one cycle");
            fail_count = fail_count + 1;
        end else
            $display("PASS  Test 5: done deasserts after one cycle");

        repeat(2) @(posedge clk);

        // -----------------------------------------------------------------
        // Test 6 — Latency: exactly 12 cycles from start to done
        //   INIT(1) + ROUND×9(9) + FINAL(1) + DONE(1) = 12
        // -----------------------------------------------------------------
        @(negedge clk);
        plaintext   = 128'h00112233445566778899aabbccddeeff;
        key         = 128'h000102030405060708090a0b0c0d0e0f;
        start       = 1'b1;
        @(posedge clk); #1; start = 1'b0;  // this posedge is cycle 0

        cycle_count = 0;
        i           = 0;   // re-used as timeout flag (0=ok, 1=timed out)
        while (!done && i == 0) begin
            @(posedge clk); #1;
            cycle_count = cycle_count + 1;
            if (cycle_count > 20) begin
                $display("FAIL  Test 6: done never asserted (timeout)");
                fail_count = fail_count + 1;
                i = 1;     // break the loop without forward disable
            end
        end
        if (i == 0) begin
            if (cycle_count !== 12) begin
                $display("FAIL  Test 6: latency=%0d cycles, expected 12", cycle_count);
                fail_count = fail_count + 1;
            end else
                $display("PASS  Test 6: latency=%0d cycles", cycle_count);
        end

        // -----------------------------------------------------------------
        // Summary
        // -----------------------------------------------------------------
        $display("----------------------------------------");
        if (fail_count == 0)
            $display("ALL TESTS PASSED — aes_core_masked OK");
        else
            $display("FAILED: %0d test(s) did not pass", fail_count);
        $display("----------------------------------------");

        $finish;
    end

endmodule
