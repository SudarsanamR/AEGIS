// =============================================================================
// Testbench: tb_mask_refresh
// File:      sim/tb_mask_refresh.v
// Project:   AEGIS — Act 2, Step 4.3
//
// Tests:
//   Group 1 — Reset behaviour:
//     After rst=1, mask_out must equal seed regardless of prior state.
//
//   Group 2 — Deterministic sequence:
//     From seed=0xAC with enable=1 every cycle, verify the first 16
//     output values match the precomputed LFSR sequence exactly.
//     Sequence: AC 59 B2 65 CB 96 2C 58 B0 61 C3 87 0F 1F 3E 7D ...
//
//   Group 3 — Enable gating:
//     When enable=0 the register must hold its value for multiple cycles.
//     Verify no advance occurs across 5 idle cycles.
//
//   Group 4 — Re-seed during operation:
//     Assert rst mid-sequence with a different seed; verify it loads
//     immediately and produces the new sequence from that seed.
//
//   Group 5 — Period:
//     Run for 255 steps, collect all values, verify:
//       - No value repeats (period = 255)
//       - 0x00 never appears
//       - Step 255 returns to the original seed value
// =============================================================================

`timescale 1ns / 1ps

module tb_mask_refresh;

    // =========================================================================
    // DUT ports
    // =========================================================================
    reg        clk;
    reg        rst;
    reg  [7:0] seed;
    reg        enable;
    wire [7:0] mask_out;

    // =========================================================================
    // DUT instantiation
    // =========================================================================
    mask_refresh dut (
        .clk      (clk),
        .rst      (rst),
        .seed     (seed),
        .enable   (enable),
        .mask_out (mask_out)
    );

    // =========================================================================
    // 100 MHz clock — 10 ns period
    // =========================================================================
    initial clk = 0;
    always #5 clk = ~clk;

    // =========================================================================
    // Reference LFSR step function (task-local — no module dependency)
    // =========================================================================
    function [7:0] lfsr_next;
        input [7:0] state;
        reg new_bit;
        begin
            new_bit  = state[7] ^ state[5] ^ state[4] ^ state[3];
            lfsr_next = {state[6:0], new_bit};
        end
    endfunction

    // =========================================================================
    // Precomputed sequence from seed 0xAC (Python-verified, 255-period)
    // =========================================================================
    // AC 59 B2 65 CB 96 2C 58 B0 61 C3 87 0F 1F 3E 7D
    // FB F6 ED DB B7 6F DF BE 7C F8 F1 E3 C7 8E 1D 3B ...

    // =========================================================================
    // Test infrastructure
    // =========================================================================
    integer      fail_count;
    integer      i;
    reg  [7:0]   expected;
    reg  [7:0]   state_ref;
    reg  [7:0]   seen [0:255]; // for period test
    integer      seen_count;
    integer      zero_seen;
    integer      period_ok;

    // Helper: clock one edge with given enable
    task tick;
        input ena;
        begin
            @(negedge clk);        // set inputs just before rising edge
            enable = ena;
            @(posedge clk);        // rising edge advances DUT
            #1;                    // tiny propagation wait after clock
        end
    endtask

    // =========================================================================
    // Stimulus
    // =========================================================================
    initial begin
        fail_count = 0;

        // Initial conditions
        rst    = 1;
        seed   = 8'hAC;
        enable = 0;

        // -----------------------------------------------------------------
        // Group 1 — Reset behaviour
        // -----------------------------------------------------------------
        $display("--- Group 1: Reset behaviour ---");

        // Hold reset for 3 cycles, verify mask_out = seed throughout
        repeat (3) @(posedge clk); #1;
        if (mask_out !== 8'hAC) begin
            $display("FAIL  G1.1: rst=1, expected 0xAC, got 0x%02h", mask_out);
            fail_count = fail_count + 1;
        end else
            $display("PASS  G1.1: mask_out=0xAC during reset");

        // Change seed while rst=1, verify mask_out updates
        @(negedge clk); seed = 8'h5A; @(posedge clk); #1;
        if (mask_out !== 8'h5A) begin
            $display("FAIL  G1.2: new seed 0x5A during rst, got 0x%02h", mask_out);
            fail_count = fail_count + 1;
        end else
            $display("PASS  G1.2: mask_out follows seed during reset");

        // Restore seed=0xAC and release reset as TWO SEPARATE clock edges.
        // Bug pattern to avoid: assigning seed=X and rst=0 on the same negedge
        // means the posedge that follows sees rst=0 and does NOT load the seed —
        // the register just holds the previous value.
        // Correct sequence:
        //   Edge A: rst=1, seed=0xAC  → synchronous reset fires, loads 0xAC
        //   Edge B: rst=0, enable=0   → rst inactive, register holds 0xAC
        @(negedge clk); seed = 8'hAC;          // rst still 1 — do not release yet
        @(posedge clk); #1;                    // EDGE A: loads seed=0xAC
        if (mask_out !== 8'hAC) begin
            $display("FAIL  G1.3a: load seed=0xAC with rst=1, got 0x%02h", mask_out);
            fail_count = fail_count + 1;
        end else
            $display("PASS  G1.3a: mask_out=0xAC loaded while rst=1");

        @(negedge clk); rst = 0;               // now release reset
        @(posedge clk); #1;                    // EDGE B: rst=0, enable=0 — holds
        if (mask_out !== 8'hAC) begin
            $display("FAIL  G1.3b: rst release, expected 0xAC, got 0x%02h", mask_out);
            fail_count = fail_count + 1;
        end else
            $display("PASS  G1.3b: mask_out=0xAC stable after rst release");

        // -----------------------------------------------------------------
        // Group 2 — Deterministic sequence from seed 0xAC
        // -----------------------------------------------------------------
        $display("--- Group 2: Deterministic sequence ---");

        // Precomputed sequence (Python-verified):
        // Step 0 = 0xAC (held after reset), then each enable advances it.
        // The register holds 0xAC currently. Enable 15 times, check each output.
        begin : seq_check
            reg [7:0] exp_seq [0:15];
            exp_seq[ 0] = 8'hAC; // current state (no tick yet)
            exp_seq[ 1] = 8'h59;
            exp_seq[ 2] = 8'hB2;
            exp_seq[ 3] = 8'h65;
            exp_seq[ 4] = 8'hCB;
            exp_seq[ 5] = 8'h96;
            exp_seq[ 6] = 8'h2C;
            exp_seq[ 7] = 8'h58;
            exp_seq[ 8] = 8'hB0;
            exp_seq[ 9] = 8'h61;
            exp_seq[10] = 8'hC3;
            exp_seq[11] = 8'h87;
            exp_seq[12] = 8'h0F;
            exp_seq[13] = 8'h1F;
            exp_seq[14] = 8'h3E;
            exp_seq[15] = 8'h7D;

            // Check step 0 (current value)
            if (mask_out !== exp_seq[0]) begin
                $display("FAIL  G2 step 0: exp 0x%02h got 0x%02h",
                         exp_seq[0], mask_out);
                fail_count = fail_count + 1;
            end else
                $display("PASS  G2 step  0: 0x%02h", mask_out);

            // Enable once per step, check after each clock edge
            for (i = 1; i <= 15; i = i + 1) begin
                tick(1); // one enabled clock edge advances the LFSR
                if (mask_out !== exp_seq[i]) begin
                    $display("FAIL  G2 step %2d: exp 0x%02h got 0x%02h",
                             i, exp_seq[i], mask_out);
                    fail_count = fail_count + 1;
                end else
                    $display("PASS  G2 step %2d: 0x%02h", i, mask_out);
            end
        end

        // -----------------------------------------------------------------
        // Group 3 — Enable gating (no advance when enable=0)
        // -----------------------------------------------------------------
        $display("--- Group 3: Enable gating ---");
        // mask_out is currently 0x7D (step 15 above)
        expected = mask_out;
        for (i = 0; i < 5; i = i + 1) begin
            tick(0); // enable=0 — should not advance
            if (mask_out !== expected) begin
                $display("FAIL  G3 idle cycle %0d: expected 0x%02h got 0x%02h",
                         i, expected, mask_out);
                fail_count = fail_count + 1;
            end
        end
        $display("PASS  G3: mask_out stable for 5 idle cycles (0x%02h)", mask_out);

        // One enabled tick must advance it now
        expected = lfsr_next(mask_out);
        tick(1);
        if (mask_out !== expected) begin
            $display("FAIL  G3 advance after idle: exp 0x%02h got 0x%02h",
                     expected, mask_out);
            fail_count = fail_count + 1;
        end else
            $display("PASS  G3: advance after idle → 0x%02h", mask_out);

        // -----------------------------------------------------------------
        // Group 4 — Re-seed mid-sequence
        // -----------------------------------------------------------------
        $display("--- Group 4: Re-seed during operation ---");
        // Assert rst with new seed=0x33
        @(negedge clk); rst = 1; seed = 8'h33; enable = 0;
        @(posedge clk); #1;
        if (mask_out !== 8'h33) begin
            $display("FAIL  G4.1: re-seed 0x33, got 0x%02h", mask_out);
            fail_count = fail_count + 1;
        end else
            $display("PASS  G4.1: re-seed to 0x33");

        // Release rst, advance once, check matches lfsr_next(0x33)
        @(negedge clk); rst = 0; enable = 1;
        @(posedge clk); #1;
        expected = lfsr_next(8'h33); // = ?
        if (mask_out !== expected) begin
            $display("FAIL  G4.2: first step from 0x33: exp 0x%02h got 0x%02h",
                     expected, mask_out);
            fail_count = fail_count + 1;
        end else
            $display("PASS  G4.2: first step from 0x33 = 0x%02h", mask_out);

        // -----------------------------------------------------------------
        // Group 5 — Full period test
        // -----------------------------------------------------------------
        $display("--- Group 5: Full 255-step period test ---");

        // Re-seed to 0xAC
        @(negedge clk); rst = 1; seed = 8'hAC; enable = 0;
        @(posedge clk); #1;
        @(negedge clk); rst = 0;

        seen_count = 0;
        zero_seen  = 0;
        period_ok  = 1;

        // Clear seen array
        for (i = 0; i < 256; i = i + 1) seen[i] = 0;

        // Run 255 enabled steps, record each mask_out
        for (i = 0; i < 255; i = i + 1) begin
            // Check current value before advancing
            if (mask_out === 8'h00) begin
                $display("FAIL  G5: 0x00 appeared at step %0d", i);
                zero_seen = 1;
                fail_count = fail_count + 1;
            end
            if (seen[mask_out] !== 0) begin
                $display("FAIL  G5: repeated value 0x%02h at step %0d", mask_out, i);
                period_ok = 0;
                fail_count = fail_count + 1;
            end
            seen[mask_out] = 1;
            seen_count = seen_count + 1;
            tick(1);
        end

        // After 255 steps the LFSR must be back at seed
        if (mask_out !== 8'hAC) begin
            $display("FAIL  G5: after 255 steps expected 0xAC (seed), got 0x%02h",
                     mask_out);
            fail_count = fail_count + 1;
            period_ok = 0;
        end

        if (seen_count !== 255) begin
            $display("FAIL  G5: only %0d distinct values seen (expected 255)",
                     seen_count);
            fail_count = fail_count + 1;
        end

        if (period_ok && !zero_seen)
            $display("PASS  G5: 255 unique non-zero values, period=255, wraps to 0xAC");
        else
            $display("FAIL  G5: period test failed");

        // -----------------------------------------------------------------
        // Summary
        // -----------------------------------------------------------------
        $display("----------------------------------------");
        if (fail_count == 0)
            $display("ALL TESTS PASSED — mask_refresh OK");
        else
            $display("FAILED: %0d test(s) did not pass", fail_count);
        $display("----------------------------------------");

        $finish;
    end

endmodule
