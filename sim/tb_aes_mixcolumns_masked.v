// =============================================================================
// Testbench: tb_aes_mixcolumns_masked
// File:      sim/tb_aes_mixcolumns_masked.v
// Project:   AEGIS — Act 2, Step 4.2
//
// Tests:
//   Group 1 — Linearity invariant:
//     state_out XOR mask_in == MC(real_state)
//     Checked for multiple (state, mask_in) pairs.
//
//   Group 2 — NIST vector (zero mask):
//     After SubBytes on the NIST round-0 ARK output:
//       SubBytes result = 63cab7040953d051cd60e0e7ba70e18c
//     After ShiftRows:
//       63cab704 53d051cd e0e7ba70 098ce18c   (NIST App. B round 1)
//     MixColumns of that is the NIST round-1 state before ARK:
//       5f72641557f5bc92f7be3b291db9f91a
//     With mask_in=0, state_out must match exactly.
//
//   Group 3 — mask_out passthrough:
//     mask_out === mask_in for all test cases.
//
//   Group 4 — Edge cases:
//     All-zero state, all-FF state, mask_in=0xFF.
// =============================================================================

`timescale 1ns / 1ps

module tb_aes_mixcolumns_masked;

    // =========================================================================
    // DUT ports
    // =========================================================================
    reg  [127:0] state_masked;
    reg  [7:0]   mask_in;
    wire [127:0] state_out;
    wire [7:0]   mask_out;

    // =========================================================================
    // DUT instantiation
    // =========================================================================
    aes_mixcolumns_masked dut (
        .state_masked (state_masked),
        .mask_in      (mask_in),
        .state_out    (state_out),
        .mask_out     (mask_out)
    );

    // =========================================================================
    // Reference MixColumns (pure Verilog, self-contained)
    // =========================================================================
    function [7:0] xtime_ref;
        input [7:0] b;
        xtime_ref = b[7] ? ((b << 1) ^ 8'h1b) : (b << 1);
    endfunction

    function [31:0] mix_col_ref;
        input [31:0] col;
        reg [7:0] b0, b1, b2, b3, x0, x1, x2, x3;
        begin
            b0 = col[31:24]; b1 = col[23:16]; b2 = col[15:8]; b3 = col[7:0];
            x0 = xtime_ref(b0); x1 = xtime_ref(b1);
            x2 = xtime_ref(b2); x3 = xtime_ref(b3);
            mix_col_ref[31:24] = x0 ^ (x1^b1) ^ b2       ^ b3;
            mix_col_ref[23:16] = b0  ^ x1      ^ (x2^b2)  ^ b3;
            mix_col_ref[15: 8] = b0  ^ b1      ^ x2        ^ (x3^b3);
            mix_col_ref[ 7: 0] = (x0^b0) ^ b1  ^ b2        ^ x3;
        end
    endfunction

    function [127:0] mixcols_ref;
        input [127:0] s;
        begin
            mixcols_ref[127:96] = mix_col_ref(s[127:96]);
            mixcols_ref[ 95:64] = mix_col_ref(s[ 95:64]);
            mixcols_ref[ 63:32] = mix_col_ref(s[ 63:32]);
            mixcols_ref[ 31: 0] = mix_col_ref(s[ 31: 0]);
        end
    endfunction

    // =========================================================================
    // Test infrastructure
    // =========================================================================
    integer fail_count;
    reg [127:0] real_state;
    reg [127:0] expected_state_out;
    reg [127:0] recovered_mc;

    task apply_and_check;
        input [127:0] real_s;
        input [7:0]   m_in;
        input integer  t_num;
        begin
            real_state    = real_s;
            mask_in       = m_in;
            // Present the masked state: every byte XOR'd with m_in
            state_masked  = real_s ^ {{16{m_in}}};
            #10; // combinational settle

            // --- Check 1: linearity invariant ---
            // state_out = MC(state_masked) = MC(real_state) XOR mask_in per byte
            expected_state_out = mixcols_ref(real_s) ^ {{16{m_in}}};
            if (state_out !== expected_state_out) begin
                $display("FAIL  Test %0d [linearity]: m_in=%h", t_num, m_in);
                $display("       got    state_out=%h", state_out);
                $display("       expect           =%h", expected_state_out);
                fail_count = fail_count + 1;
            end else begin
                $display("PASS  Test %0d [linearity]: m_in=%h  out=%h",
                         t_num, m_in, state_out);
            end

            // --- Check 2: mask passthrough ---
            if (mask_out !== m_in) begin
                $display("FAIL  Test %0d [mask_out]: got %h expected %h",
                         t_num, mask_out, m_in);
                fail_count = fail_count + 1;
            end else begin
                $display("PASS  Test %0d [mask_out=mask_in=%h]", t_num, m_in);
            end

            // --- Check 3: recovered plaintext after removing mask ---
            recovered_mc = state_out ^ {{16{m_in}}};
            if (recovered_mc !== mixcols_ref(real_s)) begin
                $display("FAIL  Test %0d [recovery]: recovered=%h  expected=%h",
                         t_num, recovered_mc, mixcols_ref(real_s));
                fail_count = fail_count + 1;
            end
        end
    endtask

    // =========================================================================
    // Stimulus
    // =========================================================================
    initial begin
        fail_count = 0;

        // -----------------------------------------------------------------
        // Group 1 — NIST vector, zero mask
        //
        // NIST FIPS 197, Appendix B, Round 1 trace (project NIST vector):
        //   Plaintext:  00112233445566778899aabbccddeeff
        //   Key:        000102030405060708090a0b0c0d0e0f
        //
        //   After AddRoundKey(rk0): 00102030405060708090a0b0c0d0e0f0
        //   After SubBytes:         63cab7040953d051cd60e0e7ba70e18c
        //   After ShiftRows:        6353e08c0960e104cd70b751bacad0e7
        //   After MixColumns:       5f72641557f5bc92f7be3b291db9f91a  ← tested here
        //
        // MixColumns operates on the post-ShiftRows state, not SubBytes output.
        // -----------------------------------------------------------------
        $display("--- Group 1: NIST vector (zero mask) ---");

        // Test 1: NIST round-1 MixColumns input (after SubBytes+ShiftRows), mask=0
        apply_and_check(
            128'h6353e08c0960e104cd70b751bacad0e7,
            8'h00, 1);

        // Spot-check column 0 explicitly
        #1;
        if (state_out[127:96] !== 32'h5f726415) begin
            $display("FAIL  NIST col0: got %h expected 5f726415", state_out[127:96]);
            fail_count = fail_count + 1;
        end else
            $display("PASS  NIST col0 = 5f726415");

        if (state_out !== 128'h5f72641557f5bc92f7be3b291db9f91a) begin
            $display("FAIL  NIST full: got %h", state_out);
            $display("      expected:     5f72641557f5bc92f7be3b291db9f91a");
            fail_count = fail_count + 1;
        end else
            $display("PASS  NIST full MixColumns vector");

        // -----------------------------------------------------------------
        // Group 2 — Linearity with non-zero masks
        // -----------------------------------------------------------------
        $display("--- Group 2: Linearity (various masks) ---");

        // Test 2: NIST post-ShiftRows state, mask=0xAA
        apply_and_check(
            128'h6353e08c0960e104cd70b751bacad0e7,
            8'haa, 2);

        // Test 3: NIST post-ShiftRows state, mask=0xFF
        apply_and_check(
            128'h6353e08c0960e104cd70b751bacad0e7,
            8'hff, 3);

        // Test 4: NIST post-ShiftRows state, mask=0x3C
        apply_and_check(
            128'h6353e08c0960e104cd70b751bacad0e7,
            8'h3c, 4);

        // Test 5: random-ish state, mask=0x55
        apply_and_check(
            128'hdeadbeefcafebabe0123456789abcdef,
            8'h55, 5);

        // Test 6: alternating byte pattern, mask=0x01
        apply_and_check(
            128'haaaaaaaaaaaaaaaa5555555555555555,
            8'h01, 6);

        // -----------------------------------------------------------------
        // Group 3 — Edge cases
        // -----------------------------------------------------------------
        $display("--- Group 3: Edge cases ---");

        // Test 7: all-zero state, mask=0
        //   MC({0,...,0}) = {0,...,0}  → state_out = 0
        apply_and_check(128'h0, 8'h00, 7);

        // Test 8: all-FF state, mask=0
        //   Each column = {FF,FF,FF,FF}
        //   MC row0 = 2·FF ⊕ 3·FF ⊕ FF ⊕ FF = (2⊕3⊕1⊕1)·FF = FF
        //   All output bytes = FF  → state_out = {16{FF}}
        apply_and_check(128'hffffffffffffffffffffffffffffffff, 8'h00, 8);

        // Confirm all-FF explicitly
        if (state_out !== 128'hffffffffffffffffffffffffffffffff) begin
            $display("FAIL  Test 8: MC(FF*16) should be FF*16, got %h", state_out);
            fail_count = fail_count + 1;
        end else
            $display("PASS  Test 8: MC(FF*16) = FF*16 confirmed");

        // Test 9: all-FF state, mask=0xFF
        //   real_state = FF, state_masked = 0x00 per byte
        //   MC(0*16) = 0 per byte
        //   state_out = 0 XOR FF = FF per byte
        //   recovery: state_out XOR mask_in = FF XOR FF = 0x00 per byte
        //   MC(0xFF per byte) = 0xFF per byte  ✓
        apply_and_check(128'hffffffffffffffffffffffffffffffff, 8'hff, 9);

        // Test 10: identity-like — single non-zero column, others zero
        apply_and_check(
            128'h0102030400000000000000000000000,
            8'h00, 10);

        // -----------------------------------------------------------------
        // Group 4 — mask_out passthrough sweep (6 extra mask values)
        // -----------------------------------------------------------------
        $display("--- Group 4: mask_out passthrough sweep ---");
        begin : mask_sweep
            integer i;
            reg [7:0] test_masks [0:5];
            test_masks[0] = 8'h00; test_masks[1] = 8'h01;
            test_masks[2] = 8'h7f; test_masks[3] = 8'h80;
            test_masks[4] = 8'hfe; test_masks[5] = 8'hff;
            for (i = 0; i < 6; i = i + 1) begin
                mask_in      = test_masks[i];
                state_masked = 128'h6353e08c0960e104cd70b751bacad0e7
                               ^ {{16{test_masks[i]}}};
                #10;
                if (mask_out !== test_masks[i]) begin
                    $display("FAIL  mask sweep i=%0d: mask_in=%h mask_out=%h",
                             i, test_masks[i], mask_out);
                    fail_count = fail_count + 1;
                end else
                    $display("PASS  mask sweep: mask_in=%h → mask_out=%h",
                             test_masks[i], mask_out);
            end
        end

        // -----------------------------------------------------------------
        // Summary
        // -----------------------------------------------------------------
        $display("----------------------------------------");
        if (fail_count == 0)
            $display("ALL TESTS PASSED — aes_mixcolumns_masked OK");
        else
            $display("FAILED: %0d test(s) did not pass", fail_count);
        $display("----------------------------------------");

        $finish;
    end

endmodule
