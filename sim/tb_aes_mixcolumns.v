//==============================================================================
// Testbench for AES MixColumns
// AEGIS Project - ChipVerse '26
//==============================================================================
// Self-checking testbench. Reports PASS/FAIL for each test.
// Uses two independent NIST sources:
//   1. FIPS 197 Round 1: ShiftRows_out -> MixColumns_out
//   2. FIPS 197 Appendix B column: [d4,bf,5d,30] -> [04,66,81,e5]
//
// Also tests the xtime reduction path specifically (byte 0x80 -> 0x1b),
// the GF linearity property MC(a^b)==MC(a)^MC(b), and the MDS matrix
// columns for unit vectors [01,00,00,00] and [00,01,00,00].
//==============================================================================

`timescale 1ns / 1ps

module tb_aes_mixcolumns;

    //==========================================================================
    // Test Signals
    //==========================================================================
    reg  [127:0] state_in;
    wire [127:0] state_out;

    integer errors;

    //==========================================================================
    // Instantiate DUT
    //==========================================================================
    aes_mixcolumns dut (
        .state_in (state_in),
        .state_out(state_out)
    );

    //==========================================================================
    // Helper Task
    //==========================================================================
    task check;
        input [127:0] expected;
        input [8*44-1:0] test_name;
        begin
            #10;
            if (state_out !== expected) begin
                $display("  FAIL: %s", test_name);
                $display("    Expected: %h", expected);
                $display("    Got:      %h", state_out);
                errors = errors + 1;
            end else begin
                $display("  PASS: %s", test_name);
            end
        end
    endtask

    reg [127:0] mc_a, mc_b;

    //==========================================================================
    // Test Procedure
    //==========================================================================
    initial begin
        errors = 0;
        $display("========================================");
        $display("AES MixColumns Testbench");
        $display("========================================");

        //----------------------------------------------------------------------
        // Test 1: NIST FIPS 197 Round 1
        //----------------------------------------------------------------------
        // Transformation chain:
        //   PlainText XOR RoundKey[0] = 00102030405060708090a0b0c0d0e0f0
        //   After SubBytes             = 63cab7040953d051cd60e0e7ba70e18c
        //   After ShiftRows  (input)   = 6353e08c0960e104cd70b751bacad0e7
        //   After MixColumns (output)  = 5f72641557f5bc92f7be3b291db9f91a

        $display("\nTest 1: NIST FIPS 197 Round 1 MixColumns");
        state_in = 128'h6353e08c0960e104cd70b751bacad0e7;
        check(128'h5f72641557f5bc92f7be3b291db9f91a,
              "NIST round-1 MixColumns");

        //----------------------------------------------------------------------
        // Test 2: All-Zero Input
        //----------------------------------------------------------------------
        // 2*0=0, 3*0=0, so all outputs are 0. Tests no stray non-zero wire.

        $display("\nTest 2: All-Zero Input");
        state_in = 128'h0;
        check(128'h0, "all-zero state -> all-zero output");

        //----------------------------------------------------------------------
        // Test 3: xtime Reduction Path - byte 0x80
        //----------------------------------------------------------------------
        // xtime(0x80): bit7=1, so shift = 0x00, ^ 0x1b = 0x1b.
        // This is the critical path - if bit7 detection fails, all bytes
        // with MSB=1 will be wrong (the most common case in AES).
        //
        // For column [0x80, 0, 0, 0]:
        //   t0=0x1b, t1=t2=t3=0x00
        //   out0 = 0x1b^0^0^0^0 = 0x1b
        //   out1 = 0x80^0^0^0^0 = 0x80
        //   out2 = 0x80^0^0^0^0 = 0x80
        //   out3 = 0x1b^0x80^0^0^0 = 0x9b

        $display("\nTest 3: xtime Reduction (0x80 -> 0x1b, MSB detection)");
        state_in = 128'h80000000800000008000000080000000;
        check(128'h1b80809b1b80809b1b80809b1b80809b,
              "xtime(0x80)=0x1b GF reduction fires");

        //----------------------------------------------------------------------
        // Test 4: MDS Matrix Column - unit vector [01,00,00,00]
        //----------------------------------------------------------------------
        // Reading column 0 of the MixColumns matrix: [2,1,1,3]
        // out=[2*1, 1*1, 1*1, 3*1] = [02, 01, 01, 03]
        // This isolates xtime(0x01)=0x02 (simple left-shift, no reduction).

        $display("\nTest 4: MDS matrix col0: [01,00,00,00] -> [02,01,01,03]");
        state_in = 128'h01000000010000000100000001000000;
        check(128'h02010103020101030201010302010103,
              "unit vec [01,00,00,00] -> [02,01,01,03]");

        //----------------------------------------------------------------------
        // Test 5: MDS Matrix Column - unit vector [00,01,00,00]
        //----------------------------------------------------------------------
        // Reading column 1 of the MixColumns matrix: [3,2,1,1]
        // out=[3*1, 2*1, 1*1, 1*1] = [03, 02, 01, 01]

        $display("\nTest 5: MDS matrix col1: [00,01,00,00] -> [03,02,01,01]");
        state_in = 128'h00010000000100000001000000010000;
        check(128'h03020101030201010302010103020101,
              "unit vec [00,01,00,00] -> [03,02,01,01]");

        //----------------------------------------------------------------------
        // Test 6: NIST FIPS 197 Appendix B Column [d4,bf,5d,30]
        //----------------------------------------------------------------------
        // Second independent NIST source. All 4 columns identical.
        // Tests simultaneous non-trivial reduction paths.

        $display("\nTest 6: FIPS-197 Appendix B: [d4,bf,5d,30] -> [04,66,81,e5]");
        state_in = 128'hd4bf5d30d4bf5d30d4bf5d30d4bf5d30;
        check(128'h046681e5046681e5046681e5046681e5,
              "FIPS-197 App-B [d4,bf,5d,30]->[04,66,81,e5]");

        //----------------------------------------------------------------------
        // Test 7: GF Linearity MC(a^b) == MC(a) ^ MC(b)
        //----------------------------------------------------------------------
        // Critical property: used in Act 2 masked MixColumns.
        // MC(s^m) = MC(s) ^ MC(m) only if MC is linear over GF(2).
        // If this fails, the masking scheme is broken.

        $display("\nTest 7: GF Linearity MC(a^b) == MC(a) ^ MC(b)");
        state_in = 128'h00112233445566778899aabbccddeeff; // a
        #10;
        mc_a = state_out;
        state_in = 128'h000102030405060708090a0b0c0d0e0f; // b
        #10;
        mc_b = state_out;
        state_in = 128'h00102030405060708090a0b0c0d0e0f0; // a^b
        #10;
        if (state_out !== (mc_a ^ mc_b)) begin
            $display("  FAIL: GF linearity broken");
            $display("    MC(a^b)     = %h", state_out);
            $display("    MC(a)^MC(b) = %h", mc_a ^ mc_b);
            errors = errors + 1;
        end else begin
            $display("  PASS: GF linearity: MC(a^b) == MC(a)^MC(b)");
        end

        //----------------------------------------------------------------------
        // Test 8: Explicit GF arithmetic [57,13,57,13] -> [df,9b,df,9b]
        //----------------------------------------------------------------------
        // Both bytes have bit7=0 so no reduction - tests pure shift path.
        // xtime(0x57)=0xae, xtime(0x13)=0x26

        $display("\nTest 8: Explicit GF check [57,13,57,13] -> [df,9b,df,9b]");
        state_in = 128'h57135713571357135713571357135713;
        check(128'hdf9bdf9bdf9bdf9bdf9bdf9bdf9bdf9b,
              "GF check [57,13,57,13] -> [df,9b,df,9b]");

        //----------------------------------------------------------------------
        // Test 9: Reduction path [aa,55,aa,55] -> [4f,b0,4f,b0]
        //----------------------------------------------------------------------
        // 0xAA has bit7=1 (reduction fires), 0x55 has bit7=0 (no reduction).
        // Tests both code paths in the same column.

        $display("\nTest 9: Mixed MSB [aa,55,aa,55] -> [4f,b0,4f,b0]");
        state_in = 128'haa55aa55aa55aa55aa55aa55aa55aa55;
        check(128'h4fb04fb04fb04fb04fb04fb04fb04fb0,
              "mixed MSB [aa,55,aa,55] -> [4f,b0,4f,b0]");

        //----------------------------------------------------------------------
        // Final Report
        //----------------------------------------------------------------------
        $display("\n========================================");
        if (errors == 0) begin
            $display("ALL TESTS PASSED");
            $display("MixColumns module is verified and ready");
        end else begin
            $display("TESTS FAILED: %0d errors detected", errors);
            $display("Check: ternary xtime direction, bit-slice assignments");
        end
        $display("========================================");

        $finish;
    end

endmodule