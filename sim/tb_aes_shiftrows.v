//==============================================================================
// Testbench for AES ShiftRows
// AEGIS Project - ChipVerse '26
//==============================================================================
// Self-checking testbench. Reports PASS/FAIL for each test.
// Uses NIST FIPS 197 Round 1 intermediate values.
//
// NIST chain used here:
//   Plaintext XOR RoundKey[0] = 00102030405060708090a0b0c0d0e0f0
//   After SubBytes             = 63cab7040953d051cd60e0e7ba70e18c  <- input
//   After ShiftRows            = 6353e08c0960e104cd70b751bacad0e7  <- expected output
//==============================================================================

`timescale 1ns / 1ps

module tb_aes_shiftrows;

    //==========================================================================
    // Test Signals
    //==========================================================================
    reg  [127:0] state_in;
    wire [127:0] state_out;

    integer errors;

    //==========================================================================
    // Instantiate DUT
    //==========================================================================
    aes_shiftrows dut (
        .state_in(state_in),
        .state_out(state_out)
    );

    //==========================================================================
    // Helper Task — check one result and report
    //==========================================================================
    task check;
        input [127:0] expected;
        input [8*40-1:0] test_name;  // 40-char string
        begin
            #10; // Let combinational output settle
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

    //==========================================================================
    // Test Procedure
    //==========================================================================
    initial begin
        errors = 0;
        $display("========================================");
        $display("AES ShiftRows Testbench");
        $display("========================================");

        //----------------------------------------------------------------------
        // Test 1: NIST FIPS 197 Round 1 vector
        //----------------------------------------------------------------------
        // This is the most important test. If this passes, the byte routing
        // is correct for all four rows simultaneously.
        //
        // Input state matrix (column-major):
        //        col0  col1  col2  col3
        //  row0:  63    09    cd    ba
        //  row1:  ca    53    60    70
        //  row2:  b7    d0    e0    e1
        //  row3:  04    51    e7    8c
        //
        // Expected output (after row shifts):
        //        col0  col1  col2  col3
        //  row0:  63    09    cd    ba   (shift 0: unchanged)
        //  row1:  53    60    70    ca   (shift 1: ca wraps to col3)
        //  row2:  e0    e1    b7    d0   (shift 2: pair swap)
        //  row3:  8c    04    51    e7   (shift 3: 8c wraps from col3 to col0)

        $display("\nTest 1: NIST FIPS 197 Round 1 ShiftRows");
        state_in = 128'h63cab7040953d051cd60e0e7ba70e18c;
        check(128'h6353e08c0960e104cd70b751bacad0e7,
              "NIST round-1 ShiftRows");

        //----------------------------------------------------------------------
        // Test 2: All-zero input
        //----------------------------------------------------------------------
        // ShiftRows of all zeros must be all zeros. Shifting zeros produces zeros.
        // This tests that no wire is accidentally tied to a non-zero source.

        $display("\nTest 2: All-Zero Input");
        state_in = 128'h0;
        check(128'h0, "all-zero input -> all-zero output");

        //----------------------------------------------------------------------
        // Test 3: All-ones input
        //----------------------------------------------------------------------
        // ShiftRows of all 0xFF bytes must be all 0xFF bytes.
        // Confirming no bit is accidentally grounded.

        $display("\nTest 3: All-Ones Input");
        state_in = 128'hffffffffffffffffffffffffffffffff;
        check(128'hffffffffffffffffffffffffffffffff,
              "all-ones input -> all-ones output");

        //----------------------------------------------------------------------
        // Test 4: Row isolation — only Row 0 set, others zero
        //----------------------------------------------------------------------
        // Row 0 bytes are at cols [0,1,2,3]: bits [127:120],[95:88],[63:56],[31:24]
        // These must pass through unchanged; all other output bits must be zero.
        // Encoding row0 = {0xDE, 0xAD, 0xBE, 0xEF} in col-major positions:
        //   bit[127:120]=DE, bit[95:88]=AD, bit[63:56]=BE, bit[31:24]=EF
        //   = DE_00_00_00_AD_00_00_00_BE_00_00_00_EF_00_00_00

        $display("\nTest 4: Row-0 Isolation (shift-0, must be unchanged)");
        state_in = 128'hDE000000AD000000BE000000EF000000;
        check(128'hDE000000AD000000BE000000EF000000,
              "row0 unchanged (shift 0)");

        //----------------------------------------------------------------------
        // Test 5: Row isolation — only Row 1 set, others zero
        //----------------------------------------------------------------------
        // Row 1 bytes are at cols [0,1,2,3]: bits [119:112],[87:80],[55:48],[23:16]
        // Input:  b1=0xAA at col0, b5=0xBB at col1, b9=0xCC at col2, b13=0xDD at col3
        //   bit[119:112]=AA, bit[87:80]=BB, bit[55:48]=CC, bit[23:16]=DD
        //   = 00AA000000BB000000CC000000DD0000
        //
        // After shift-left-1: [BB, CC, DD, AA]
        //   bit[119:112]=BB, bit[87:80]=CC, bit[55:48]=DD, bit[23:16]=AA
        //   = 00BB000000CC000000DD000000AA0000

        $display("\nTest 5: Row-1 Isolation (shift-1)");
        state_in = 128'h00AA000000BB000000CC000000DD0000;
        check(128'h00BB000000CC000000DD000000AA0000,
              "row1 rotates left by 1 byte");

        //----------------------------------------------------------------------
        // Test 6: Row isolation — only Row 2 set, others zero
        //----------------------------------------------------------------------
        // Row 2 bytes: bits [111:104],[79:72],[47:40],[15:8]
        // Input:  b2=0x11 at col0, b6=0x22 at col1, b10=0x33 at col2, b14=0x44 at col3
        //   = 00001100000022000000330000004400
        //
        // After shift-left-2: [0x33, 0x44, 0x11, 0x22]
        //   = 00003300000044000000110000002200

        $display("\nTest 6: Row-2 Isolation (shift-2)");
        state_in = 128'h00001100000022000000330000004400;
        check(128'h00003300000044000000110000002200,
              "row2 rotates left by 2 bytes");

        //----------------------------------------------------------------------
        // Test 7: Row isolation — only Row 3 set, others zero
        //----------------------------------------------------------------------
        // Row 3 bytes: bits [103:96],[71:64],[39:32],[7:0]
        // Input:  b3=0xAB at col0, b7=0xCD at col1, b11=0xEF at col2, b15=0x01 at col3
        //   = 000000AB000000CD000000EF000000 01
        //   = 000000AB000000CD000000EF00000001
        //
        // After shift-left-3 (= right-1): [0x01, 0xAB, 0xCD, 0xEF]
        //   = 00000001000000AB000000CD000000EF

        $display("\nTest 7: Row-3 Isolation (shift-3 = right-rotate-1)");
        state_in = 128'h000000AB000000CD000000EF00000001;
        check(128'h00000001000000AB000000CD000000EF,
              "row3 rotates left by 3 bytes (right-1)");

        //----------------------------------------------------------------------
        // Final Report
        //----------------------------------------------------------------------
        $display("\n========================================");
        if (errors == 0) begin
            $display("ALL TESTS PASSED");
            $display("ShiftRows module is verified and ready");
        end else begin
            $display("TESTS FAILED: %0d errors detected", errors);
            $display("Review wire assignments for incorrect row routing");
        end
        $display("========================================");

        $finish;
    end

endmodule