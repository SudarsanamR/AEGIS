`timescale 1ns / 1ps
//==============================================================================
// Testbench for AES Key Expansion
// AEGIS Project - ChipVerse '26
//==============================================================================
// Verifies all 11 round keys against NIST FIPS 197 test vectors.
// THIS IS THE MOST CRITICAL TEST - if any round key is wrong, AES fails.
//==============================================================================

module tb_aes_key_expansion;

    //==========================================================================
    // Test Signals
    //==========================================================================
    reg  [127:0] cipher_key;
    wire [127:0] round_key_0;
    wire [127:0] round_key_1;
    wire [127:0] round_key_2;
    wire [127:0] round_key_3;
    wire [127:0] round_key_4;
    wire [127:0] round_key_5;
    wire [127:0] round_key_6;
    wire [127:0] round_key_7;
    wire [127:0] round_key_8;
    wire [127:0] round_key_9;
    wire [127:0] round_key_10;
    
    integer errors;

    //==========================================================================
    // Instantiate DUT (Device Under Test)
    //==========================================================================
    aes_key_expansion dut (
        .cipher_key(cipher_key),
        .round_key_0(round_key_0),
        .round_key_1(round_key_1),
        .round_key_2(round_key_2),
        .round_key_3(round_key_3),
        .round_key_4(round_key_4),
        .round_key_5(round_key_5),
        .round_key_6(round_key_6),
        .round_key_7(round_key_7),
        .round_key_8(round_key_8),
        .round_key_9(round_key_9),
        .round_key_10(round_key_10)
    );

    //==========================================================================
    // Test Procedure
    //==========================================================================
    initial begin
        errors = 0;
        $display("========================================");
        $display("AES Key Expansion Testbench");
        $display("========================================");
        $display("Verifying all 11 round keys against NIST FIPS 197 Appendix A.1");
        $display("");
        
        //----------------------------------------------------------------------
        // NIST Test Vector: Cipher Key 000102030405060708090a0b0c0d0e0f
        //----------------------------------------------------------------------
        cipher_key = 128'h000102030405060708090a0b0c0d0e0f;
        #10;  // Wait for combinational logic to settle
        
        // Verify Round Key 0 (should equal cipher key)
        $display("Round Key  0:");
        $display("  Expected: 000102030405060708090a0b0c0d0e0f");
        $display("  Got:      %h", round_key_0);
        if (round_key_0 != 128'h000102030405060708090a0b0c0d0e0f) begin
            $display("  FAIL: Round key 0 mismatch");
            errors = errors + 1;
        end else begin
            $display("  PASS");
        end
        $display("");
        
        // Verify Round Key 1
        $display("Round Key  1:");
        $display("  Expected: d6aa74fdd2af72fadaa678f1d6ab76fe");
        $display("  Got:      %h", round_key_1);
        if (round_key_1 != 128'hd6aa74fdd2af72fadaa678f1d6ab76fe) begin
            $display("  FAIL: Round key 1 mismatch");
            errors = errors + 1;
        end else begin
            $display("  PASS");
        end
        $display("");
        
        // Verify Round Key 2
        $display("Round Key  2:");
        $display("  Expected: b692cf0b643dbdf1be9bc5006830b3fe");
        $display("  Got:      %h", round_key_2);
        if (round_key_2 != 128'hb692cf0b643dbdf1be9bc5006830b3fe) begin
            $display("  FAIL: Round key 2 mismatch");
            errors = errors + 1;
        end else begin
            $display("  PASS");
        end
        $display("");
        
        // Verify Round Key 3
        $display("Round Key  3:");
        $display("  Expected: b6ff744ed2c2c9bf6c590cbf0469bf41");
        $display("  Got:      %h", round_key_3);
        if (round_key_3 != 128'hb6ff744ed2c2c9bf6c590cbf0469bf41) begin
            $display("  FAIL: Round key 3 mismatch");
            errors = errors + 1;
        end else begin
            $display("  PASS");
        end
        $display("");
        
        // Verify Round Key 4
        $display("Round Key  4:");
        $display("  Expected: 47f7f7bc95353e03f96c32bcfd058dfd");
        $display("  Got:      %h", round_key_4);
        if (round_key_4 != 128'h47f7f7bc95353e03f96c32bcfd058dfd) begin
            $display("  FAIL: Round key 4 mismatch");
            errors = errors + 1;
        end else begin
            $display("  PASS");
        end
        $display("");
        
        // Verify Round Key 5
        $display("Round Key  5:");
        $display("  Expected: 3caaa3e8a99f9deb50f3af57adf622aa");
        $display("  Got:      %h", round_key_5);
        if (round_key_5 != 128'h3caaa3e8a99f9deb50f3af57adf622aa) begin
            $display("  FAIL: Round key 5 mismatch");
            errors = errors + 1;
        end else begin
            $display("  PASS");
        end
        $display("");
        
        // Verify Round Key 6
        $display("Round Key  6:");
        $display("  Expected: 5e390f7df7a69296a7553dc10aa31f6b");
        $display("  Got:      %h", round_key_6);
        if (round_key_6 != 128'h5e390f7df7a69296a7553dc10aa31f6b) begin
            $display("  FAIL: Round key 6 mismatch");
            errors = errors + 1;
        end else begin
            $display("  PASS");
        end
        $display("");
        
        // Verify Round Key 7
        $display("Round Key  7:");
        $display("  Expected: 14f9701ae35fe28c440adf4d4ea9c026");
        $display("  Got:      %h", round_key_7);
        if (round_key_7 != 128'h14f9701ae35fe28c440adf4d4ea9c026) begin
            $display("  FAIL: Round key 7 mismatch");
            errors = errors + 1;
        end else begin
            $display("  PASS");
        end
        $display("");
        
        // Verify Round Key 8
        $display("Round Key  8:");
        $display("  Expected: 47438735a41c65b9e016baf4aebf7ad2");
        $display("  Got:      %h", round_key_8);
        if (round_key_8 != 128'h47438735a41c65b9e016baf4aebf7ad2) begin
            $display("  FAIL: Round key 8 mismatch");
            errors = errors + 1;
        end else begin
            $display("  PASS");
        end
        $display("");
        
        // Verify Round Key 9
        $display("Round Key  9:");
        $display("  Expected: 549932d1f08557681093ed9cbe2c974e");
        $display("  Got:      %h", round_key_9);
        if (round_key_9 != 128'h549932d1f08557681093ed9cbe2c974e) begin
            $display("  FAIL: Round key 9 mismatch");
            errors = errors + 1;
        end else begin
            $display("  PASS");
        end
        $display("");
        
        // Verify Round Key 10
        $display("Round Key 10:");
        $display("  Expected: 13111d7fe3944a17f307a78b4d2b30c5");
        $display("  Got:      %h", round_key_10);
        if (round_key_10 != 128'h13111d7fe3944a17f307a78b4d2b30c5) begin
            $display("  FAIL: Round key 10 mismatch");
            errors = errors + 1;
        end else begin
            $display("  PASS");
        end
        $display("");
        
        //----------------------------------------------------------------------
        // Test 2: All Zeros Key
        //----------------------------------------------------------------------
        $display("========================================");
        $display("Test 2: All Zeros Cipher Key");
        $display("========================================");
        
        cipher_key = 128'h00000000000000000000000000000000;
        #10;
        
        // Round key 0 should equal the cipher key
        $display("Round Key  0:");
        $display("  Expected: 00000000000000000000000000000000");
        $display("  Got:      %h", round_key_0);
        if (round_key_0 != 128'h00000000000000000000000000000000) begin
            $display("  FAIL");
            errors = errors + 1;
        end else begin
            $display("  PASS");
        end
        $display("");
        
        // Round key 1 should be derived correctly
        // Expected: 62636363626363636263636362636363
        $display("Round Key  1:");
        $display("  Expected: 62636363626363636263636362636363");
        $display("  Got:      %h", round_key_1);
        if (round_key_1 != 128'h62636363626363636263636362636363) begin
            $display("  FAIL");
            errors = errors + 1;
        end else begin
            $display("  PASS");
        end
        $display("");
        
        //----------------------------------------------------------------------
        // Test 3: All Ones Key
        //----------------------------------------------------------------------
        $display("========================================");
        $display("Test 3: All Ones Cipher Key");
        $display("========================================");
        
        cipher_key = 128'hffffffffffffffffffffffffffffffff;
        #10;
        
        // Round key 0 should equal the cipher key
        $display("Round Key  0:");
        $display("  Expected: ffffffffffffffffffffffffffffffff");
        $display("  Got:      %h", round_key_0);
        if (round_key_0 != 128'hffffffffffffffffffffffffffffffff) begin
            $display("  FAIL");
            errors = errors + 1;
        end else begin
            $display("  PASS");
        end
        $display("");
        
        // Round key 1 should be derived correctly
        // Expected: e8e9e9e917161616e8e9e9e91a191916
        $display("Round Key  1:");
        $display("  Expected: he8e9e9e917161616e8e9e9e917161616");
        $display("  Got:      %h", round_key_1);
        if (round_key_1 != 128'he8e9e9e917161616e8e9e9e917161616) begin
            $display("  FAIL");
            errors = errors + 1;
        end else begin
            $display("  PASS");
        end
        $display("");
        
        //----------------------------------------------------------------------
        // Final Report
        //----------------------------------------------------------------------
        $display("========================================");
        if (errors == 0) begin
            $display("ALL TESTS PASSED");
            $display("Key Expansion module is verified and ready");
            $display("All 11 NIST round keys are correct!");
        end else begin
            $display("TESTS FAILED: %0d errors detected", errors);
            $display("CRITICAL: Review key expansion logic");
            $display("If round keys are wrong, AES will fail");
        end
        $display("========================================");
        
        $finish;
    end

endmodule
