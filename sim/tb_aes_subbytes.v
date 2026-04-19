//==============================================================================
// Testbench for AES SubBytes
// AEGIS Project - ChipVerse '26
//==============================================================================
// Tests the S-box substitution against known values.
// Verifies: individual byte lookups, full state transformation, edge cases
//==============================================================================

`timescale 1ns / 1ps

module tb_aes_subbytes;

    //==========================================================================
    // Test Signals
    //==========================================================================
    reg  [127:0] state_in;
    wire [127:0] state_out;
    
    integer errors;
    integer i;

    //==========================================================================
    // Instantiate DUT (Device Under Test)
    //==========================================================================
    aes_subbytes dut (
        .state_in(state_in),
        .state_out(state_out)
    );

    //==========================================================================
    // Test Procedure
    //==========================================================================
    initial begin
        errors = 0;
        $display("========================================");
        $display("AES SubBytes Testbench");
        $display("========================================");
        
        //----------------------------------------------------------------------
        // Test 1: Known S-box Values
        //----------------------------------------------------------------------
        // Verify a few critical S-box entries manually
        // sbox[0x00] = 0x63, sbox[0x53] = 0xed, sbox[0xff] = 0x16
        
        $display("\nTest 1: Individual S-box Lookups");
        
        // Test sbox[0x00] = 0x63
        state_in = 128'h00000000000000000000000000000000;
        #10;
        if (state_out != 128'h63636363636363636363636363636363) begin
            $display("  FAIL: sbox[0x00] should be 0x63");
            $display("    Expected: 63636363636363636363636363636363");
            $display("    Got:      %h", state_out);
            errors = errors + 1;
        end else begin
            $display("  PASS: sbox[0x00] = 0x63");
        end
        
        // Test sbox[0xff] = 0x16
        state_in = 128'hffffffffffffffffffffffffffffffff;
        #10;
        if (state_out != 128'h16161616161616161616161616161616) begin
            $display("  FAIL: sbox[0xff] should be 0x16");
            $display("    Expected: 16161616161616161616161616161616");
            $display("    Got:      %h", state_out);
            errors = errors + 1;
        end else begin
            $display("  PASS: sbox[0xff] = 0x16");
        end
        
        // Test sbox[0x53] = 0xed
        state_in = 128'h53535353535353535353535353535353;
        #10;
        if (state_out != 128'hedededededededededededededededed) begin
            $display("  FAIL: sbox[0x53] should be 0xed");
            $display("    Expected: edededededededededededededededed");
            $display("    Got:      %h", state_out);
            errors = errors + 1;
        end else begin
            $display("  PASS: sbox[0x53] = 0xed");
        end
        
        //----------------------------------------------------------------------
        // Test 2: NIST AES Test Vector - First Round SubBytes
        //----------------------------------------------------------------------
        // After AddRoundKey with key[0], before SubBytes:
        // State = Plaintext XOR Key[0]
        //       = 00112233445566778899aabbccddeeff XOR 000102030405060708090a0b0c0d0e0f
        //       = 00102030405060708090a0b0c0d0e0f0
        //
        // After SubBytes:
        //       = 63cab7040953d051cd60e0e7ba70e18c
        
        $display("\nTest 2: NIST Test Vector SubBytes");
        state_in = 128'h00102030405060708090a0b0c0d0e0f0;
        #10;
        if (state_out != 128'h63cab7040953d051cd60e0e7ba70e18c) begin
            $display("  FAIL: NIST vector SubBytes mismatch");
            $display("    Expected: 63cab7040953d051cd60e0e7ba70e18c");
            $display("    Got:      %h", state_out);
            errors = errors + 1;
        end else begin
            $display("  PASS: NIST vector SubBytes correct");
        end
        
        //----------------------------------------------------------------------
        // Test 3: Alternating Bits Pattern
        //----------------------------------------------------------------------
        $display("\nTest 3: Alternating Bits (0xAA, 0x55)");
        
        state_in = 128'haaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa;
        #10;
        if (state_out != 128'hacacacacacacacacacacacacacacacac) begin
            $display("  FAIL: sbox[0xaa] should be 0xac");
            $display("    Got: %h", state_out);
            errors = errors + 1;
        end else begin
            $display("  PASS: sbox[0xaa] = 0xac");
        end
        
        state_in = 128'h55555555555555555555555555555555;
        #10;
        if (state_out != 128'hfcfcfcfcfcfcfcfcfcfcfcfcfcfcfcfc) begin
            $display("  FAIL: sbox[0x55] should be 0xfc");
            $display("    Got: %h", state_out);
            errors = errors + 1;
        end else begin
            $display("  PASS: sbox[0x55] = 0xfc");
        end
        
        //----------------------------------------------------------------------
        // Test 4: Mixed Byte Pattern
        //----------------------------------------------------------------------
        // Test that each byte position is independently substituted
        $display("\nTest 4: Mixed Byte Independence");
        state_in = 128'h00112233445566778899aabbccddeeff;
        #10;
        // Each byte should be independently substituted:
        // sbox[00]=63, sbox[11]=82, sbox[22]=93, sbox[33]=c3,
        // sbox[44]=1b, sbox[55]=fc, sbox[66]=33, sbox[77]=f5,
        // sbox[88]=c4, sbox[99]=ee, sbox[aa]=ac, sbox[bb]=ea,
        // sbox[cc]=4b, sbox[dd]=c1, sbox[ee]=28, sbox[ff]=16
        if (state_out != 128'h638293c31bfc33f5c4eeacea4bc12816) begin  // FIXED
            $display("  FAIL: Mixed byte substitution incorrect");
            $display("    Expected: 638293c31bfc33f5c4eeacea4bc12816");
            $display("    Got:      %h", state_out);
            errors = errors + 1;
        end else begin
            $display("  PASS: Mixed byte substitution correct");
        end
        
        //----------------------------------------------------------------------
        // Final Report
        //----------------------------------------------------------------------
        $display("\n========================================");
        if (errors == 0) begin
            $display("ALL TESTS PASSED");
            $display("SubBytes module is verified and ready");
        end else begin
            $display("TESTS FAILED: %0d errors detected", errors);
            $display("Review S-box implementation");
        end
        $display("========================================");
        
        $finish;
    end

endmodule