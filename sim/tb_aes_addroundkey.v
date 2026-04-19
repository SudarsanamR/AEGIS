`timescale 1ns / 1ps
//==============================================================================
// Testbench for AES AddRoundKey
// AEGIS Project - ChipVerse '26
//==============================================================================
// Tests the XOR operation against NIST test vectors and edge cases.
// Verifies: initial whitening, round key addition, XOR properties
//==============================================================================

module tb_aes_addroundkey;

    //==========================================================================
    // Test Signals
    //==========================================================================
    reg  [127:0] state_in;
    reg  [127:0] round_key;
    wire [127:0] state_out;
    
    integer errors;

    //==========================================================================
    // Instantiate DUT (Device Under Test)
    //==========================================================================
    aes_addroundkey dut (
        .state_in(state_in),
        .round_key(round_key),
        .state_out(state_out)
    );

    //==========================================================================
    // Test Procedure
    //==========================================================================
    initial begin
        errors = 0;
        $display("========================================");
        $display("AES AddRoundKey Testbench");
        $display("========================================");
        
        //----------------------------------------------------------------------
        // Test 1: NIST Initial AddRoundKey (Plaintext XOR Key[0])
        //----------------------------------------------------------------------
        $display("\nTest 1: NIST Initial AddRoundKey");
        
        // Plaintext: 00112233445566778899aabbccddeeff
        // Key[0]:    000102030405060708090a0b0c0d0e0f
        // Expected:  00102030405060708090a0b0c0d0e0f0
        state_in  = 128'h00112233445566778899aabbccddeeff;
        round_key = 128'h000102030405060708090a0b0c0d0e0f;
        #10;
        
        if (state_out != 128'h00102030405060708090a0b0c0d0e0f0) begin
            $display("  FAIL: Initial AddRoundKey mismatch");
            $display("    Expected: 00102030405060708090a0b0c0d0e0f0");
            $display("    Got:      %h", state_out);
            errors = errors + 1;
        end else begin
            $display("  PASS: Initial AddRoundKey correct");
        end
        
        //----------------------------------------------------------------------
        // Test 2: NIST Round 1 AddRoundKey
        //----------------------------------------------------------------------
        $display("\nTest 2: NIST Round 1 AddRoundKey");
        
        // After MixColumns: 5f72641557f5bc92f7be3b291db9f91a
        // RoundKey[1]:      d6aa74fdd2af72fadaa678f1d6ab76fe
        // Expected:         89d810e8855ace682d1843d8cb128fe4  // FIXED
        state_in  = 128'h5f72641557f5bc92f7be3b291db9f91a;
        round_key = 128'hd6aa74fdd2af72fadaa678f1d6ab76fe;
        #10;
        
        if (state_out != 128'h89d810e8855ace682d1843d8cb128fe4) begin  // FIXED
            $display("  FAIL: Round 1 AddRoundKey mismatch");
            $display("    Expected: 89d810e8855ace682d1843d8cb128fe4");
            $display("    Got:      %h", state_out);
            errors = errors + 1;
        end else begin
            $display("  PASS: Round 1 AddRoundKey correct");
        end
        
        //----------------------------------------------------------------------
        // Test 3: XOR Identity - State XOR Zero = State
        //----------------------------------------------------------------------
        $display("\nTest 3: XOR Identity (State XOR 0 = State)");
        
        state_in  = 128'hfedcba9876543210fedcba9876543210;
        round_key = 128'h00000000000000000000000000000000;
        #10;
        
        if (state_out != 128'hfedcba9876543210fedcba9876543210) begin
            $display("  FAIL: XOR identity failed");
            $display("    Expected: fedcba9876543210fedcba9876543210");
            $display("    Got:      %h", state_out);
            errors = errors + 1;
        end else begin
            $display("  PASS: XOR identity holds (State XOR 0 = State)");
        end
        
        //----------------------------------------------------------------------
        // Test 4: XOR Self-Inverse - State XOR State = 0
        //----------------------------------------------------------------------
        $display("\nTest 4: XOR Self-Inverse (State XOR State = 0)");
        
        state_in  = 128'habcdef1234567890abcdef1234567890;
        round_key = 128'habcdef1234567890abcdef1234567890;
        #10;
        
        if (state_out != 128'h00000000000000000000000000000000) begin
            $display("  FAIL: XOR self-inverse failed");
            $display("    Expected: 00000000000000000000000000000000");
            $display("    Got:      %h", state_out);
            errors = errors + 1;
        end else begin
            $display("  PASS: XOR self-inverse holds (State XOR State = 0)");
        end
        
        //----------------------------------------------------------------------
        // Test 5: All Ones XOR All Ones = All Zeros
        //----------------------------------------------------------------------
        $display("\nTest 5: All Ones XOR All Ones");
        
        state_in  = 128'hffffffffffffffffffffffffffffffff;
        round_key = 128'hffffffffffffffffffffffffffffffff;
        #10;
        
        if (state_out != 128'h00000000000000000000000000000000) begin
            $display("  FAIL: All ones XOR all ones should be zero");
            $display("    Expected: 00000000000000000000000000000000");
            $display("    Got:      %h", state_out);
            errors = errors + 1;
        end else begin
            $display("  PASS: All ones XOR all ones = zero");
        end
        
        //----------------------------------------------------------------------
        // Test 6: Bit Inversion - State XOR All_Ones = NOT State
        //----------------------------------------------------------------------
        $display("\nTest 6: Bit Inversion (State XOR 0xFF...FF = NOT State)");
        
        state_in  = 128'h0f0f0f0f0f0f0f0f0f0f0f0f0f0f0f0f;
        round_key = 128'hffffffffffffffffffffffffffffffff;
        #10;
        
        if (state_out != 128'hf0f0f0f0f0f0f0f0f0f0f0f0f0f0f0f0) begin
            $display("  FAIL: Bit inversion failed");
            $display("    Expected: f0f0f0f0f0f0f0f0f0f0f0f0f0f0f0f0");
            $display("    Got:      %h", state_out);
            errors = errors + 1;
        end else begin
            $display("  PASS: Bit inversion correct (XOR with all 1's = NOT)");
        end
        
        //----------------------------------------------------------------------
        // Test 7: Alternating Bits Pattern
        //----------------------------------------------------------------------
        $display("\nTest 7: Alternating Bits (0xAA XOR 0x55)");
        
        state_in  = 128'haaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa;
        round_key = 128'h55555555555555555555555555555555;
        #10;
        
        if (state_out != 128'hffffffffffffffffffffffffffffffff) begin
            $display("  FAIL: Alternating bits XOR failed");
            $display("    Expected: ffffffffffffffffffffffffffffffff");
            $display("    Got:      %h", state_out);
            errors = errors + 1;
        end else begin
            $display("  PASS: Alternating bits XOR correct (0xAA XOR 0x55 = 0xFF)");
        end
        
        //----------------------------------------------------------------------
        // Final Report
        //----------------------------------------------------------------------
        $display("\n========================================");
        if (errors == 0) begin
            $display("ALL TESTS PASSED");
            $display("AddRoundKey module is verified and ready");
        end else begin
            $display("TESTS FAILED: %0d errors detected", errors);
            $display("Review XOR implementation");
        end
        $display("========================================");
        
        $finish;
    end

endmodule
