`timescale 1ns / 1ps
//==============================================================================
// Testbench for AES Core
// AEGIS Project - ChipVerse '26
//==============================================================================
// Verifies complete AES-128 encryption against NIST test vectors.
// Tests: NIST vector, multiple encryptions, edge cases.
// THIS IS THE CRITICAL MILESTONE - if this passes, your AES works!
//==============================================================================

module tb_aes_core;

    //==========================================================================
    // Test Signals
    //==========================================================================
    reg         clk;
    reg         rst;
    reg         start;
    reg  [127:0] plaintext;
    reg  [127:0] cipher_key;
    wire [127:0] ciphertext;
    wire        done;
    
    integer errors;
    integer cycle_count;

    //==========================================================================
    // Clock Generation (100MHz = 10ns period)
    //==========================================================================
    initial begin
        clk = 0;
        forever #5 clk = ~clk;  // 10ns period = 100MHz
    end

    //==========================================================================
    // Instantiate DUT (Device Under Test)
    //==========================================================================
    aes_core dut (
        .clk(clk),
        .rst(rst),
        .start(start),
        .plaintext(plaintext),
        .cipher_key(cipher_key),
        .ciphertext(ciphertext),
        .done(done)
    );

    //==========================================================================
    // Test Procedure
    //==========================================================================
    initial begin
        errors = 0;
        cycle_count = 0;
        
        $display("========================================");
        $display("AES Core Testbench");
        $display("========================================");
        $display("Testing complete AES-128 encryption");
        $display("");
        
        // Initialize signals
        rst = 1;
        start = 0;
        plaintext = 128'h0;
        cipher_key = 128'h0;
        
        // Reset for 2 cycles
        repeat(2) @(posedge clk);
        rst = 0;
        @(posedge clk);
        
        //----------------------------------------------------------------------
        // Test 1: NIST FIPS 197 Test Vector
        //----------------------------------------------------------------------
        $display("========================================");
        $display("Test 1: NIST FIPS 197 Appendix C.1");
        $display("========================================");
        
        plaintext  = 128'h00112233445566778899aabbccddeeff;
        cipher_key = 128'h000102030405060708090a0b0c0d0e0f;
        
        $display("Plaintext:  %h", plaintext);
        $display("Cipher Key: %h", cipher_key);
        $display("");
        
        // Start encryption
        @(posedge clk);
        start = 1;
        @(posedge clk);
        start = 0;
        
        // Wait for done signal (with timeout)
        cycle_count = 0;
        while (!done && cycle_count < 50) begin
            @(posedge clk);
            cycle_count = cycle_count + 1;
        end
        
        if (!done) begin
            $display("ERROR: Encryption timeout after %0d cycles", cycle_count);
            errors = errors + 1;
        end else begin
            $display("Encryption completed in %0d cycles", cycle_count);
            $display("");
            $display("Expected Ciphertext: 69c4e0d86a7b0430d8cdb78070b4c55a"); // MODIFIED: corrected value
            $display("Got Ciphertext:      %h", ciphertext);
            
            if (ciphertext == 128'h69c4e0d86a7b0430d8cdb78070b4c55a) begin // MODIFIED: corrected value
                $display("PASS: NIST test vector encryption correct!");
            end else begin
                $display("FAIL: Ciphertext mismatch");
                errors = errors + 1;
            end
        end
        $display("");
        
        // Wait a few cycles before next test
        repeat(5) @(posedge clk);
        
        //----------------------------------------------------------------------
        // Test 2: All Zeros Plaintext
        //----------------------------------------------------------------------
        $display("========================================");
        $display("Test 2: All Zeros Plaintext");
        $display("========================================");
        
        plaintext  = 128'h00000000000000000000000000000000;
        cipher_key = 128'h00000000000000000000000000000000;
        
        $display("Plaintext:  %h", plaintext);
        $display("Cipher Key: %h", cipher_key);
        $display("");
        
        @(posedge clk);
        start = 1;
        @(posedge clk);
        start = 0;
        
        // Wait for done
        cycle_count = 0;
        while (!done && cycle_count < 50) begin
            @(posedge clk);
            cycle_count = cycle_count + 1;
        end
        
        if (!done) begin
            $display("ERROR: Encryption timeout");
            errors = errors + 1;
        end else begin
            $display("Encryption completed in %0d cycles", cycle_count);
            $display("");
            $display("Expected Ciphertext: 66e94bd4ef8a2c3b884cfa59ca342b2e");
            $display("Got Ciphertext:      %h", ciphertext);
            
            if (ciphertext == 128'h66e94bd4ef8a2c3b884cfa59ca342b2e) begin
                $display("PASS: All zeros encryption correct!");
            end else begin
                $display("FAIL: Ciphertext mismatch");
                errors = errors + 1;
            end
        end
        $display("");
        
        // Wait a few cycles before next test
        repeat(5) @(posedge clk);
        
        //----------------------------------------------------------------------
        // Test 3: All Ones Plaintext
        //----------------------------------------------------------------------
        $display("========================================");
        $display("Test 3: All Ones Plaintext");
        $display("========================================");
        
        plaintext  = 128'hffffffffffffffffffffffffffffffff;
        cipher_key = 128'h00000000000000000000000000000000;
        
        $display("Plaintext:  %h", plaintext);
        $display("Cipher Key: %h", cipher_key);
        $display("");
        
        @(posedge clk);
        start = 1;
        @(posedge clk);
        start = 0;
        
        // Wait for done
        cycle_count = 0;
        while (!done && cycle_count < 50) begin
            @(posedge clk);
            cycle_count = cycle_count + 1;
        end
        
        if (!done) begin
            $display("ERROR: Encryption timeout");
            errors = errors + 1;
        end else begin
            $display("Encryption completed in %0d cycles", cycle_count);
            $display("");
            $display("Expected Ciphertext: 3f5b8cc9ea855a0afa7347d23e8d664e"); // MODIFIED: corrected value
            $display("Got Ciphertext:      %h", ciphertext);
            
            if (ciphertext == 128'h3f5b8cc9ea855a0afa7347d23e8d664e) begin // MODIFIED: corrected value
                $display("PASS: All ones encryption correct!");
            end else begin
                $display("FAIL: Ciphertext mismatch");
                errors = errors + 1;
            end
        end
        $display("");
        
        // Wait a few cycles before next test
        repeat(5) @(posedge clk);
        
        //----------------------------------------------------------------------
        // Test 4: Multiple Sequential Encryptions
        //----------------------------------------------------------------------
        $display("========================================");
        $display("Test 4: Multiple Sequential Encryptions");
        $display("========================================");
        $display("Testing that core can be reused...");
        $display("");
        
        // First encryption
        plaintext  = 128'h00112233445566778899aabbccddeeff;
        cipher_key = 128'h000102030405060708090a0b0c0d0e0f;
        
        @(posedge clk);
        start = 1;
        @(posedge clk);
        start = 0;
        
        // Wait for done
        cycle_count = 0;
        while (!done && cycle_count < 50) begin
            @(posedge clk);
            cycle_count = cycle_count + 1;
        end
        
        if (ciphertext != 128'h69c4e0d86a7b0430d8cdb78070b4c55a) begin // MODIFIED: corrected value
            $display("FAIL: First encryption incorrect");
            errors = errors + 1;
        end else begin
            $display("First encryption: PASS");
        end
        
        // Small delay
        repeat(3) @(posedge clk);
        
        // Second encryption (different plaintext, same key)
        plaintext = 128'hffeeddccbbaa99887766554433221100;
        
        @(posedge clk);
        start = 1;
        @(posedge clk);
        start = 0;
        
        // Wait for done
        cycle_count = 0;
        while (!done && cycle_count < 50) begin
            @(posedge clk);
            cycle_count = cycle_count + 1;
        end
        
        // We don't have a reference for this, just check it completed
        if (!done) begin
            $display("FAIL: Second encryption timeout");
            errors = errors + 1;
        end else begin
            $display("Second encryption: PASS (completed in %0d cycles)", cycle_count);
            $display("  Ciphertext: %h", ciphertext);
        end
        $display("");
        
        //----------------------------------------------------------------------
        // Final Report
        //----------------------------------------------------------------------
        $display("========================================");
        if (errors == 0) begin
            $display("ALL TESTS PASSED");
            $display("AES Core is functionally correct!");
            $display("========================================");
            $display("");
            $display("MILESTONE ACHIEVED:");
            $display("You now have a working AES-128 cipher!");
            $display("Next: Add UART interface and system integration");
        end else begin
            $display("TESTS FAILED: %0d errors detected", errors);
            $display("========================================");
            $display("");
            $display("Debug checklist:");
            $display("1. Verify all transformation modules are instantiated");
            $display("2. Check FSM state transitions");
            $display("3. Verify round counter increments correctly");
            $display("4. Check MixColumns is bypassed in round 10");
        end
        $display("========================================");
        
        $finish;
    end
    
    //==========================================================================
    // Timeout Watchdog
    //==========================================================================
    initial begin
        #100000;  // 100us timeout
        $display("");
        $display("========================================");
        $display("SIMULATION TIMEOUT");
        $display("Testbench exceeded 100us");
        $display("========================================");
        $finish;
    end

endmodule
