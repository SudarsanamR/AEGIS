// =============================================================================
// Testbench: tb_aes_subbytes_masked
// File:      sim/tb_aes_subbytes_masked.v
// Project:   AEGIS — Act 2, Step 4.1
//
// Tests:
//   1. NIST Sanity (zero mask): mask_in=0, mask_out=0 — output must match
//      the unmasked SubBytes result exactly for the first byte (0x19 → 0xd4).
//      Also checks the all-zeros case: sbox[0x00] = 0x63.
//
//   2. Masking Correctness (core invariant):
//      For arbitrary (a, m_in, m_out):
//        sbox(a XOR m_in ^ m_in) == sbox(a)   →  state_out ^ mask_out == sbox(a)
//      Verified over 16 pseudo-random test cases using a known byte sequence.
//
//   3. Edge Cases:
//      - mask_in = 8'hFF, mask_out = 8'hFF
//      - state = 8'hFF (byte 0 only, rest zeros)
//      - mask_in = mask_out (output looks identical to unmasked)
//
//   4. Full-state check: apply the NIST round-0 state after AddRoundKey
//      with zero mask, verify all 16 bytes match expected SubBytes output.
// =============================================================================

`timescale 1ns / 1ps

module tb_aes_subbytes_masked;

    // =========================================================================
    // DUT ports
    // =========================================================================
    reg  [127:0] state_masked;
    reg  [7:0]   mask_in;
    reg  [7:0]   mask_out;
    wire [127:0] state_out;

    // =========================================================================
    // DUT instantiation
    // =========================================================================
    aes_subbytes_masked dut (
        .state_masked (state_masked),
        .mask_in      (mask_in),
        .mask_out     (mask_out),
        .state_out    (state_out)
    );

    // =========================================================================
    // Reference S-Box (duplicated here so the TB is self-contained)
    // =========================================================================
    function [7:0] sbox_ref;
        input [7:0] in;
        case (in)
            8'h00: sbox_ref = 8'h63; 8'h01: sbox_ref = 8'h7c; 8'h02: sbox_ref = 8'h77;
            8'h03: sbox_ref = 8'h7b; 8'h04: sbox_ref = 8'hf2; 8'h05: sbox_ref = 8'h6b;
            8'h06: sbox_ref = 8'h6f; 8'h07: sbox_ref = 8'hc5; 8'h08: sbox_ref = 8'h30;
            8'h09: sbox_ref = 8'h01; 8'h0a: sbox_ref = 8'h67; 8'h0b: sbox_ref = 8'h2b;
            8'h0c: sbox_ref = 8'hfe; 8'h0d: sbox_ref = 8'hd7; 8'h0e: sbox_ref = 8'hab;
            8'h0f: sbox_ref = 8'h76; 8'h10: sbox_ref = 8'hca; 8'h11: sbox_ref = 8'h82;
            8'h12: sbox_ref = 8'hc9; 8'h13: sbox_ref = 8'h7d; 8'h14: sbox_ref = 8'hfa;
            8'h15: sbox_ref = 8'h59; 8'h16: sbox_ref = 8'h47; 8'h17: sbox_ref = 8'hf0;
            8'h18: sbox_ref = 8'had; 8'h19: sbox_ref = 8'hd4; 8'h1a: sbox_ref = 8'ha2;
            8'h1b: sbox_ref = 8'haf; 8'h1c: sbox_ref = 8'h9c; 8'h1d: sbox_ref = 8'ha4;
            8'h1e: sbox_ref = 8'h72; 8'h1f: sbox_ref = 8'hc0; 8'h20: sbox_ref = 8'hb7;
            8'h21: sbox_ref = 8'hfd; 8'h22: sbox_ref = 8'h93; 8'h23: sbox_ref = 8'h26;
            8'h24: sbox_ref = 8'h36; 8'h25: sbox_ref = 8'h3f; 8'h26: sbox_ref = 8'hf7;
            8'h27: sbox_ref = 8'hcc; 8'h28: sbox_ref = 8'h34; 8'h29: sbox_ref = 8'ha5;
            8'h2a: sbox_ref = 8'he5; 8'h2b: sbox_ref = 8'hf1; 8'h2c: sbox_ref = 8'h71;
            8'h2d: sbox_ref = 8'hd8; 8'h2e: sbox_ref = 8'h31; 8'h2f: sbox_ref = 8'h15;
            8'h30: sbox_ref = 8'h04; 8'h31: sbox_ref = 8'hc7; 8'h32: sbox_ref = 8'h23;
            8'h33: sbox_ref = 8'hc3; 8'h34: sbox_ref = 8'h18; 8'h35: sbox_ref = 8'h96;
            8'h36: sbox_ref = 8'h05; 8'h37: sbox_ref = 8'h9a; 8'h38: sbox_ref = 8'h07;
            8'h39: sbox_ref = 8'h12; 8'h3a: sbox_ref = 8'h80; 8'h3b: sbox_ref = 8'he2;
            8'h3c: sbox_ref = 8'heb; 8'h3d: sbox_ref = 8'h27; 8'h3e: sbox_ref = 8'hb2;
            8'h3f: sbox_ref = 8'h75; 8'h40: sbox_ref = 8'h09; 8'h41: sbox_ref = 8'h83;
            8'h42: sbox_ref = 8'h2c; 8'h43: sbox_ref = 8'h1a; 8'h44: sbox_ref = 8'h1b;
            8'h45: sbox_ref = 8'h6e; 8'h46: sbox_ref = 8'h5a; 8'h47: sbox_ref = 8'ha0;
            8'h48: sbox_ref = 8'h52; 8'h49: sbox_ref = 8'h3b; 8'h4a: sbox_ref = 8'hd6;
            8'h4b: sbox_ref = 8'hb3; 8'h4c: sbox_ref = 8'h29; 8'h4d: sbox_ref = 8'he3;
            8'h4e: sbox_ref = 8'h2f; 8'h4f: sbox_ref = 8'h84; 8'h50: sbox_ref = 8'h53;
            8'h51: sbox_ref = 8'hd1; 8'h52: sbox_ref = 8'h00; 8'h53: sbox_ref = 8'hed;
            8'h54: sbox_ref = 8'h20; 8'h55: sbox_ref = 8'hfc; 8'h56: sbox_ref = 8'hb1;
            8'h57: sbox_ref = 8'h5b; 8'h58: sbox_ref = 8'h6a; 8'h59: sbox_ref = 8'hcb;
            8'h5a: sbox_ref = 8'hbe; 8'h5b: sbox_ref = 8'h39; 8'h5c: sbox_ref = 8'h4a;
            8'h5d: sbox_ref = 8'h4c; 8'h5e: sbox_ref = 8'h58; 8'h5f: sbox_ref = 8'hcf;
            8'h60: sbox_ref = 8'hd0; 8'h61: sbox_ref = 8'hef; 8'h62: sbox_ref = 8'haa;
            8'h63: sbox_ref = 8'hfb; 8'h64: sbox_ref = 8'h43; 8'h65: sbox_ref = 8'h4d;
            8'h66: sbox_ref = 8'h33; 8'h67: sbox_ref = 8'h85; 8'h68: sbox_ref = 8'h45;
            8'h69: sbox_ref = 8'hf9; 8'h6a: sbox_ref = 8'h02; 8'h6b: sbox_ref = 8'h7f;
            8'h6c: sbox_ref = 8'h50; 8'h6d: sbox_ref = 8'h3c; 8'h6e: sbox_ref = 8'h9f;
            8'h6f: sbox_ref = 8'ha8; 8'h70: sbox_ref = 8'h51; 8'h71: sbox_ref = 8'ha3;
            8'h72: sbox_ref = 8'h40; 8'h73: sbox_ref = 8'h8f; 8'h74: sbox_ref = 8'h92;
            8'h75: sbox_ref = 8'h9d; 8'h76: sbox_ref = 8'h38; 8'h77: sbox_ref = 8'hf5;
            8'h78: sbox_ref = 8'hbc; 8'h79: sbox_ref = 8'hb6; 8'h7a: sbox_ref = 8'hda;
            8'h7b: sbox_ref = 8'h21; 8'h7c: sbox_ref = 8'h10; 8'h7d: sbox_ref = 8'hff;
            8'h7e: sbox_ref = 8'hf3; 8'h7f: sbox_ref = 8'hd2; 8'h80: sbox_ref = 8'hcd;
            8'h81: sbox_ref = 8'h0c; 8'h82: sbox_ref = 8'h13; 8'h83: sbox_ref = 8'hec;
            8'h84: sbox_ref = 8'h5f; 8'h85: sbox_ref = 8'h97; 8'h86: sbox_ref = 8'h44;
            8'h87: sbox_ref = 8'h17; 8'h88: sbox_ref = 8'hc4; 8'h89: sbox_ref = 8'ha7;
            8'h8a: sbox_ref = 8'h7e; 8'h8b: sbox_ref = 8'h3d; 8'h8c: sbox_ref = 8'h64;
            8'h8d: sbox_ref = 8'h5d; 8'h8e: sbox_ref = 8'h19; 8'h8f: sbox_ref = 8'h73;
            8'h90: sbox_ref = 8'h60; 8'h91: sbox_ref = 8'h81; 8'h92: sbox_ref = 8'h4f;
            8'h93: sbox_ref = 8'hdc; 8'h94: sbox_ref = 8'h22; 8'h95: sbox_ref = 8'h2a;
            8'h96: sbox_ref = 8'h90; 8'h97: sbox_ref = 8'h88; 8'h98: sbox_ref = 8'h46;
            8'h99: sbox_ref = 8'hee; 8'h9a: sbox_ref = 8'hb8; 8'h9b: sbox_ref = 8'h14;
            8'h9c: sbox_ref = 8'hde; 8'h9d: sbox_ref = 8'h5e; 8'h9e: sbox_ref = 8'h0b;
            8'h9f: sbox_ref = 8'hdb; 8'ha0: sbox_ref = 8'he0; 8'ha1: sbox_ref = 8'h32;
            8'ha2: sbox_ref = 8'h3a; 8'ha3: sbox_ref = 8'h0a; 8'ha4: sbox_ref = 8'h49;
            8'ha5: sbox_ref = 8'h06; 8'ha6: sbox_ref = 8'h24; 8'ha7: sbox_ref = 8'h5c;
            8'ha8: sbox_ref = 8'hc2; 8'ha9: sbox_ref = 8'hd3; 8'haa: sbox_ref = 8'hac;
            8'hab: sbox_ref = 8'h62; 8'hac: sbox_ref = 8'h91; 8'had: sbox_ref = 8'h95;
            8'hae: sbox_ref = 8'he4; 8'haf: sbox_ref = 8'h79; 8'hb0: sbox_ref = 8'he7;
            8'hb1: sbox_ref = 8'hc8; 8'hb2: sbox_ref = 8'h37; 8'hb3: sbox_ref = 8'h6d;
            8'hb4: sbox_ref = 8'h8d; 8'hb5: sbox_ref = 8'hd5; 8'hb6: sbox_ref = 8'h4e;
            8'hb7: sbox_ref = 8'ha9; 8'hb8: sbox_ref = 8'h6c; 8'hb9: sbox_ref = 8'h56;
            8'hba: sbox_ref = 8'hf4; 8'hbb: sbox_ref = 8'hea; 8'hbc: sbox_ref = 8'h65;
            8'hbd: sbox_ref = 8'h7a; 8'hbe: sbox_ref = 8'hae; 8'hbf: sbox_ref = 8'h08;
            8'hc0: sbox_ref = 8'hba; 8'hc1: sbox_ref = 8'h78; 8'hc2: sbox_ref = 8'h25;
            8'hc3: sbox_ref = 8'h2e; 8'hc4: sbox_ref = 8'h1c; 8'hc5: sbox_ref = 8'ha6;
            8'hc6: sbox_ref = 8'hb4; 8'hc7: sbox_ref = 8'hc6; 8'hc8: sbox_ref = 8'he8;
            8'hc9: sbox_ref = 8'hdd; 8'hca: sbox_ref = 8'h74; 8'hcb: sbox_ref = 8'h1f;
            8'hcc: sbox_ref = 8'h4b; 8'hcd: sbox_ref = 8'hbd; 8'hce: sbox_ref = 8'h8b;
            8'hcf: sbox_ref = 8'h8a; 8'hd0: sbox_ref = 8'h70; 8'hd1: sbox_ref = 8'h3e;
            8'hd2: sbox_ref = 8'hb5; 8'hd3: sbox_ref = 8'h66; 8'hd4: sbox_ref = 8'h48;
            8'hd5: sbox_ref = 8'h03; 8'hd6: sbox_ref = 8'hf6; 8'hd7: sbox_ref = 8'h0e;
            8'hd8: sbox_ref = 8'h61; 8'hd9: sbox_ref = 8'h35; 8'hda: sbox_ref = 8'h57;
            8'hdb: sbox_ref = 8'hb9; 8'hdc: sbox_ref = 8'h86; 8'hdd: sbox_ref = 8'hc1;
            8'hde: sbox_ref = 8'h1d; 8'hdf: sbox_ref = 8'h9e; 8'he0: sbox_ref = 8'he1;
            8'he1: sbox_ref = 8'hf8; 8'he2: sbox_ref = 8'h98; 8'he3: sbox_ref = 8'h11;
            8'he4: sbox_ref = 8'h69; 8'he5: sbox_ref = 8'hd9; 8'he6: sbox_ref = 8'h8e;
            8'he7: sbox_ref = 8'h94; 8'he8: sbox_ref = 8'h9b; 8'he9: sbox_ref = 8'h1e;
            8'hea: sbox_ref = 8'h87; 8'heb: sbox_ref = 8'he9; 8'hec: sbox_ref = 8'hce;
            8'hed: sbox_ref = 8'h55; 8'hee: sbox_ref = 8'h28; 8'hef: sbox_ref = 8'hdf;
            8'hf0: sbox_ref = 8'h8c; 8'hf1: sbox_ref = 8'ha1; 8'hf2: sbox_ref = 8'h89;
            8'hf3: sbox_ref = 8'h0d; 8'hf4: sbox_ref = 8'hbf; 8'hf5: sbox_ref = 8'he6;
            8'hf6: sbox_ref = 8'h42; 8'hf7: sbox_ref = 8'h68; 8'hf8: sbox_ref = 8'h41;
            8'hf9: sbox_ref = 8'h99; 8'hfa: sbox_ref = 8'h2d; 8'hfb: sbox_ref = 8'h0f;
            8'hfc: sbox_ref = 8'hb0; 8'hfd: sbox_ref = 8'h54; 8'hfe: sbox_ref = 8'hbb;
            8'hff: sbox_ref = 8'h16;
        endcase
    endfunction

    // =========================================================================
    // Helper: apply sbox_ref to all 16 bytes of a 128-bit state
    // =========================================================================
    function [127:0] subbytes_ref;
        input [127:0] s;
        integer i;
        begin
            for (i = 0; i < 16; i = i + 1)
                subbytes_ref[127 - i*8 -: 8] = sbox_ref(s[127 - i*8 -: 8]);
        end
    endfunction

    // =========================================================================
    // Test infrastructure
    // =========================================================================
    integer test_num;
    integer fail_count;
    reg [127:0] state_real;    // the "true" unmasked state
    reg [127:0] expected_out;  // SubBytes(state_real) XOR mask_out
    reg [127:0] recovered;     // state_out XOR mask_out  (should == SubBytes(state_real))

    // =========================================================================
    // Combinational propagation delay — wait 10 ns after each input change
    // =========================================================================
    task apply_and_check;
        input [127:0] state_r;   // true unmasked state
        input [7:0]   m_in;
        input [7:0]   m_out;
        input integer t_num;
        begin
            state_real    = state_r;
            mask_in       = m_in;
            mask_out      = m_out;
            // Present the pre-masked state to the DUT
            state_masked  = state_r ^ {16{m_in}}; // XOR every byte with m_in
            #10; // allow combinational logic to settle

            expected_out = subbytes_ref(state_r) ^ {16{m_out}};
            recovered    = state_out ^ {16{m_out}};

            if (state_out !== expected_out) begin
                $display("FAIL  Test %0d: state=%h m_in=%h m_out=%h",
                         t_num, state_r, m_in, m_out);
                $display("       got state_out=%h  expected=%h", state_out, expected_out);
                fail_count = fail_count + 1;
            end else begin
                $display("PASS  Test %0d: m_in=%h m_out=%h  out=%h",
                         t_num, m_in, m_out, state_out);
            end
        end
    endtask

    // =========================================================================
    // Stimulus
    // =========================================================================
    initial begin
        fail_count = 0;

        // -----------------------------------------------------------------
        // Group 1: NIST Sanity — zero mask (behaves like unmasked SubBytes)
        // -----------------------------------------------------------------

        // Test 1: sbox[0x00] = 0x63  (FIPS 197 Appendix A known value)
        apply_and_check(
            128'h00000000000000000000000000000000,
            8'h00, 8'h00, 1);
        // Expected state_out = {16{8'h63}} = 0x63636363...63

        // Test 2: NIST round-0 state after AddRoundKey(pt, rk0)
        //   pt  = 00112233445566778899aabbccddeeff
        //   rk0 = 000102030405060708090a0b0c0d0e0f
        //   ARK = 00102030405060708090a0b0c0d0e0f0   (XOR, column-major)
        // SubBytes of that:  63cab7040953d051cd60e0e7ba70e18c
        apply_and_check(
            128'h00102030405060708090a0b0c0d0e0f0,
            8'h00, 8'h00, 2);
        // Expected: 63cab7040953d051cd60e0e7ba70e18c

        // -----------------------------------------------------------------
        // Group 2: Masking Correctness — vary mask_in and mask_out
        //   Invariant: state_out XOR mask_out == SubBytes(state_real)
        // -----------------------------------------------------------------

        // Test 3: mask_in = 0xAA, mask_out = 0x55
        apply_and_check(
            128'h00102030405060708090a0b0c0d0e0f0,
            8'haa, 8'h55, 3);

        // Test 4: mask_in = 0xFF, mask_out = 0x00
        apply_and_check(
            128'h00102030405060708090a0b0c0d0e0f0,
            8'hff, 8'h00, 4);

        // Test 5: mask_in = 0x00, mask_out = 0xFF  (output always XOR'd 0xFF)
        apply_and_check(
            128'h00102030405060708090a0b0c0d0e0f0,
            8'h00, 8'hff, 5);

        // Test 6: mask_in = mask_out = 0x3C
        apply_and_check(
            128'hdeadbeefcafebabe0123456789abcdef,
            8'h3c, 8'h3c, 6);

        // Test 7: mask_in = 0x01, mask_out = 0x02 (small masks, bit-level check)
        apply_and_check(
            128'hffffffffffffffffffffffffffffffff,
            8'h01, 8'h02, 7);

        // Test 8: alternating pattern, large masks
        apply_and_check(
            128'haaaaaaaaaaaaaaaa5555555555555555,
            8'hc3, 8'h7e, 8);

        // -----------------------------------------------------------------
        // Group 3: Edge Cases
        // -----------------------------------------------------------------

        // Test 9: all-ones state, mask_in = 0xFF
        //   state byte = 0xFF, state_masked byte = 0xFF^0xFF = 0x00
        //   DUT computes: sbox[0x00 ^ 0xFF] = sbox[0xFF] = 0x16  (unmasking recovers 0xFF)
        //   SubBytes(0xFF) = 0x16  → state_out = 0x16 XOR mask_out = 0x16
        apply_and_check(
            128'hffffffffffffffffffffffffffffffff,
            8'hff, 8'h00, 9);
        // Expected: all bytes = 0x16

        // Test 10: all-ones state, mask_in = 0xFF, mask_out = 0xFF
        //   SubBytes(0xFF) = 0x16  → state_out = 0x16 XOR 0xFF = 0xE9
        apply_and_check(
            128'hffffffffffffffffffffffffffffffff,
            8'hff, 8'hff, 10);
        // Expected: all bytes = 0xE9

        // Test 11: all-zeros state, non-zero mask_in
        //   state = 0x00 per byte, state_masked = mask_in per byte
        //   sbox[0x00] = 0x63 → state_out = 0x63 XOR mask_out
        apply_and_check(
            128'h00000000000000000000000000000000,
            8'h42, 8'h17, 11);

        // Test 12: byte 0 = 0x19, NIST known value sbox[0x19] = 0xd4
        apply_and_check(
            128'h19000000000000000000000000000000,
            8'h00, 8'h00, 12);
        // Expected byte 0 of state_out = 0xd4

        // Test 13: mask_in = mask_out, full NIST state
        //   state_out XOR mask_out = SubBytes(state)
        //   state_out = SubBytes(state) XOR mask_in  (since mask_in==mask_out)
        apply_and_check(
            128'h00102030405060708090a0b0c0d0e0f0,
            8'h77, 8'h77, 13);

        // Test 14: random-ish values for all 16 bytes
        apply_and_check(
            128'h0f0e0d0c0b0a09080706050403020100,
            8'hb5, 8'h4a, 14);

        // -----------------------------------------------------------------
        // Group 4: Explicit byte-level spot-checks on Test 2
        //   NIST SubBytes(00102030405060708090a0b0c0d0e0f0)
        //   = 63 ca b7 04 09 53 d0 51 cd 60 e0 e7 ba 70 e1 8c
        // -----------------------------------------------------------------
        state_masked  = 128'h00102030405060708090a0b0c0d0e0f0; // mask_in=0
        mask_in       = 8'h00;
        mask_out      = 8'h00;
        #10;
        test_num = 15;
        if (state_out[127:120] !== 8'h63) begin
            $display("FAIL  Test %0d byte0: got %h expected 63", test_num, state_out[127:120]);
            fail_count = fail_count + 1;
        end else $display("PASS  Test %0d byte0=63", test_num);

        if (state_out[119:112] !== 8'hca) begin
            $display("FAIL  Test %0d byte1: got %h expected ca", test_num, state_out[119:112]);
            fail_count = fail_count + 1;
        end else $display("PASS  Test %0d byte1=ca", test_num);

        if (state_out[111:104] !== 8'hb7) begin
            $display("FAIL  Test %0d byte2: got %h expected b7", test_num, state_out[111:104]);
            fail_count = fail_count + 1;
        end else $display("PASS  Test %0d byte2=b7", test_num);

        if (state_out[ 95: 88] !== 8'h09) begin
            $display("FAIL  Test %0d byte4 (row0,col1): got %h expected 09",
                     test_num, state_out[95:88]);
            fail_count = fail_count + 1;
        end else $display("PASS  Test %0d byte4=09", test_num);

        // -----------------------------------------------------------------
        // Summary
        // -----------------------------------------------------------------
        $display("----------------------------------------");
        if (fail_count == 0)
            $display("ALL TESTS PASSED — aes_subbytes_masked OK");
        else
            $display("FAILED: %0d test(s) did not pass", fail_count);
        $display("----------------------------------------");

        $finish;
    end

endmodule
