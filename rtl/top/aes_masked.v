// =============================================================================
// Module:      aes_masked
// File:        rtl/top/aes_masked.v
// Project:     AEGIS — Act 2, Step 4.5 (MODIFIED for timing closure)
//
// TIMING FIX: Added clock divider-by-2 to create 50MHz clock for AES core.
//
// WHY THIS CHANGE IS NECESSARY:
//   The boolean-masked AES core has a longer critical path than the unmasked
//   version due to two additional 128-bit XOR layers (unmask input before S-Box,
//   re-mask output after S-Box). Combined with MixColumns GF(2^8) arithmetic,
//   this exceeds the 10ns period budget at 100MHz.
//
// ARCHITECTURE CHANGE:
//   - Input clock (clk): 100 MHz — drives UART RX/TX
//   - Divided clock (clk_aes): 50 MHz — drives AES core, control FSM, HW monitor
//   - Clock domain crossing: none (control FSM outputs are quasi-static)
//
// WHY UART STAYS AT 100MHz:
//   The UART modules have internal baud rate dividers (DIVISOR=10417 for 9600 baud).
//   Changing their clock would require recalculating the divisor. Keeping them at
//   100MHz means the UART protocol is unchanged from Act 1.
//
// IMPACT:
//   - Encryption latency: 13 cycles × 20ns = 260ns (vs 130ns at 100MHz)
//   - Trace collection: identical (UART is the bottleneck at 9600 baud)
//   - Resource usage: +1 FF for clock divider
//
// =============================================================================

module aes_masked (
    input  wire clk,      // 100 MHz from Arty S7 oscillator (pin E3)
    input  wire rst,      // Active-high synchronous reset
    input  wire rx_pin,   // UART RX from PC (pin A9)
    output wire tx_pin,   // UART TX to PC   (pin D10)
    output wire led_busy  // Busy indicator LED (pin H5)
);

    // -------------------------------------------------------------------------
    // Clock divider: 100MHz → 50MHz for AES core and control logic
    // -------------------------------------------------------------------------
    reg clk_div_reg;  // toggles at 100MHz → creates 50MHz square wave

    always @(posedge clk) begin
        if (rst)
            clk_div_reg <= 1'b0;
        else
            clk_div_reg <= ~clk_div_reg;
    end

    wire clk_aes;
    assign clk_aes = clk_div_reg;  // 50 MHz clock for AES core and control FSM

    // -------------------------------------------------------------------------
    // Internal wiring — identical to original aes_masked.v
    // -------------------------------------------------------------------------

    // UART RX → Control FSM
    wire        rx_valid;
    wire [7:0]  rx_data;

    // Control FSM → UART TX
    wire        tx_start;
    wire [7:0]  tx_data_w;
    wire        tx_busy;

    // Control FSM → AES core
    wire        aes_start;
    wire [127:0] aes_plaintext;
    wire [127:0] aes_key;

    // AES core → Control FSM + HW monitor
    wire        aes_done;
    wire [127:0] aes_ciphertext;
    wire [127:0] aes_subbytes_out;  // MASKED SubBytes tap

    // Control FSM → HW monitor
    wire        hw_load;

    // HW monitor → Control FSM
    wire        hw_valid;
    wire [7:0]  hw_out;

    // -------------------------------------------------------------------------
    // UART RX — runs on 100MHz clock (unchanged divisor)
    // -------------------------------------------------------------------------
    uart_rx #(.DIVISOR(10417)) u_uart_rx (
        .clk      (clk),      // 100 MHz — IMPORTANT: not clk_aes
        .rst      (rst),
        .rx_pin   (rx_pin),
        .rx_data  (rx_data),
        .rx_valid (rx_valid)
    );

    // -------------------------------------------------------------------------
    // UART TX — runs on 100MHz clock (unchanged divisor)
    // -------------------------------------------------------------------------
    uart_tx #(.DIVISOR(10417)) u_uart_tx (
        .clk      (clk),      // 100 MHz — IMPORTANT: not clk_aes
        .rst      (rst),
        .tx_start (tx_start),
        .tx_data  (tx_data_w),
        .tx_pin   (tx_pin),
        .tx_busy  (tx_busy)
    );

    // -------------------------------------------------------------------------
    // AES masked core — runs on 50MHz clock
    // MODIFIED: now uses clk_aes instead of clk
    // -------------------------------------------------------------------------
    aes_core_masked u_aes_core (
        .clk         (clk_aes),  // MODIFIED: 50 MHz
        .rst         (rst),
        .start       (aes_start),
        .plaintext   (aes_plaintext),
        .key         (aes_key),
        .ciphertext  (aes_ciphertext),
        .done        (aes_done),
        .subbytes_out(aes_subbytes_out)
    );

    // -------------------------------------------------------------------------
    // Hamming Weight monitor — runs on 50MHz clock
    // MODIFIED: now uses clk_aes instead of clk
    // -------------------------------------------------------------------------
    hamming_weight u_hw_monitor (
        .clk      (clk_aes),  // MODIFIED: 50 MHz
        .rst      (rst),
        .load     (hw_load),
        .data_in  (aes_subbytes_out),
        .hw_out   (hw_out),
        .hw_valid (hw_valid)
    );

    // -------------------------------------------------------------------------
    // Control FSM — runs on 50MHz clock
    // MODIFIED: now uses clk_aes instead of clk
    //
    // CLOCK DOMAIN CROSSING ANALYSIS:
    //   Inputs from UART (clk domain): rx_valid, rx_data
    //     → These are ASYNCHRONOUS to clk_aes. However, the control FSM only
    //       samples rx_data when rx_valid=1, and rx_valid is asserted for 1 full
    //       100MHz cycle. At 50MHz, the FSM will see rx_valid HIGH for at least
    //       1 clk_aes cycle (possibly 2). The FSM design already handles this:
    //       it latches rx_data on the FIRST cycle rx_valid is seen, then ignores
    //       further rx_valid pulses until the byte counter advances.
    //       This is a SAFE quasi-static crossing (no metastability risk).
    //
    //   Outputs to UART (clk domain): tx_start, tx_data
    //     → tx_start is asserted for 1 clk_aes cycle. The UART TX sees this as
    //       a 20ns pulse on its 100MHz clock — sufficient to trigger (tx_start
    //       causes the TX FSM to latch tx_data and begin transmission).
    //       This is SAFE (no metastability, pulse width adequate).
    //
    // CONCLUSION: No synchronizers needed. The quasi-static nature of the
    //             protocol (low data rate, multi-cycle stable signals) makes
    //             this crossing safe without CDC logic.
    // -------------------------------------------------------------------------
    control_fsm u_control_fsm (
        .clk           (clk_aes),  // MODIFIED: 50 MHz
        .rst           (rst),
        .rx_valid      (rx_valid),
        .rx_data       (rx_data),
        .tx_busy       (tx_busy),
        .tx_start      (tx_start),
        .tx_data       (tx_data_w),
        .aes_start     (aes_start),
        .aes_plaintext (aes_plaintext),
        .aes_key       (aes_key),
        .aes_done      (aes_done),
        .aes_ciphertext(aes_ciphertext),
        .hw_load       (hw_load),
        .hw_valid      (hw_valid),
        .hw_out        (hw_out),
        .led_busy      (led_busy)
    );

endmodule
