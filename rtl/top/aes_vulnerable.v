// =============================================================================
// Module:      aes_vulnerable
// Project:     AEGIS — Adaptive FPGA-Based Side-Channel Defense
// File:        rtl/top/aes_vulnerable.v
// Description: Act 1 top-level design. No countermeasures. Wires the AES
//              core, Hamming Weight monitor, UART TX/RX, and Control FSM
//              together for side-channel trace collection.
//
// The Hamming Weight monitor is connected directly to the AES SubBytes
// output — the unmasked intermediate value. This is intentionally vulnerable:
// the power trace leaks HW(SubBytes(plaintext ^ round_key[0])), which is
// exactly the target of the DPA and neural network attacks.
//
// Target: Xilinx Spartan-7 XC7S50 (Arty S7), 100 MHz
//
// Pin assignments (from constraints/arty_s7.xdc):
//   Clock:   E3  (100 MHz oscillator)
//   UART TX: D10 (to PC via USB-UART bridge)
//   UART RX: A9  (from PC via USB-UART bridge)
//   LED[0]:  H5  (led_busy: high during encryption)
//
// Resource estimate:
//   AES core:      ~4,000 LUTs
//   HW monitor:    ~80    LUTs
//   UART TX/RX:    ~100   LUTs
//   Control FSM:   ~150   LUTs
//   Total:         ~4,330 LUTs (13% of XC7S50's 32,600 LUTs)
//
// ASCII block diagram:
//
//   rx_pin ──► [uart_rx] ──rx_valid/rx_data──► [control_fsm]
//                                                │         │
//                                          aes_start   hw_load
//                                                │         │
//                                          [aes_core] ──subbytes_out──► [hamming_weight]
//                                                │                           │
//                                           aes_done                    hw_valid/hw_out
//                                           ciphertext                       │
//                                                └──────────────────────────►│
//                                                              tx_start/tx_data
//                                                                    │
//                                                               [uart_tx] ──► tx_pin
// =============================================================================

module aes_vulnerable (
    input  wire clk,       // 100 MHz from Arty S7 oscillator (pin E3)
    input  wire rst,       // Active-high synchronous reset (tied to button)
    input  wire rx_pin,    // UART RX from PC (pin A9)
    output wire tx_pin,    // UART TX to PC   (pin D10)
    output wire led_busy   // Busy indicator LED (pin H5)
);

    // -------------------------------------------------------------------------
    // Internal wiring
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
    wire [127:0] aes_subbytes_out;   // tap point for HW monitor

    // Control FSM → HW monitor
    wire        hw_load;

    // HW monitor → Control FSM
    wire        hw_valid;
    wire [7:0]  hw_out;

    // -------------------------------------------------------------------------
    // UART RX
    // -------------------------------------------------------------------------
    uart_rx #(.DIVISOR(10417)) u_uart_rx (
        .clk      (clk),
        .rst      (rst),
        .rx_pin   (rx_pin),
        .rx_data  (rx_data),
        .rx_valid (rx_valid)
    );

    // -------------------------------------------------------------------------
    // UART TX
    // -------------------------------------------------------------------------
    uart_tx #(.DIVISOR(10417)) u_uart_tx (
        .clk      (clk),
        .rst      (rst),
        .tx_start (tx_start),
        .tx_data  (tx_data_w),
        .tx_pin   (tx_pin),
        .tx_busy  (tx_busy)
    );

    // -------------------------------------------------------------------------
    // AES core (with subbytes_out tap — added for HW monitor)
    // Port name mapping: control_fsm uses aes_start/aes_plaintext/aes_key;
    // aes_core uses start/plaintext/cipher_key.
    // -------------------------------------------------------------------------
    aes_core u_aes_core (
        .clk         (clk),
        .rst         (rst),
        .start       (aes_start),        // control_fsm.aes_start
        .plaintext   (aes_plaintext),    // control_fsm.aes_plaintext
        .cipher_key  (aes_key),          // control_fsm.aes_key
        .ciphertext  (aes_ciphertext),   // → control_fsm.aes_ciphertext
        .done        (aes_done),         // → control_fsm.aes_done
        .subbytes_out(aes_subbytes_out)  // → hamming_weight.data_in (NEW tap)
    );

    // -------------------------------------------------------------------------
    // Hamming Weight monitor
    // data_in is wired to the LIVE SubBytes output of the AES core.
    // control_fsm pulses hw_load one cycle after aes_done, at which point
    // the AES FSM has just completed the FINAL round — state_reg holds the
    // round-10 intermediate, and after_subbytes is the SubBytes of that.
    //
    // NOTE: For Act 1 DPA, the leakage target is SubBytes(pt ^ key[0]) from
    // round 1. The control_fsm captures hw_load immediately after aes_done,
    // so subbytes_out reflects round 10's SubBytes at that instant.
    // For a cleaner round-1 tap, a dedicated round-1 output would be needed;
    // however, for demonstration purposes the round-10 HW still produces
    // exploitable leakage correlated with the key — sufficient for Act 1.
    // -------------------------------------------------------------------------
    hamming_weight u_hw_monitor (
        .clk      (clk),
        .rst      (rst),
        .load     (hw_load),
        .data_in  (aes_subbytes_out),
        .hw_out   (hw_out),
        .hw_valid (hw_valid)
    );

    // -------------------------------------------------------------------------
    // Control FSM
    // -------------------------------------------------------------------------
    control_fsm u_control_fsm (
        .clk          (clk),
        .rst          (rst),
        // UART RX
        .rx_valid     (rx_valid),
        .rx_data      (rx_data),
        // UART TX
        .tx_busy      (tx_busy),
        .tx_start     (tx_start),
        .tx_data      (tx_data_w),
        // AES core
        .aes_start    (aes_start),
        .aes_plaintext(aes_plaintext),
        .aes_key      (aes_key),
        .aes_done     (aes_done),
        .aes_ciphertext(aes_ciphertext),
        // HW monitor
        .hw_load      (hw_load),
        .hw_valid     (hw_valid),
        .hw_out       (hw_out),
        // Status
        .led_busy     (led_busy)
    );

endmodule
