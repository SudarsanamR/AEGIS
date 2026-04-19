// =============================================================================
// Module:      control_fsm
// Project:     AEGIS — Adaptive FPGA-Based Side-Channel Defense
// File:        rtl/interface/control_fsm.v
// Description: Top-level control FSM that orchestrates the UART↔AES↔HW
//              pipeline for side-channel trace collection.
//
// Protocol:
//   PC → FPGA : 32 bytes  [plaintext[0..15], key[0..15]]  (byte 0 first)
//   FPGA → PC : 17 bytes  [ciphertext[0..15], hw_byte]    (byte 0 first)
//
// The HW byte is the Hamming Weight of the AES SubBytes output captured
// at the first round — this is the leakage model for the DPA attack.
// In aes_vulnerable.v the SubBytes output is wired directly to hw_monitor;
// the control FSM just triggers hw_load after aes_done and reads hw_out.
//
// FSM states:
//   WAIT_DATA   — receive 32 UART bytes into pt_buf and key_buf
//   LOAD_AES    — pulse aes_start for one cycle, load pt/key into AES core
//   WAIT_AES    — wait for aes_done from AES core
//   CAPTURE_HW  — pulse hw_load for one cycle to trigger HW monitor
//   WAIT_HW     — wait for hw_valid from HW monitor (2-cycle latency)
//   SEND_CT     — transmit 16 ciphertext bytes via UART TX
//   SEND_HW     — transmit 1 HW byte via UART TX
//   WAIT_TX     — wait for current tx_busy to deassert before next byte
//
// Port summary:
//   clk, rst            — 100 MHz clock, synchronous reset active-high
//   -- UART RX interface --
//   rx_valid            — from uart_rx: one-cycle pulse, rx_data valid
//   rx_data [7:0]       — from uart_rx: received byte
//   -- UART TX interface --
//   tx_busy             — from uart_tx: high while transmitting
//   tx_start            — to uart_tx: pulse to begin transmission
//   tx_data [7:0]       — to uart_tx: byte to transmit
//   -- AES core interface --
//   aes_start           — to aes_core: pulse to begin encryption
//   aes_plaintext[127:0]— to aes_core: plaintext (column-major)
//   aes_key[127:0]      — to aes_core: key (column-major)
//   aes_done            — from aes_core: encryption complete
//   aes_ciphertext[127:0]— from aes_core: encrypted result
//   -- HW monitor interface --
//   hw_load             — to hamming_weight: pulse to capture
//   hw_valid            — from hamming_weight: sticky valid
//   hw_out [7:0]        — from hamming_weight: popcount result
//   -- Status --
//   led_busy            — high while processing (drives onboard LED)
// =============================================================================

module control_fsm (
    input  wire         clk,
    input  wire         rst,

    // UART RX
    input  wire         rx_valid,
    input  wire [7:0]   rx_data,

    // UART TX
    input  wire         tx_busy,
    output reg          tx_start,
    output reg  [7:0]   tx_data,

    // AES core
    output reg          aes_start,
    output reg  [127:0] aes_plaintext,
    output reg  [127:0] aes_key,
    input  wire         aes_done,
    input  wire [127:0] aes_ciphertext,

    // Hamming Weight monitor
    output reg          hw_load,
    input  wire         hw_valid,
    input  wire [7:0]   hw_out,

    // Status
    output reg          led_busy
);

    // -------------------------------------------------------------------------
    // FSM state encoding
    // -------------------------------------------------------------------------
    localparam [2:0]
        WAIT_DATA  = 3'd0,   // receiving 32 bytes from PC
        LOAD_AES   = 3'd1,   // pulsing aes_start
        WAIT_AES   = 3'd2,   // waiting for aes_done
        CAPTURE_HW = 3'd3,   // pulsing hw_load
        WAIT_HW    = 3'd4,   // waiting for hw_valid
        SEND_CT    = 3'd5,   // transmitting ciphertext bytes 0–15
        SEND_HW    = 3'd6,   // transmitting HW byte
        WAIT_TX    = 3'd7;   // waiting for tx_busy to clear

    reg [2:0] state;
    reg [2:0] next_state;   // state to return to after WAIT_TX

    // -------------------------------------------------------------------------
    // Byte reception counters and buffers
    // -------------------------------------------------------------------------
    reg [5:0]  byte_cnt;       // counts received bytes 0–31
    reg [7:0]  pt_buf  [0:15]; // plaintext buffer, byte 0 = pt_buf[0]
    reg [7:0]  key_buf [0:15]; // key buffer,       byte 0 = key_buf[0]

    // -------------------------------------------------------------------------
    // Transmission counter
    // -------------------------------------------------------------------------
    reg [4:0]  tx_byte_idx;    // index of next byte to transmit (0–16)

    // -------------------------------------------------------------------------
    // HW byte storage — latch hw_out when hw_valid asserts
    // -------------------------------------------------------------------------
    reg [7:0]  hw_capture;

    // -------------------------------------------------------------------------
    // 128-bit assembly helpers
    // Build column-major 128-bit word from byte array.
    // Column-major: byte[0] → bits[127:120], byte[1] → bits[119:112], etc.
    // This matches the ordering defined in the project hardware rules.
    // -------------------------------------------------------------------------
    // These are driven combinationally from pt_buf/key_buf in LOAD_AES.
    integer j;

    // -------------------------------------------------------------------------
    // FSM
    // -------------------------------------------------------------------------
    always @(posedge clk) begin
        if (rst) begin
            state        <= WAIT_DATA;
            next_state   <= WAIT_DATA;
            byte_cnt     <= 6'd0;
            tx_byte_idx  <= 5'd0;
            tx_start     <= 1'b0;
            tx_data      <= 8'h00;
            aes_start    <= 1'b0;
            aes_plaintext<= 128'd0;
            aes_key      <= 128'd0;
            hw_load      <= 1'b0;
            hw_capture   <= 8'd0;
            led_busy     <= 1'b0;
            // Clear buffers
            for (j = 0; j < 16; j = j + 1) begin
                pt_buf[j]  <= 8'h00;
                key_buf[j] <= 8'h00;
            end
        end else begin
            // Default: deassert all one-cycle strobes each cycle
            tx_start  <= 1'b0;
            aes_start <= 1'b0;
            hw_load   <= 1'b0;

            case (state)

                // ── WAIT_DATA ─────────────────────────────────────────────────
                // Receive exactly 32 bytes: first 16 → plaintext, next 16 → key.
                // byte_cnt tracks position; resets to 0 at start of each frame.
                WAIT_DATA: begin
                    led_busy <= 1'b0;
                    if (rx_valid) begin
                        if (byte_cnt < 6'd16) begin
                            // Bytes 0–15: plaintext
                            pt_buf[byte_cnt[3:0]] <= rx_data;
                        end else begin
                            // Bytes 16–31: key
                            key_buf[byte_cnt[3:0]] <= rx_data;
                        end

                        if (byte_cnt == 6'd31) begin
                            // All 32 bytes received — proceed to encrypt
                            byte_cnt <= 6'd0;
                            state    <= LOAD_AES;
                        end else begin
                            byte_cnt <= byte_cnt + 6'd1;
                        end
                    end
                end

                // ── LOAD_AES ──────────────────────────────────────────────────
                // Assemble the 128-bit plaintext and key from byte buffers
                // (column-major: byte 0 in bits [127:120]) and pulse aes_start.
                LOAD_AES: begin
                    led_busy <= 1'b1;

                    // Assemble column-major 128-bit words from byte arrays.
                    // byte[i] → bits[(127 - i*8) : (120 - i*8)]
                    aes_plaintext <= {
                        pt_buf[0],  pt_buf[1],  pt_buf[2],  pt_buf[3],
                        pt_buf[4],  pt_buf[5],  pt_buf[6],  pt_buf[7],
                        pt_buf[8],  pt_buf[9],  pt_buf[10], pt_buf[11],
                        pt_buf[12], pt_buf[13], pt_buf[14], pt_buf[15]
                    };
                    aes_key <= {
                        key_buf[0],  key_buf[1],  key_buf[2],  key_buf[3],
                        key_buf[4],  key_buf[5],  key_buf[6],  key_buf[7],
                        key_buf[8],  key_buf[9],  key_buf[10], key_buf[11],
                        key_buf[12], key_buf[13], key_buf[14], key_buf[15]
                    };

                    aes_start <= 1'b1;   // one-cycle pulse to AES core
                    state     <= WAIT_AES;
                end

                // ── WAIT_AES ──────────────────────────────────────────────────
                // Poll aes_done. AES core holds done high for one cycle.
                // The HW monitor input is wired to the SubBytes output inside
                // aes_vulnerable.v — we trigger hw_load immediately after done.
                WAIT_AES: begin
                    if (aes_done) begin
                        state <= CAPTURE_HW;
                    end
                end

                // ── CAPTURE_HW ────────────────────────────────────────────────
                // Pulse hw_load for one cycle. The hamming_weight module will
                // latch whatever is on its data_in (wired to SubBytes output
                // in the top-level) and produce hw_valid 2 cycles later.
                CAPTURE_HW: begin
                    hw_load <= 1'b1;    // one-cycle pulse
                    state   <= WAIT_HW;
                end

                // ── WAIT_HW ───────────────────────────────────────────────────
                // hw_valid is sticky — stays high after it asserts.
                // Latch hw_out when it arrives.
                WAIT_HW: begin
                    if (hw_valid) begin
                        hw_capture  <= hw_out;
                        tx_byte_idx <= 5'd0;
                        state       <= SEND_CT;
                    end
                end

                // ── SEND_CT ───────────────────────────────────────────────────
                // Transmit ciphertext bytes 0–15 over UART TX.
                // Each byte: assert tx_start, then go to WAIT_TX.
                // WAIT_TX returns to SEND_CT; when all 16 done → SEND_HW.
                SEND_CT: begin
                    if (!tx_busy) begin
                        // Extract byte tx_byte_idx from ciphertext (column-major)
                        // byte i → aes_ciphertext[(127 - i*8) -: 8]
                        tx_data  <= aes_ciphertext[(127 - tx_byte_idx*8) -: 8];
                        tx_start <= 1'b1;

                        if (tx_byte_idx == 5'd15) begin
                            // Last ciphertext byte just started — go to HW next
                            next_state  <= SEND_HW;
                            tx_byte_idx <= 5'd0;
                        end else begin
                            next_state  <= SEND_CT;
                            tx_byte_idx <= tx_byte_idx + 5'd1;
                        end
                        state <= WAIT_TX;
                    end
                end

                // ── SEND_HW ───────────────────────────────────────────────────
                // Transmit the single Hamming Weight byte.
                SEND_HW: begin
                    if (!tx_busy) begin
                        tx_data    <= hw_capture;
                        tx_start   <= 1'b1;
                        next_state <= WAIT_DATA;  // after HW → receive next frame
                        state      <= WAIT_TX;
                    end
                end

                // ── WAIT_TX ───────────────────────────────────────────────────
                // Wait for tx_busy to deassert (current byte fully transmitted),
                // then return to next_state.
                // We must wait at least one cycle after asserting tx_start
                // before sampling tx_busy, since tx_busy asserts the same
                // cycle tx_start is seen — hence the 'if (!tx_busy)' guards
                // in SEND_CT/SEND_HW ensure we don't re-enter WAIT_TX while
                // already busy.
                WAIT_TX: begin
                    if (!tx_busy) begin
                        state <= next_state;
                    end
                end

                default: state <= WAIT_DATA;

            endcase
        end
    end

endmodule
