// =============================================================================
// Module:      uart_tx
// Project:     AEGIS — Adaptive FPGA-Based Side-Channel Defense
// File:        rtl/interface/uart_tx.v
// Description: UART transmitter, 9600 baud, 8N1 (8 data bits, no parity,
//              1 stop bit). Transmits one byte per transaction.
//
// Protocol frame (LSB first, idle line = HIGH):
//   ____      ___________________________________________      ____
//       |    | D0  D1  D2  D3  D4  D5  D6  D7          |    |
//       |START|                                    |STOP|
//       |_____|                                    |____|
//
// Timing:
//   Clock:     100 MHz  → period = 10 ns
//   Baud rate: 9600     → bit period = 104,167 ns = 10,417 cycles
//   DIVISOR    = 10417  (rounds to nearest; error < 0.01%)
//
// Port summary:
//   clk       — 100 MHz system clock
//   rst       — synchronous reset, active high
//   tx_start  — pulse high for ONE cycle to begin transmission
//   tx_data   — 8-bit byte to send (must be stable when tx_start is high)
//   tx_pin    — serial output to FPGA pin (idle HIGH per RS-232 convention)
//   tx_busy   — high from tx_start until stop bit completes; caller must
//               not assert tx_start again while tx_busy is high
//
// FSM states:
//   IDLE  — line idle (HIGH), waiting for tx_start
//   START — driving start bit (LOW) for one baud period
//   DATA  — shifting out 8 data bits LSB-first, one per baud period
//   STOP  — driving stop bit (HIGH) for one baud period, then → IDLE
// =============================================================================

module uart_tx (
    input  wire       clk,
    input  wire       rst,
    input  wire       tx_start,   // pulse: begin sending tx_data
    input  wire [7:0] tx_data,    // byte to transmit
    output reg        tx_pin,     // serial line out
    output reg        tx_busy     // high while frame in progress
);

    // -------------------------------------------------------------------------
    // Parameters
    // -------------------------------------------------------------------------
    // DIVISOR: number of 100MHz clock cycles per baud period.
    // 100_000_000 / 9600 = 10416.67 → round to 10417.
    // This gives a baud error of (10417 - 10416.67)/10416.67 = 0.003%,
    // well within the ±2% tolerance of standard UART receivers.
    parameter DIVISOR = 10417;

    // -------------------------------------------------------------------------
    // FSM state encoding — one-hot for speed on Spartan-7 LUT4 fabric
    // -------------------------------------------------------------------------
    localparam [1:0]
        IDLE  = 2'b00,
        START = 2'b01,
        DATA  = 2'b10,
        STOP  = 2'b11;

    reg [1:0] state;

    // -------------------------------------------------------------------------
    // Baud rate generator
    // Counts from 0 to DIVISOR-1, then pulses baud_tick for one clock cycle.
    // All state transitions happen on baud_tick edges.
    // -------------------------------------------------------------------------
    reg [13:0] baud_cnt;   // 14 bits: ceil(log2(10417)) = 14
    reg        baud_tick;  // one-cycle pulse at each baud boundary

    always @(posedge clk) begin
        if (rst) begin
            baud_cnt  <= 14'd0;
            baud_tick <= 1'b0;
        end else if (state == IDLE) begin
            // Reset counter while idle so first baud period after START
            // is exactly DIVISOR cycles — no partial period at the start
            // of a frame.
            baud_cnt  <= 14'd0;
            baud_tick <= 1'b0;
        end else if (baud_cnt == DIVISOR - 1) begin
            baud_cnt  <= 14'd0;
            baud_tick <= 1'b1;   // tick fires this cycle
        end else begin
            baud_cnt  <= baud_cnt + 14'd1;
            baud_tick <= 1'b0;
        end
    end

    // -------------------------------------------------------------------------
    // Shift register and bit counter
    // -------------------------------------------------------------------------
    reg [7:0] shift_reg;  // holds byte being transmitted
    reg [2:0] bit_cnt;    // counts data bits sent: 0–7

    // -------------------------------------------------------------------------
    // TX FSM
    // -------------------------------------------------------------------------
    always @(posedge clk) begin
        if (rst) begin
            state     <= IDLE;
            tx_pin    <= 1'b1;    // idle line HIGH (RS-232 mark state)
            tx_busy   <= 1'b0;
            shift_reg <= 8'b0;
            bit_cnt   <= 3'd0;
        end else begin
            case (state)

                // ── IDLE ─────────────────────────────────────────────────────
                IDLE: begin
                    tx_pin  <= 1'b1;   // hold line HIGH
                    tx_busy <= 1'b0;
                    if (tx_start) begin
                        // Latch data NOW so caller can change tx_data next cycle
                        shift_reg <= tx_data;
                        bit_cnt   <= 3'd0;
                        tx_busy   <= 1'b1;  // busy from this cycle onward
                        state     <= START;
                        // Note: baud_cnt resets to 0 on IDLE→START transition
                        // (handled in baud generator above) so the START bit
                        // will be held for exactly DIVISOR cycles.
                    end
                end

                // ── START ─────────────────────────────────────────────────────
                // Drive tx_pin LOW for one full baud period (start bit).
                START: begin
                    tx_pin <= 1'b0;        // start bit = LOW
                    if (baud_tick) begin
                        state <= DATA;     // move to data after one bit period
                    end
                end

                // ── DATA ──────────────────────────────────────────────────────
                // Shift out 8 bits LSB-first, one per baud tick.
                DATA: begin
                    tx_pin <= shift_reg[0];   // LSB on the wire
                    if (baud_tick) begin
                        shift_reg <= {1'b0, shift_reg[7:1]};  // shift right
                        if (bit_cnt == 3'd7) begin
                            // All 8 bits sent — move to stop bit
                            state <= STOP;
                        end else begin
                            bit_cnt <= bit_cnt + 3'd1;
                        end
                    end
                end

                // ── STOP ──────────────────────────────────────────────────────
                // Drive tx_pin HIGH for one full baud period (stop bit),
                // then return to IDLE.
                STOP: begin
                    tx_pin <= 1'b1;        // stop bit = HIGH
                    if (baud_tick) begin
                        tx_busy <= 1'b0;   // frame complete
                        state   <= IDLE;
                    end
                end

                // ── Default (should never hit in synthesis) ───────────────────
                default: begin
                    state   <= IDLE;
                    tx_pin  <= 1'b1;
                    tx_busy <= 1'b0;
                end

            endcase
        end
    end

endmodule
