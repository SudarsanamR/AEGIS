// =============================================================================
// Module:      uart_rx
// Project:     AEGIS — Adaptive FPGA-Based Side-Channel Defense
// File:        rtl/interface/uart_rx.v
// Description: UART receiver, 9600 baud, 8N1 (8 data bits, no parity,
//              1 stop bit). Receives one byte per frame, outputs with
//              a one-cycle rx_valid strobe.
//
// Centre-sampling strategy:
//   When the falling edge of the start bit is detected, the baud counter
//   is pre-loaded to DIVISOR/2. This causes the first baud_tick to fire
//   at the midpoint of the start bit, and every subsequent tick lands at
//   the midpoint of the next bit. Midpoint sampling maximises noise margin
//   and is standard practice in UART receiver design.
//
// Metastability:
//   rx_pin is an asynchronous input from the outside world. It passes
//   through a 2-FF synchroniser before entering any combinational logic.
//   This is mandatory on all async inputs to synchronous designs.
//
// Port summary:
//   clk       — 100 MHz system clock
//   rst       — synchronous reset, active high
//   rx_pin    — serial input from FPGA pin
//   rx_data   — 8-bit received byte, valid when rx_valid is high
//   rx_valid  — pulses high for ONE clock cycle when a byte is ready
//               (caller must latch rx_data on the cycle rx_valid is high)
//
// FSM states:
//   IDLE  — waiting for start bit (falling edge on rx_sync)
//   START — verifying start bit at centre sample (must still be LOW)
//   DATA  — sampling 8 data bits at centre of each baud period
//   STOP  — sampling stop bit, asserting rx_valid if stop bit is HIGH
// =============================================================================

module uart_rx (
    input  wire       clk,
    input  wire       rst,
    input  wire       rx_pin,    // raw serial input from pin
    output reg  [7:0] rx_data,   // received byte
    output reg        rx_valid   // one-cycle pulse: rx_data is valid
);

    // -------------------------------------------------------------------------
    // Parameters
    // -------------------------------------------------------------------------
    parameter DIVISOR      = 10417;          // cycles per baud (100MHz / 9600)
    parameter HALF_DIVISOR = DIVISOR / 2;    // 5208: centre of first bit

    // -------------------------------------------------------------------------
    // FSM state encoding
    // -------------------------------------------------------------------------
    localparam [1:0]
        IDLE  = 2'b00,
        START = 2'b01,
        DATA  = 2'b10,
        STOP  = 2'b11;

    reg [1:0] state;

    // -------------------------------------------------------------------------
    // 2-FF synchroniser for rx_pin
    // Prevents metastability from propagating into the FSM.
    // Both FFs use the same clock domain (100 MHz).
    // -------------------------------------------------------------------------
    reg rx_sync0, rx_sync1;   // synchroniser pipeline stages

    always @(posedge clk) begin
        if (rst) begin
            rx_sync0 <= 1'b1;   // idle line is HIGH
            rx_sync1 <= 1'b1;
        end else begin
            rx_sync0 <= rx_pin;   // first stage: capture raw input
            rx_sync1 <= rx_sync0; // second stage: now safe to use in logic
        end
    end

    // -------------------------------------------------------------------------
    // Falling-edge detector on synchronised rx
    // prev_rx stores rx_sync1 from last cycle so we can detect HIGH→LOW.
    // start_detected is combinational — it goes high the cycle rx_sync1
    // first goes LOW after being HIGH (i.e., the start bit arrival).
    // -------------------------------------------------------------------------
    reg rx_prev;   // rx_sync1 delayed by one cycle for edge detection

    always @(posedge clk) begin
        if (rst)
            rx_prev <= 1'b1;
        else
            rx_prev <= rx_sync1;
    end

    // Falling edge: was HIGH last cycle, is LOW this cycle
    wire start_detected = rx_prev & ~rx_sync1;

    // -------------------------------------------------------------------------
    // Baud rate generator with centre-sample pre-load
    //
    // Normal operation: count up to DIVISOR-1, then pulse baud_tick.
    // On start_detected:  pre-load to HALF_DIVISOR so first tick fires at
    //                     the centre of the start bit.
    // While IDLE:         hold counter at 0 (no counting needed).
    // -------------------------------------------------------------------------
    reg [13:0] baud_cnt;
    reg        baud_tick;

    always @(posedge clk) begin
        if (rst) begin
            baud_cnt  <= 14'd0;
            baud_tick <= 1'b0;
        end else if (state == IDLE) begin
            // Pre-arm: if start detected this cycle, load HALF_DIVISOR so
            // counting starts immediately on the transition to START state.
            if (start_detected)
                baud_cnt <= HALF_DIVISOR[13:0];
            else
                baud_cnt <= 14'd0;
            baud_tick <= 1'b0;
        end else if (baud_cnt == DIVISOR - 1) begin
            baud_cnt  <= 14'd0;
            baud_tick <= 1'b1;
        end else begin
            baud_cnt  <= baud_cnt + 14'd1;
            baud_tick <= 1'b0;
        end
    end

    // -------------------------------------------------------------------------
    // Shift register and bit counter
    // -------------------------------------------------------------------------
    reg [7:0] shift_reg;   // accumulates received bits
    reg [2:0] bit_cnt;     // counts data bits received: 0–7

    // -------------------------------------------------------------------------
    // RX FSM
    // -------------------------------------------------------------------------
    always @(posedge clk) begin
        if (rst) begin
            state     <= IDLE;
            rx_data   <= 8'b0;
            rx_valid  <= 1'b0;
            shift_reg <= 8'b0;
            bit_cnt   <= 3'd0;
        end else begin
            rx_valid <= 1'b0;   // default: valid is a one-cycle pulse

            case (state)

                // ── IDLE ──────────────────────────────────────────────────────
                // Wait for falling edge on rx_sync1 (start bit).
                IDLE: begin
                    bit_cnt <= 3'd0;
                    if (start_detected) begin
                        // Baud counter is already pre-loaded to HALF_DIVISOR
                        // in the baud generator above; transition immediately.
                        state <= START;
                    end
                end

                // ── START ─────────────────────────────────────────────────────
                // Wait for baud_tick (centre of start bit), then verify LOW.
                // If the line is HIGH at centre, it was a glitch — go back
                // to IDLE. This is a basic false-start rejection.
                START: begin
                    if (baud_tick) begin
                        if (rx_sync1 == 1'b0) begin
                            // Genuine start bit confirmed at centre sample
                            state <= DATA;
                        end else begin
                            // Line went high again — noise/glitch, abort
                            state <= IDLE;
                        end
                    end
                end

                // ── DATA ──────────────────────────────────────────────────────
                // Sample one bit per baud_tick, LSB first, shift into MSB
                // of shift_reg (shift right so LSB ends at bit 0).
                DATA: begin
                    if (baud_tick) begin
                        // Shift in from MSB; after 8 bits, LSB is in [0]
                        shift_reg <= {rx_sync1, shift_reg[7:1]};
                        if (bit_cnt == 3'd7) begin
                            state <= STOP;
                        end else begin
                            bit_cnt <= bit_cnt + 3'd1;
                        end
                    end
                end

                // ── STOP ──────────────────────────────────────────────────────
                // Sample stop bit at centre. If HIGH (valid stop), latch
                // shift_reg into rx_data and pulse rx_valid.
                // If LOW (framing error), discard silently and return to IDLE.
                // (No framing error output — keep interface simple for AEGIS.)
                STOP: begin
                    if (baud_tick) begin
                        if (rx_sync1 == 1'b1) begin
                            // Valid stop bit — output the received byte
                            rx_data  <= shift_reg;
                            rx_valid <= 1'b1;   // one-cycle pulse
                        end
                        // Whether valid or framing error, return to IDLE
                        state <= IDLE;
                    end
                end

                default: begin
                    state <= IDLE;
                end

            endcase
        end
    end

endmodule
