# AEGIS — Architecture & Security Analysis

## 1. System Overview

AEGIS implements a three-stage side-channel defense demonstration on the
Xilinx Spartan-7 XC7S50 FPGA (Arty S7 board). Each stage adds a new layer
of protection, and each layer's effectiveness is quantified by running
the same attack suite against it.

```
──────────────── SIGNAL FLOW ────────────────

  PC (Python)                      FPGA (Verilog)
  ┌───────────┐      UART         ┌─────────────────────┐
  │ Plaintext │ ──────9600──────► │ Control FSM         │
  │ Generator │                   │   │                 │
  │           │                   │   ▼                 │
  │ DPA /     │      UART        │ AES Core (50 MHz)   │
  │ Neural    │ ◄──────────────── │   │                 │
  │ Attack    │   CT + HW byte   │   ▼                 │
  └───────────┘                   │ HW Monitor (popcount│
                                  └─────────────────────┘
```

## 2. AES-128 Implementation

### 2.1 Iterative Round Architecture

The AES core uses a **single-round iterative** architecture (not pipelined,
not fully unrolled). This is the most resource-efficient approach, using
one set of SubBytes/ShiftRows/MixColumns/AddRoundKey hardware shared
across all 10 rounds via an FSM.

**FSM**: `IDLE → INIT → ROUND(×9) → FINAL → DONE`

- **INIT**: `state = plaintext ⊕ round_key[0]` (initial AddRoundKey)
- **ROUND 1–9**: SubBytes → ShiftRows → MixColumns → AddRoundKey
- **FINAL (Round 10)**: SubBytes → ShiftRows → AddRoundKey (no MixColumns)

**Latency**: 13 clock cycles (1 INIT + 9 ROUND + 1 FINAL + 1 DONE + 1 capture)

### 2.2 Key Schedule

Fully combinational — all 11 round keys generated in parallel from the
128-bit cipher key. This avoids key scheduling latency at the cost of
~3000 LUTs. Acceptable for the Spartan-7 which has 32,600 LUTs.

## 3. Side-Channel Vulnerability (Act 1)

### 3.1 Leakage Point

The Hamming Weight (HW) of the Round 1 SubBytes output leaks through
CMOS power consumption: `P ∝ HW(SubBytes(plaintext[j] ⊕ key[j]))`.

The `hamming_weight.v` module computes this internally and sends it
via UART alongside the ciphertext — simulating what an oscilloscope
would measure from the power rail.

### 3.2 DPA Attack

**Model**: For each key guess `kg`, compute:
```
hypothesis[i] = HW(SubBytes(plaintext[i, byte_j] ⊕ kg))
correlation[kg] = Pearson(hypothesis, traces)
```
The correct `kg` produces maximum |correlation|.

**Result**: Key recovered at ~200 traces with |r| ≈ 0.25.

## 4. Boolean Masking Defense (Act 2)

### 4.1 Masking Invariant

Every register in the masked AES core holds `real_value ⊕ {mask × 16}`,
where `mask` is an 8-bit value replicated across all 16 bytes.

**Critical property**: `mask_reg` and `state_masked` advance simultaneously
on every clock edge. If they ever get out of sync by one cycle, the output
is wrong.

### 4.2 LFSR Mask Rotation

After each SubBytes call, `mask_reg` advances one LFSR step:
```
Polynomial: x^8 + x^6 + x^5 + x^4 + 1
next_mask = {mask_reg[6:0], mask_reg[7]⊕mask_reg[5]⊕mask_reg[4]⊕mask_reg[3]}
```

Period = 255 (all non-zero values). Seed = 0xAC.

### 4.3 Why DPA Fails

With uniform mask `m`, `Cov(HW(x), HW(x⊕m)) = 0` when `HW(m) = 4`.
The mask 0x59 (LFSR round-1 output from seed 0xAC) has HW = 4.
This is a provable decorrelation.

### 4.4 Why Neural Attacks Succeed

The mask is **constant** across all traces (same seed every encryption).
The leakage function `HW(SubBytes(pt ⊕ k) ⊕ 0x59)` is a fixed,
deterministic mapping. An MLP with sufficient capacity learns this
mapping from labeled training data (profiling attack).

## 5. Full Hardening (Act 3)

### 5.1 Ring Oscillator TRNG

```
     ┌──────────────────────────────┐
     │  ┌───┐   ┌───┐   ┌───┐     │
     └──┤NOT├───┤NOT├───┤NOT├──┬───┘ osc_out[i]
        └───┘   └───┘   └───┘  │
                                ▼
                        XOR of 8 oscillators
                                │
                        sample @ 1 MHz
                                │
                            trng_bit
```

8 parallel ring oscillators, each 3 LUT1 stages with feedback.
`KEEP` and `DONT_TOUCH` attributes prevent Vivado optimization.
Placed in Pblock `SLICE_X0Y0:SLICE_X3Y3` for thermal coupling.

### 5.2 Entropy Validation

Non-overlapping 10,000-bit window checks:
- `ones_count >= 4,500` (45%)
- `ones_count <= 5,500` (55%)

If the test fails, `entropy_valid` goes to 0 and the AES core halts.
First validation takes 10 ms at the 1 MHz TRNG rate.

### 5.3 TRNG-Sourced Mask Seed

**Key change from Act 2**: `mask_reg` is loaded from `trng_seed` (a port)
at the start of each encryption, instead of the constant `MASK_SEED = 0xAC`.

This means every encryption uses a **different, truly random** initial mask.
The LFSR still rotates the mask between rounds (for decorrelation within
a single encryption), but the starting point is unpredictable.

### 5.4 Why Neural Attacks Fail on Hardened Design

With random mask seeds, the leakage for the same plaintext byte is:
```
trace[i] = HW(SubBytes(pt[i] ⊕ key) ⊕ lfsr_next(random_seed[i])) + noise
```

The mask changes every trace. There is no fixed mapping from plaintext
to leakage — the function is randomized. An MLP cannot learn a
relationship that doesn't persist across traces.

Expected neural attack accuracy: ~15% (random guessing over 9 HW classes).
Expected key rank: ~128 (median of uniform distribution over 256 candidates).

### 5.5 Timing Jitter

```
  AES FSM:  ROUND → S_JITTER → ROUND → S_JITTER → ... → FINAL → DONE
                       ↕                    ↕
            timing_randomizer        timing_randomizer
            (0–15 dummy cycles)      (0–15 dummy cycles)
```

- Each round produces a `round_done` pulse
- Timing randomizer loads a 4-bit TRNG nibble into a countdown register
- `proceed` fires when countdown reaches 0
- AES FSM resumes the next round on `proceed`

**Effect on traces**: Adjacent encryptions have different total cycle counts
(13–173 cycles). If an attacker captures power traces with an oscilloscope,
the round boundaries don't align across traces, destroying time-domain
correlation.

## 6. Clock Domain Crossing

```
  100 MHz domain          50 MHz domain
  ┌─────────────┐         ┌──────────────────────┐
  │ UART RX/TX  │         │ AES core             │
  │ TRNG (ROs)  │ ──CDC──►│ Timing randomizer    │
  └─────────────┘         │ TRNG validator       │
                          │ Control FSM          │
                          └──────────────────────┘
```

- **UART → Control FSM**: Quasi-static crossing (rx_valid is wide enough)
- **TRNG → Validator**: Toggle-based CDC with 2-FF synchronizer

## 7. Resource Budget

| Module | LUTs | FFs | BRAMs |
|--------|------|-----|-------|
| Key expansion | ~3,000 | 0 | 0 |
| AES core (masked) | ~1,500 | ~200 | 0 |
| Masked SubBytes | ~2,000 | 0 | 0 |
| TRNG (8 ROs) | ~24 | ~10 | 0 |
| TRNG validator | ~30 | ~30 | 0 |
| Timing randomizer | ~15 | ~15 | 0 |
| UART + Control | ~500 | ~200 | 0 |
| HW monitor | ~200 | ~150 | 0 |
| **Total** | **~7,300** | **~600** | **0** |
| **Utilization (XC7S50)** | **22%** | **1%** | **0%** |
