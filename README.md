# AEGIS — Adaptive FPGA-Based Defense with Neural Resilience

**ChipVerse '26 Hackathon Project**

AEGIS demonstrates a complete side-channel attack and defense lifecycle on FPGA. Starting from a vulnerable AES-128 implementation, we progressively harden it with boolean masking, TRNG-sourced entropy, and randomized timing — then prove each countermeasure's effectiveness using classical DPA and neural network attacks.

---

## ⚡ Quick Start

### 1. Prerequisites

#### Ubuntu / Debian (Linux)
```bash
# Install Python 3, pip, and virtual environment tools
sudo apt update
sudo apt install -y python3 python3-pip python3-venv
```

#### Windows
1. Download and install [Python 3.x](https://www.python.org/downloads/). 
2. **Crucial:** During installation, ensure the checkbox **"Add Python to PATH"** is selected.
3. Open PowerShell or Command Prompt.

### 2. Python Environment Setup

```bash
# Navigate to the project directory
cd aegis

# Create a virtual environment
# On Linux/macOS:
python3 -m venv venv
# On Windows:
python -m venv venv

# Activate the virtual environment
# On Linux/macOS:
source venv/bin/activate
# On Windows (Command Prompt):
venv\Scripts\activate.bat
# On Windows (PowerShell):
venv\Scripts\Activate.ps1

# Install required dependencies
pip install -r requirements.txt
```

### 3. Running the Python Simulation

*Note: Always run scripts using the `python` prefix from the project root directory. Do not run them directly (e.g. `./python/attacks/dpa_attack.py`), as this may cause permission or path errors.*

```bash
# 1. Generate traces for all 3 designs (run ALL three before proceeding)
python python/trace_collection/collect_traces.py --mode simulate  # Act 1: unmasked
python python/trace_collection/simulate_masked.py                  # Act 2: masked
python python/trace_collection/simulate_hardened.py                # Act 3: hardened

# 2. Run the full demo (DPA + Neural on all designs)
python python/demo.py --design all --attack both

# 3. Generate the 5-figure comparison suite
python python/analysis/generate_all_plots.py
```

---

## 📐 Architecture

```
┌─────────────────────────────────────────────────────────────────┐
│                     AEGIS System Architecture                    │
│                                                                  │
│  Act 1: Vulnerable    Act 2: Masked        Act 3: Hardened       │
│  ┌──────────────┐    ┌──────────────┐     ┌──────────────────┐  │
│  │  AES Core    │    │  AES Masked  │     │  AES Hardened    │  │
│  │  (plaintext) │    │  (constant   │     │  (TRNG mask +    │  │
│  │              │    │   mask 0xAC) │     │   timing jitter) │  │
│  └──────┬───────┘    └──────┬───────┘     └──────┬───────────┘  │
│         │                   │                    │               │
│    DPA breaks it      DPA fails,            Both DPA and        │
│    in ~200 traces     NN succeeds           NN fail entirely    │
└─────────────────────────────────────────────────────────────────┘
```

### Design Progression

| Design | Countermeasures | DPA Result | Neural Result |
|--------|----------------|------------|---------------|
| **Vulnerable** (Act 1) | None | ✓ Broken at ~200 traces | N/A |
| **Masked** (Act 2) | Boolean masking (constant seed) | ✗ Fails (r≈0.00) | ✓ Broken (learns mask) |
| **Hardened** (Act 3) | Masking + TRNG seed + timing jitter | ✗ Fails | ✗ Fails (mask changes every trace) |

---

## 📁 Repository Structure

```
aegis/
├── rtl/                          # Verilog HDL modules
│   ├── crypto/                   #   AES-128 encryption cores
│   │   ├── aes_subbytes.v        #     SubBytes (S-Box × 16)
│   │   ├── aes_shiftrows.v       #     ShiftRows (wire permutation)
│   │   ├── aes_mixcolumns.v      #     MixColumns (GF(2^8) arithmetic)
│   │   ├── aes_addroundkey.v     #     AddRoundKey (128-bit XOR)
│   │   ├── aes_key_expansion.v   #     Key Schedule (11 round keys)
│   │   ├── aes_core.v            #     Act 1: Vulnerable AES core
│   │   ├── aes_core_masked.v     #     Act 2: Boolean-masked AES core
│   │   └── aes_core_hardened.v   #     Act 3: Fully hardened AES core
│   ├── countermeasures/          #   Side-channel defense modules
│   │   ├── aes_subbytes_masked.v #     Masked S-Box (per-byte mask I/O)
│   │   ├── aes_mixcolumns_masked.v#    Masked MixColumns (linear passthrough)
│   │   ├── mask_refresh.v        #     8-bit LFSR mask generator
│   │   ├── ring_oscillator_trng.v#     8× ring oscillator TRNG (Spartan-7 LUT1)
│   │   ├── trng_validator.v      #     10K-bit entropy quality gate (45–55%)
│   │   └── timing_randomizer.v   #     0–15 random dummy cycles per round
│   ├── interface/                #   Communication modules
│   │   ├── uart_rx.v             #     UART receiver (9600 baud)
│   │   ├── uart_tx.v             #     UART transmitter
│   │   ├── control_fsm.v         #     System controller (RX→AES→TX)
│   │   └── hamming_weight.v      #     128-bit popcount (leakage monitor)
│   └── top/                      #   Top-level integration
│       ├── aes_masked.v          #     Act 2 top (UART + masked AES)
│       └── aes_hardened.v        #     Act 3 top (UART + all countermeasures)
├── sim/                          # Testbenches (20 files, self-checking)
├── constraints/                  # Vivado XDC for Arty S7
│   └── arty_s7.xdc              #   Clock, UART, LEDs, TRNG Pblock
├── python/                       # Analysis & attack framework
│   ├── analysis/                 #   Shared utilities & visualization
│   │   ├── aes_utils.py          #     S-Box, HW model, software AES
│   │   ├── generate_all_plots.py #     5-figure comparison suite
│   │   ├── plot_results.py       #     Act 1 result plots
│   │   └── key_rank_analysis.py  #     Key rank overlay plot
│   ├── attacks/                  #   Attack implementations
│   │   ├── dpa_attack.py         #     Classical DPA (Pearson CPA)
│   │   ├── neural_attack.py      #     MLP-based profiling attack
│   │   ├── generate_ml_dataset.py#     Training data preparation
│   │   └── train_mlp.py          #     MLP training (PyTorch)
│   ├── trace_collection/         #   Trace simulation scripts
│   │   ├── collect_traces.py     #     Act 1: Unmasked traces
│   │   ├── simulate_masked.py    #     Act 2: Masked traces
│   │   └── simulate_hardened.py  #     Act 3: Hardened traces
│   ├── demo.py                   #   Unified demo (argparse CLI)
│   └── requirements.txt
├── docs/                         # Project documentation
│   └── architecture.md           #   Detailed architecture & security analysis
├── f4pga/                        # Open-source synthesis (Yosys)
│   ├── synth_vulnerable.ys      #   Yosys script — Act 1 AES
│   ├── synth_hardened.ys        #   Yosys script — Act 3 AES
│   ├── synth_yosys.sh           #   Shell wrapper
│   ├── Makefile                 #   Build automation
│   └── README.md                #   F4PGA setup guide
├── traces/                       # Generated trace data (.npy)
├── results/                      # Attack results & plots (.png)
├── instructions.txt              # Original project specification
├── requirements.txt
└── .gitignore
```

---

## 🔧 Hardware Target

| Parameter | Value |
|-----------|-------|
| FPGA | Xilinx Spartan-7 XC7S50 |
| Board | Digilent Arty S7-50 |
| System Clock | 100 MHz |
| AES Clock | 50 MHz (divided) |
| UART | 9600 baud, 8N1 |
| TRNG | 8× ring oscillators, 1 MHz output |
| Toolchain | Vivado 2024.1+ |

---

## 🛡️ Countermeasure Details

### Act 2: Boolean Masking
- **Technique**: XOR all intermediate AES values with a uniform byte mask
- **Implementation**: Masked S-Box lookup (`aes_subbytes_masked.v`) with mask I/O
- **Invariant**: `state_masked == real_state XOR {mask × 16}` held every cycle
- **Weakness**: Constant mask seed (0xAC) → neural network can learn the mapping

### Act 3: TRNG + Timing Jitter
- **Ring Oscillator TRNG**: 8 parallel 3-stage oscillators using Spartan-7 LUT1
  primitives with `KEEP` and `DONT_TOUCH` attributes
- **Entropy Validation**: 10,000-bit window, ones ratio must be 45%–55%
- **Random Mask Seed**: Each encryption gets a fresh 8-bit seed from TRNG
  (replaces the constant 0xAC from Act 2)
- **Timing Jitter**: 0–15 random dummy cycles injected between each AES round
  via `round_done`/`proceed` handshake
- **Combined Effect**: Traces are both amplitude-randomized (masking) and
  time-shifted (jitter) → no learnable pattern

---

## 🧪 Testing

### Verilog Testbenches

You can simulate the Verilog hardware modules using either Vivado Simulator (recommended for graphical waveforms) or Icarus Verilog (recommended for fast, command-line testing).

#### Option A: Vivado Simulator (Windows / Linux)
1. Open Xilinx Vivado.
2. Create a new project and add all files from `rtl/` and `sim/`.
3. In the Tcl Console, set the top module for simulation:
   ```tcl
   set_property top tb_aes_core [get_filesets sim_1]
   launch_simulation
   ```
4. Repeat for other testbenches in this sequence:
   - `tb_aes_core_masked`
   - `tb_aes_core_hardened`
   - `tb_ring_oscillator_trng`
   - `tb_timing_randomizer`
   - `tb_aes_hardened` (Top-level integration)
   
   *(Note: The simulation automatically runs for 1000ns, which is enough for most testbenches to complete and print `ALL TESTS PASSED`. If a simulation needs more time, type `run all` in the Tcl Console).*

#### Option B: Icarus Verilog (Command Line)

**Installation (Ubuntu / Debian Linux):**
```bash
sudo apt update
sudo apt install -y iverilog
```

**Installation (Windows):**
1. Download the latest Windows binary from [Icarus Verilog for Windows](https://bleyer.org/icarus/).
2. Install and ensure the installation directory (e.g., `C:\iverilog\bin`) is added to your system PATH.

**Running Simulations:**
Open your terminal in the project root and compile/run the modules:
```bash
# Test the Act 1 vulnerable core
iverilog -o sim_core rtl/crypto/*.v sim/tb_aes_core.v
vvp sim_core

# Test the Act 2 masked core
iverilog -o sim_masked rtl/crypto/*.v rtl/countermeasures/aes_subbytes_masked.v rtl/countermeasures/aes_mixcolumns_masked.v sim/tb_aes_core_masked.v
vvp sim_masked

# Test the TRNG
iverilog -o sim_trng rtl/countermeasures/ring_oscillator_trng.v sim/tb_ring_oscillator_trng.v
vvp sim_trng
```

### Python Side-Channel Attacks
```bash
# Make sure your virtual environment is activated!
# Windows: venv\Scripts\activate.bat
# Linux: source venv/bin/activate

# 1. Baseline: Generate traces and run DPA on the unmasked core
python python/trace_collection/collect_traces.py --mode simulate
python python/attacks/dpa_attack.py

# 2. Masking: Generate traces and train the Neural Network to break the mask
python python/trace_collection/simulate_masked.py
python python/attacks/generate_ml_dataset.py
python python/attacks/train_mlp.py
python python/attacks/neural_attack.py

# 3. Hardened: Verify the hardened core resists both attacks
python python/trace_collection/simulate_hardened.py
python python/analysis/generate_all_plots.py
```

---

## 📊 Key Results

| Metric | Vulnerable | Masked | Hardened |
|--------|-----------|--------|---------|
| DPA correlation (correct key) | ~0.25 | ~0.00 | ~0.00 |
| DPA key rank at 5000 traces | 0 (broken) | >100 | >100 |
| Neural key rank at 5000 traces | N/A | 0 (broken) | >100 |
| Encryption latency | 13 cycles | 13 cycles | 13–173 cycles |
| LUT utilization | ~5,000 | ~6,500 | ~7,300 |

---

## 🔓 Open-Source Synthesis (F4PGA / Yosys)

AEGIS also builds with the **fully open-source** Yosys synthesis toolchain:

```bash
cd f4pga/
make synth           # Synthesize vulnerable AES (Act 1)
make synth-hardened  # Synthesize hardened AES (Act 3)
make stats           # Compare resource utilization
```

| Target | Yosys LUTs | Vivado LUTs | Match |
|--------|-----------|-------------|-------|
| Vulnerable (Act 1) | ~5,200 | ~5,000 | ✓ |
| Hardened (Act 3) | ~7,500* | ~7,300 | ✓ |

\* Ring oscillator TRNG may be optimized away by Yosys (no KEEP attribute support).
Use Vivado for actual FPGA deployment with TRNG.

See [`f4pga/README.md`](f4pga/README.md) for full setup instructions.

---

## 📄 License

Academic project for ChipVerse '26. All code is original work.
