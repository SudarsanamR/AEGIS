# F4PGA / Yosys Open-Source Synthesis — Setup Guide

## Overview

This directory contains scripts to synthesize the AEGIS AES designs using
**Yosys** (open-source synthesis) as part of the **F4PGA** open-source
FPGA toolchain. This demonstrates that the AEGIS project builds with
free/open-source tools — not just proprietary Vivado.

## What's Included

| File | Purpose |
|------|---------|
| `synth_vulnerable.ys` | Yosys script — synthesize Act 1 vulnerable AES |
| `synth_hardened.ys` | Yosys script — synthesize Act 3 hardened AES |
| `synth_yosys.sh` | Shell wrapper with error checking |
| `Makefile` | Build automation (`make synth`, `make synth-hardened`) |
| `README.md` | This file |

## Quick Start

### 1. Install Yosys

```bash
# Ubuntu / Debian (recommended)
sudo apt update
sudo apt install -y yosys

# Conda (any OS)
conda install -c conda-forge yosys

# macOS (via Homebrew)
brew install yosys

# Windows (via Chocolatey)
choco install yosys
```

### 2. Run Synthesis

```bash
cd f4pga/

# Synthesize vulnerable AES (Act 1)
make synth

# Synthesize hardened AES (Act 3)
make synth-hardened

# View resource utilization
make stats

# Or run directly with yosys:
yosys -s synth_vulnerable.ys
```

### 3. Output Files

After synthesis, `output/` contains:

| File | Description |
|------|-------------|
| `synth_vulnerable.json` | JSON netlist for Act 1 (for nextpnr/VPR) |
| `synth_hardened.json` | JSON netlist for Act 3 |
| `synth_vulnerable.log` | Full Yosys synthesis log |
| `synth_hardened.log` | Full Yosys synthesis log |

## Full F4PGA Flow (Optional)

For complete bitstream generation (synthesis → P&R → bitstream), you need
the full F4PGA toolchain:

### Install F4PGA

```bash
# Install Conda (Miniconda) on Ubuntu first if needed
wget https://repo.anaconda.com/miniconda/Miniconda3-latest-Linux-x86_64.sh
bash Miniconda3-latest-Linux-x86_64.sh
source ~/.bashrc   # or open a new terminal

# Install via Conda (recommended)
conda create -n f4pga
conda activate f4pga
conda install -c conda-forge f4pga

# Download Xilinx 7-series architecture definitions (~3 GB)
# These contain the routing database from Project X-Ray
f4pga install-toolchain --fpga-family xc7
```

### Run Complete Flow

```bash
# Place and route with VPR (after synthesis)
vpr arch.xml synth_vulnerable.json --sdc ../constraints/arty_s7.xdc

# Or use nextpnr-xilinx
nextpnr-xilinx --chipdb xc7s50.bin \
               --netlist output/synth_vulnerable.json \
               --xdc ../constraints/arty_s7.xdc \
               --fasm output/vulnerable.fasm

# Generate bitstream from FASM
fasm2frames --part xc7s50csga324-1 output/vulnerable.fasm output/vulnerable.frames
xc7frames2bit output/vulnerable.frames output/vulnerable.bit
```

## Vivado vs Yosys Comparison

| Feature | Vivado | Yosys |
|---------|--------|-------|
| License | Proprietary (free for Spartan-7) | MIT (fully open) |
| Synthesis | ✓ Full support | ✓ `synth_xilinx` |
| P&R | ✓ Built-in | Via nextpnr/VPR |
| Bitstream | ✓ Built-in | Via Project X-Ray |
| KEEP/DONT_TOUCH | ✓ Native | ✗ Not supported |
| Ring Oscillator TRNG | ✓ Works (with attributes) | ⚠ May optimize away |
| Timing Analysis | ✓ Full STA | ⚠ Limited |
| Resource Estimates | ✓ Accurate | ✓ Close to Vivado |

### Key Limitation

The ring oscillator TRNG (`ring_oscillator_trng.v`) uses Vivado-specific
synthesis attributes (`KEEP`, `DONT_TOUCH`) to prevent the combinational
feedback loops from being optimized away. Yosys does not support these
attributes, so it may remove or simplify the ring oscillators.

**This is expected.** The Yosys synthesis demonstrates that:
1. All other modules synthesize correctly with open-source tools
2. Resource utilization is comparable to Vivado
3. The design is not locked to a proprietary toolchain

For actual FPGA deployment with the TRNG, use Vivado.
