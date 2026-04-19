#!/usr/bin/env bash
# =============================================================================
# f4pga/synth_yosys.sh
# AEGIS — Step 6.3: F4PGA/Yosys Open-Source Synthesis (Bonus)
# =============================================================================
#
# Purpose:
#   Synthesize the vulnerable AES design (aes_vulnerable.v / aes_core.v)
#   using the open-source Yosys synthesis tool, demonstrating that the
#   AEGIS project builds with FOSS tools — not just proprietary Vivado.
#
# Requirements:
#   - Yosys (https://github.com/YosysHQ/yosys) — install via:
#       sudo apt install yosys           (Ubuntu/Debian)
#       conda install -c conda-forge yosys  (Conda)
#       choco install yosys              (Windows/Chocolatey)
#
#   - For full F4PGA flow (P&R + bitstream), also install:
#       f4pga (pip install f4pga)
#       VPR or nextpnr-xilinx
#       f4pga-arch-defs for xc7s50
#
# Usage (from project root):
#   bash f4pga/synth_yosys.sh
#   # or directly:
#   yosys -s f4pga/synth_vulnerable.ys
#
# What this script does:
#   1. Runs Yosys synthesis on the Act 1 vulnerable AES design
#   2. Generates post-synthesis statistics (LUT count, FF count)
#   3. Writes a JSON netlist for downstream P&R (if F4PGA is installed)
#   4. Generates a Graphviz dot file of the top-level module hierarchy
#
# Output files (in f4pga/output/):
#   synth_vulnerable.json   — JSON netlist (for VPR/nextpnr)
#   synth_vulnerable.log    — full Yosys log
#   hierarchy.dot           — module hierarchy visualization
#
# NOTE: This script only performs SYNTHESIS (logic mapping).
#   Full bitstream generation (P&R + bitstream) requires the complete
#   F4PGA toolchain with Xilinx 7-series architecture definitions,
#   which are ~3GB and not included in this repo.
#   See: https://f4pga.readthedocs.io/en/latest/getting-started.html
# =============================================================================

set -e

SCRIPT_DIR="$(cd "$(dirname "$0")" && pwd)"
PROJECT_ROOT="$(dirname "$SCRIPT_DIR")"
OUTPUT_DIR="$SCRIPT_DIR/output"

mkdir -p "$OUTPUT_DIR"

echo "╔══════════════════════════════════════════════════════════╗"
echo "║     AEGIS — F4PGA/Yosys Open-Source Synthesis           ║"
echo "║     Target: Vulnerable AES (Act 1) for XC7S50          ║"
echo "╚══════════════════════════════════════════════════════════╝"
echo ""

# Check for Yosys
if ! command -v yosys &> /dev/null; then
    echo "ERROR: yosys not found in PATH."
    echo "Install with: sudo apt install yosys (Linux)"
    echo "              conda install -c conda-forge yosys (Conda)"
    echo "              choco install yosys (Windows)"
    exit 1
fi

echo "Yosys version: $(yosys -V 2>&1 | head -1)"
echo ""

# Run Yosys with the synthesis script
echo "Running synthesis..."
yosys -s "$SCRIPT_DIR/synth_vulnerable.ys" \
      -l "$OUTPUT_DIR/synth_vulnerable.log" \
      2>&1 | tail -30

echo ""
echo "Synthesis complete."
echo "  Netlist: $OUTPUT_DIR/synth_vulnerable.json"
echo "  Log:     $OUTPUT_DIR/synth_vulnerable.log"
echo "  Dot:     $OUTPUT_DIR/hierarchy.dot"
echo ""
echo "To view hierarchy: dot -Tpng $OUTPUT_DIR/hierarchy.dot -o $OUTPUT_DIR/hierarchy.png"
