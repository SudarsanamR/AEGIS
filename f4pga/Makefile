# =============================================================================
# f4pga/Makefile
# AEGIS — F4PGA/Yosys Open-Source Synthesis
# =============================================================================
#
# Usage:
#   make synth          — Synthesize vulnerable AES (Act 1)
#   make synth-hardened — Synthesize hardened AES (Act 3)
#   make clean          — Remove generated files
#   make stats          — Show resource utilization from last synthesis
#
# Requirements:
#   Yosys must be in PATH. Install:
#     Ubuntu:  sudo apt install yosys
#     Conda:   conda install -c conda-forge yosys
#     Windows: choco install yosys (or use WSL)
# =============================================================================

YOSYS    ?= yosys
OUT_DIR  := output

.PHONY: all synth synth-hardened clean stats help

all: synth

help:
	@echo "AEGIS F4PGA/Yosys Synthesis"
	@echo ""
	@echo "Targets:"
	@echo "  synth          — Synthesize vulnerable AES (Act 1) with Yosys"
	@echo "  synth-hardened — Synthesize hardened AES (Act 3) with Yosys"
	@echo "  stats          — Print resource utilization from last synthesis"
	@echo "  clean          — Remove generated output files"

# ── Vulnerable AES (Act 1) ──────────────────────────────────────────────────
synth: $(OUT_DIR)/synth_vulnerable.json

$(OUT_DIR)/synth_vulnerable.json: synth_vulnerable.ys \
    ../rtl/crypto/*.v ../rtl/interface/*.v ../rtl/top/aes_vulnerable.v
	@mkdir -p $(OUT_DIR)
	@echo "╔══════════════════════════════════════════════╗"
	@echo "║  Yosys Synthesis: Vulnerable AES (Act 1)    ║"
	@echo "╚══════════════════════════════════════════════╝"
	$(YOSYS) -s synth_vulnerable.ys -l $(OUT_DIR)/synth_vulnerable.log
	@echo ""
	@echo "Done. Netlist: $(OUT_DIR)/synth_vulnerable.json"

# ── Hardened AES (Act 3) ────────────────────────────────────────────────────
synth-hardened: $(OUT_DIR)/synth_hardened.json

$(OUT_DIR)/synth_hardened.json: synth_hardened.ys \
    ../rtl/crypto/*.v ../rtl/countermeasures/*.v ../rtl/interface/*.v \
    ../rtl/top/aes_hardened.v
	@mkdir -p $(OUT_DIR)
	@echo "╔══════════════════════════════════════════════╗"
	@echo "║  Yosys Synthesis: Hardened AES (Act 3)      ║"
	@echo "╚══════════════════════════════════════════════╝"
	$(YOSYS) -s synth_hardened.ys -l $(OUT_DIR)/synth_hardened.log
	@echo ""
	@echo "Done. Netlist: $(OUT_DIR)/synth_hardened.json"

# ── Statistics ──────────────────────────────────────────────────────────────
stats:
	@echo "=== Vulnerable AES (Act 1) ==="
	@grep -A 20 "Printing statistics" $(OUT_DIR)/synth_vulnerable.log 2>/dev/null || echo "  (not yet synthesized)"
	@echo ""
	@echo "=== Hardened AES (Act 3) ==="
	@grep -A 20 "Printing statistics" $(OUT_DIR)/synth_hardened.log 2>/dev/null || echo "  (not yet synthesized)"

# ── Clean ───────────────────────────────────────────────────────────────────
clean:
	rm -rf $(OUT_DIR)
	@echo "Cleaned $(OUT_DIR)/"
