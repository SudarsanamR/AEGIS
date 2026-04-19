# =============================================================================
# python/demo.py
# AEGIS — Unified Demo Script (Step 6.1)
# =============================================================================
# Usage (from project root, venv activated):
#
#   python python/demo.py --design vulnerable --attack dpa
#   python python/demo.py --design masked    --attack neural
#   python python/demo.py --design hardened  --attack both
#   python python/demo.py --design all       --attack both     ← full demo
#
# This script orchestrates trace simulation, attacks, and plotting in a
# single command — ideal for live hackathon demonstrations.
#
# Dependencies:
#   All trace files (plaintexts.npy) must exist in traces/.
#   The trained MLP (aegis_mlp.pth) must exist for neural attacks.
#   Run collect_traces.py --mode simulate and train_mlp.py first.
# =============================================================================

import argparse
import sys
import numpy as np
import matplotlib
matplotlib.use('Agg')  # non-interactive backend for headless demo
import matplotlib.pyplot as plt
from pathlib import Path

# ---------------------------------------------------------------------------
# Path setup
# ---------------------------------------------------------------------------
_SCRIPT_DIR = Path(__file__).resolve().parent      # python/
_PROJECT    = _SCRIPT_DIR.parent                   # aegis/
sys.path.insert(0, str(_SCRIPT_DIR))

from analysis.aes_utils import AES_SBOX, hamming_weight, hw_model  # noqa: E402

# ---------------------------------------------------------------------------
# Reproducibility
# ---------------------------------------------------------------------------
np.random.seed(42)

# ---------------------------------------------------------------------------
# Constants
# ---------------------------------------------------------------------------
ATTACK_BYTE   = 13
TRUE_KEY_BYTE = 0x0D
MASK_ROUND1   = np.uint8(0x59)
TRACES_DIR    = _PROJECT / "traces"
RESULTS_DIR   = _PROJECT / "results" / "demo"


# =============================================================================
# DPA core (inlined for standalone demo)
# =============================================================================
def run_dpa(traces, pt_byte):
    t = traces.astype(np.float64)
    t_cent = t - t.mean()
    t_std = np.sqrt((t_cent**2).sum())
    corr = np.empty(256, dtype=np.float64)
    for kg in range(256):
        h = hw_model(pt_byte, kg).astype(np.float64)
        h_cent = h - h.mean()
        h_std = np.sqrt((h_cent**2).sum())
        corr[kg] = (h_cent * t_cent).sum() / (h_std * t_std) if h_std > 0 and t_std > 0 else 0.0
    return corr


# =============================================================================
# Neural attack core
# =============================================================================
def run_neural(traces, plaintexts, model_path, mask=MASK_ROUND1):
    import torch
    import torch.nn as nn

    class AegisMLP(nn.Module):
        def __init__(self, T=1):
            super().__init__()
            self.net = nn.Sequential(
                nn.Linear(T, 200), nn.ReLU(), nn.Dropout(0.4),
                nn.Linear(200, 200), nn.ReLU(), nn.Dropout(0.4),
                nn.Linear(200, 200), nn.ReLU(), nn.Dropout(0.4),
                nn.Linear(200, 9),
            )
        def forward(self, x):
            return self.net(x)

    device = torch.device("cuda" if torch.cuda.is_available() else "cpu")
    ckpt = torch.load(model_path, map_location=device, weights_only=False)
    model = AegisMLP(T=ckpt["T"]).to(device)
    model.load_state_dict(ckpt["state_dict"])
    model.eval()

    N = len(traces)
    pt_byte = plaintexts[:, ATTACK_BYTE]
    X = torch.from_numpy(traces.reshape(-1, 1)).to(device)

    log_probs_list = []
    with torch.no_grad():
        for i in range(0, N, 1024):
            logits = model(X[i:i+1024])
            log_probs_list.append(torch.nn.functional.log_softmax(logits, dim=1).cpu().numpy())
    log_probs = np.concatenate(log_probs_list, axis=0)

    scores = np.zeros(256, dtype=np.float64)
    for kg in range(256):
        expected_hw = hamming_weight(AES_SBOX[pt_byte ^ np.uint8(kg)] ^ mask).astype(np.int64)
        scores[kg] = log_probs[np.arange(N), expected_hw].sum()
    return scores


# =============================================================================
# Plot helper
# =============================================================================
def plot_attack(values, title, ylabel, out_path, is_corr=True):
    fig, ax = plt.subplots(figsize=(14, 5))
    display = np.abs(values) if is_corr else values
    colours = ['red' if kg == TRUE_KEY_BYTE else 'steelblue' for kg in range(256)]
    ax.bar(range(256), display, color=colours, width=1.0, linewidth=0)

    best = int(np.argmax(display)) if is_corr else int(np.argmax(values))
    rank = int(np.sum(display > display[TRUE_KEY_BYTE])) if is_corr else int(np.sum(values > values[TRUE_KEY_BYTE]))

    ax.set_title(f"{title}\nBest=0x{best:02X}, Correct=0x{TRUE_KEY_BYTE:02X}, Rank={rank}",
                 fontsize=12, fontweight='bold')
    ax.set_xlabel("Key Guess (0x00–0xFF)")
    ax.set_ylabel(ylabel)
    ax.set_xlim(-1, 256)
    ax.legend(handles=[
        plt.Rectangle((0,0),1,1, fc='red',       label=f'Correct key (0x{TRUE_KEY_BYTE:02X})'),
        plt.Rectangle((0,0),1,1, fc='steelblue',  label='Wrong guess'),
    ], loc='upper right', fontsize=9)
    plt.tight_layout()
    plt.savefig(out_path, dpi=150)
    plt.close(fig)
    return rank


# =============================================================================
# Design runner
# =============================================================================
def demo_design(design_name, trace_file, attacks, plaintexts, results_dir, model_path):
    print(f"\n{'='*60}")
    print(f"  AEGIS Demo — {design_name.upper()} Design")
    print(f"{'='*60}")

    traces = np.load(trace_file)
    pt_byte = plaintexts[:, ATTACK_BYTE]
    N = len(traces)
    print(f"  Loaded {N} traces from {trace_file.name}")

    if 'dpa' in attacks:
        print(f"\n  Running DPA attack…")
        corr = run_dpa(traces, pt_byte)
        out = results_dir / f"{design_name}_dpa.png"
        rank = plot_attack(corr, f"DPA — {design_name.title()}", "|Pearson r|", out, is_corr=True)
        status = "✓ BROKEN" if rank == 0 else f"✗ SECURE (rank={rank})"
        print(f"    |r(correct)| = {abs(corr[TRUE_KEY_BYTE]):.4f}")
        print(f"    Result: {status}")
        print(f"    Plot: {out}")

    if 'neural' in attacks:
        if not model_path.exists():
            print(f"\n  Skipping neural attack — {model_path} not found")
            return
        print(f"\n  Running Neural attack…")
        mask = MASK_ROUND1 if design_name != 'vulnerable' else np.uint8(0x00)
        scores = run_neural(traces, plaintexts, model_path, mask=MASK_ROUND1)
        out = results_dir / f"{design_name}_neural.png"
        rank = plot_attack(scores, f"Neural — {design_name.title()}", "Log-Likelihood", out, is_corr=False)
        status = "✓ BROKEN" if rank == 0 else f"✗ SECURE (rank={rank})"
        print(f"    Best guess: 0x{np.argmax(scores):02X}")
        print(f"    Result: {status}")
        print(f"    Plot: {out}")


# =============================================================================
# Entry point
# =============================================================================
def main():
    parser = argparse.ArgumentParser(
        description="AEGIS — Unified Demo: simulate + attack + plot"
    )
    parser.add_argument("--design", type=str, default="all",
                        choices=["vulnerable", "masked", "hardened", "all"],
                        help="Which design to demonstrate")
    parser.add_argument("--attack", type=str, default="both",
                        choices=["dpa", "neural", "both"],
                        help="Which attack to run")
    parser.add_argument("--traces",  type=str, default="traces")
    parser.add_argument("--results", type=str, default="results/demo")
    args = parser.parse_args()

    traces_dir  = Path(args.traces)
    results_dir = Path(args.results)
    results_dir.mkdir(parents=True, exist_ok=True)
    model_path  = traces_dir / "aegis_mlp.pth"

    attacks = ['dpa', 'neural'] if args.attack == 'both' else [args.attack]

    # Load shared plaintexts
    pts_path = traces_dir / "plaintexts.npy"
    if not pts_path.exists():
        sys.exit(f"ERROR: {pts_path} not found.\nRun: python python/trace_collection/collect_traces.py --mode simulate")
    plaintexts = np.load(pts_path)

    print("╔══════════════════════════════════════════════════════════╗")
    print("║          AEGIS — Side-Channel Attack & Defense          ║")
    print("║     Adaptive FPGA-Based Defense with Neural Resilience  ║")
    print("╚══════════════════════════════════════════════════════════╝")

    designs = {
        'vulnerable': traces_dir / "traces_unmasked.npy",
        'masked':     traces_dir / "traces_masked.npy",
        'hardened':   traces_dir / "traces_hardened.npy",
    }

    if args.design == 'all':
        run_designs = ['vulnerable', 'masked', 'hardened']
    else:
        run_designs = [args.design]

    for d in run_designs:
        trace_file = designs[d]
        if not trace_file.exists():
            print(f"\n  WARNING: {trace_file} not found — skipping {d}")
            print(f"  Generate with: python python/trace_collection/simulate_{d if d != 'vulnerable' else 'collect_traces --mode simulate'}.py")
            continue
        demo_design(d, trace_file, attacks, plaintexts, results_dir, model_path)

    print(f"\n{'='*60}")
    print(f"  Demo complete. All plots saved to {results_dir}/")
    print(f"{'='*60}")


if __name__ == "__main__":
    main()
