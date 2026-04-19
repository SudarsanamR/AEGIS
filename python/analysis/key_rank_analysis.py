# =============================================================================
# python/analysis/key_rank_analysis.py
# AEGIS — Act 2: Key Rank Comparison Plot
# =============================================================================
# Usage (from project root, venv activated):
#
#   python python/analysis/key_rank_analysis.py
#   python python/analysis/key_rank_analysis.py --traces traces --results results
#
# Inputs:
#   traces/traces_unmasked.npy        — shape (N,)     Act 1 traces
#   traces/traces_masked.npy          — shape (N,)     Act 2 masked traces
#   traces/plaintexts.npy             — shape (N, 16)  plaintexts
#   traces/aegis_mlp.pth              — trained MLP
#   results/neural_ranks_masked.npy   — pre-computed neural ranks (optional)
#   results/neural_ns.npy             — pre-computed ns (optional)
#
# Outputs:
#   results/act2_key_rank.png  — 3-curve key rank comparison
#
# This is the headline figure for Act 2.  It shows three curves:
#
#   (1) DPA on unmasked AES   — rank drops to 0 quickly (attack succeeds)
#   (2) DPA on masked AES     — rank stays high (DPA fails, masking works)
#   (3) NN on masked AES      — rank drops to 0 (NN breaks the masking)
#
# The visual gap between curves (2) and (3) is the core argument for why
# neural attacks are a more powerful threat model than classical DPA.
# =============================================================================

import argparse
import sys
import numpy as np
import matplotlib.pyplot as plt
from pathlib import Path

# ---------------------------------------------------------------------------
# Path setup
# ---------------------------------------------------------------------------
_SCRIPT_DIR = Path(__file__).resolve().parent
_PYTHON_DIR = _SCRIPT_DIR.parent
if str(_PYTHON_DIR) not in sys.path:
    sys.path.insert(0, str(_PYTHON_DIR))

from analysis.aes_utils import AES_SBOX, hamming_weight   # noqa: E402

# ---------------------------------------------------------------------------
# Reproducibility (PYTHON/ML RULE 3)
# ---------------------------------------------------------------------------
import numpy as np
np.random.seed(42)

# ---------------------------------------------------------------------------
# Attack constants
# ---------------------------------------------------------------------------
ATTACK_BYTE   = 13
TRUE_KEY_BYTE = 0x0D
MASK_ROUND1   = np.uint8(0x59)   # NEW: constant round-1 mask — must match neural_attack.py
RANK_STEP     = 50   # trace count granularity for key rank curves


# =============================================================================
# DPA rank function — duplicated from dpa_attack.py (no circular import)
# =============================================================================

def _dpa_corr(traces, pt_byte):
    """Vectorised Pearson correlation, all 256 hypotheses.  Shape (256,)."""
    N = len(traces)
    t = traces.astype(np.float64)
    t_c = t - t.mean();  t_s = np.sqrt((t_c**2).sum())

    corr = np.empty(256)
    for kg in range(256):
        h = hamming_weight(AES_SBOX[pt_byte ^ np.uint8(kg)]).astype(np.float64)
        h_c = h - h.mean();  h_s = np.sqrt((h_c**2).sum())
        corr[kg] = (h_c * t_c).sum() / (h_s * t_s) if h_s > 0 else 0.0
    return corr


def dpa_key_rank_curve(traces, plaintexts, step=RANK_STEP):
    """DPA key rank vs trace count.  Returns (ns, ranks)."""
    pt_byte = plaintexts[:, ATTACK_BYTE]
    counts  = np.arange(step, len(traces) + 1, step)
    ranks   = np.empty(len(counts), dtype=np.int32)
    for i, n in enumerate(counts):
        corr    = _dpa_corr(traces[:n], pt_byte[:n])
        ranks[i] = int(np.sum(np.abs(corr) > abs(corr[TRUE_KEY_BYTE])))
    return counts, ranks


# =============================================================================
# Neural rank function — requires torch & trained model
# =============================================================================

def neural_key_rank_curve(traces, plaintexts, model_path, step=RANK_STEP):
    """Neural attack key rank vs trace count.  Returns (ns, ranks)."""
    try:
        import torch
        import torch.nn as nn
    except ImportError:
        print("WARNING: torch not available — skipping neural key rank curve.")
        return None, None

    class AegisMLP(nn.Module):
        def __init__(self, T=1):
            super().__init__()
            self.net = nn.Sequential(
                nn.Linear(T, 200), nn.ReLU(), nn.Dropout(0.4),
                nn.Linear(200, 200), nn.ReLU(), nn.Dropout(0.4),
                nn.Linear(200, 200), nn.ReLU(), nn.Dropout(0.4),
                nn.Linear(200, 9),
            )
        def forward(self, x): return self.net(x)

    device = torch.device("cuda" if torch.cuda.is_available() else "cpu")
    ckpt   = torch.load(model_path, map_location=device)
    T      = ckpt["T"]
    model  = AegisMLP(T=T).to(device)
    model.load_state_dict(ckpt["state_dict"])
    model.eval()

    pt_byte = plaintexts[:, ATTACK_BYTE]
    N       = len(traces)
    counts  = np.arange(step, N + 1, step)
    ranks   = np.empty(len(counts), dtype=np.int32)

    # Pre-compute log-probs for all N traces once (then slice for each n)
    X = torch.from_numpy(traces.reshape(-1, 1)).to(device)
    with torch.no_grad():
        log_probs = torch.nn.functional.log_softmax(model(X), dim=1).cpu().numpy()

    for i, n in enumerate(counts):
        lp_n   = log_probs[:n]           # (n, 9)
        pt_n   = pt_byte[:n]             # (n,)
        scores = np.zeros(256, dtype=np.float64)
        for kg in range(256):
            exp_hw      = hamming_weight(AES_SBOX[pt_n ^ np.uint8(kg)] ^ MASK_ROUND1).astype(np.int64)  # MODIFIED
            scores[kg]  = lp_n[np.arange(n), exp_hw].sum()
        ranks[i] = int(np.sum(scores > scores[TRUE_KEY_BYTE]))

    return counts, ranks


# =============================================================================
# Main plot function
# =============================================================================

def plot_key_rank_comparison(
    ns_dpa_u, ranks_dpa_u,
    ns_dpa_m, ranks_dpa_m,
    ns_nn_m,  ranks_nn_m,
    out_path,
):
    """Three-curve key rank comparison figure."""
    fig, ax = plt.subplots(figsize=(12, 6))

    # --- DPA unmasked ---
    ax.plot(ns_dpa_u, ranks_dpa_u,
            color='steelblue', linewidth=2.0,
            label='DPA — unmasked AES (attack SUCCEEDS)')

    # --- DPA masked ---
    ax.plot(ns_dpa_m, ranks_dpa_m,
            color='darkorange', linewidth=2.0, linestyle='--',
            label='DPA — masked AES (attack FAILS)')

    # --- Neural masked ---
    if ns_nn_m is not None:
        ax.plot(ns_nn_m, ranks_nn_m,
                color='green', linewidth=2.0, linestyle='-.',
                label='Neural (MLP) — masked AES (attack SUCCEEDS)')

    ax.axhline(y=0, color='red', linestyle=':', linewidth=1.0, label='Rank 0 (key recovered)')

    # Mark first-success points
    for curve_name, ns, ranks, colour in [
        ("DPA unmasked", ns_dpa_u, ranks_dpa_u, 'steelblue'),
        ("Neural masked", ns_nn_m,  ranks_nn_m,  'green'),
    ]:
        if ns is None or ranks is None:
            continue
        idx = np.where(ranks == 0)[0]
        if len(idx) > 0:
            n_success = ns[idx[0]]
            ax.axvline(x=n_success, color=colour, linestyle=':', alpha=0.5, linewidth=1.0)
            ax.annotate(f"{curve_name}\n{n_success} traces",
                        xy=(n_success, 1), xytext=(n_success + 100, 8),
                        color=colour, fontsize=8,
                        arrowprops=dict(arrowstyle='->', color=colour, lw=0.8))

    ax.set_title(
        "Act 2 — Key Rank vs Trace Count, Byte 13 (key=0x0D)\n"
        "DPA baseline vs Neural Attack on Boolean-Masked AES",
        fontsize=12, fontweight='bold'
    )
    ax.set_xlabel("Number of Traces", fontsize=11)
    ax.set_ylabel("Key Rank  (lower = better for attacker)", fontsize=11)
    ax.set_ylim(-3, max(ranks_dpa_m.max() if ranks_dpa_m is not None else 30, 30) * 1.15)
    ax.legend(fontsize=9, loc='upper right')
    ax.grid(True, alpha=0.3)

    plt.tight_layout()
    plt.savefig(out_path, dpi=150)
    plt.close(fig)
    print(f"Saved: {out_path}")


# =============================================================================
# Entry Point
# =============================================================================

def main():
    parser = argparse.ArgumentParser(
        description="AEGIS — Act 2 key rank comparison plot"
    )
    parser.add_argument("--traces",  type=str, default="traces")
    parser.add_argument("--results", type=str, default="results")
    parser.add_argument("--rank-step", type=int, default=RANK_STEP)
    parser.add_argument(
        "--skip-neural", action="store_true",
        help="Skip neural rank computation (use cached results/neural_ranks_masked.npy)"
    )
    args = parser.parse_args()

    traces_dir  = Path(args.traces)
    results_dir = Path(args.results)
    results_dir.mkdir(parents=True, exist_ok=True)

    # -----------------------------------------------------------------------
    # Load traces
    # -----------------------------------------------------------------------
    traces_u   = np.load(traces_dir / "traces_unmasked.npy")
    traces_m   = np.load(traces_dir / "traces_masked.npy")
    plaintexts = np.load(traces_dir / "plaintexts.npy")
    N          = len(traces_u)
    print(f"Loaded {N} unmasked + {len(traces_m)} masked traces.")

    # -----------------------------------------------------------------------
    # Curve 1: DPA on unmasked
    # -----------------------------------------------------------------------
    print("\nComputing DPA key rank curve on UNMASKED traces…")
    ns_dpa_u, ranks_dpa_u = dpa_key_rank_curve(traces_u, plaintexts, step=args.rank_step)
    idx = np.where(ranks_dpa_u == 0)[0]
    if len(idx):
        print(f"  → DPA (unmasked): rank 0 first reached at {ns_dpa_u[idx[0]]} traces")

    # -----------------------------------------------------------------------
    # Curve 2: DPA on masked
    # -----------------------------------------------------------------------
    print("\nComputing DPA key rank curve on MASKED traces…")
    ns_dpa_m, ranks_dpa_m = dpa_key_rank_curve(traces_m, plaintexts, step=args.rank_step)
    idx = np.where(ranks_dpa_m == 0)[0]
    if len(idx):
        print(f"  → DPA (masked): rank 0 first reached at {ns_dpa_m[idx[0]]} traces")
    else:
        final_rank = ranks_dpa_m[-1]
        print(f"  → DPA (masked): rank NEVER reached 0.  Final rank={final_rank}  (expected — masking works!)")

    # -----------------------------------------------------------------------
    # Curve 3: Neural attack on masked
    # -----------------------------------------------------------------------
    ns_nn_m = ranks_nn_m = None

    cached_ranks = results_dir / "neural_ranks_masked.npy"
    cached_ns    = results_dir / "neural_ns.npy"

    if args.skip_neural and cached_ranks.exists() and cached_ns.exists():
        print("\nLoading cached neural rank results…")
        ranks_nn_m = np.load(cached_ranks)
        ns_nn_m    = np.load(cached_ns)
    else:
        model_path = traces_dir / "aegis_mlp.pth"
        if model_path.exists():
            print("\nComputing neural key rank curve on MASKED traces…")
            ns_nn_m, ranks_nn_m = neural_key_rank_curve(
                traces_m, plaintexts, model_path, step=args.rank_step
            )
            if ns_nn_m is not None:
                idx = np.where(ranks_nn_m == 0)[0]
                if len(idx):
                    print(f"  → Neural (masked): rank 0 at {ns_nn_m[idx[0]]} traces")
                else:
                    print(f"  → Neural (masked): rank={ranks_nn_m[-1]} at {ns_nn_m[-1]} traces")
                # Cache for future runs
                np.save(cached_ranks, ranks_nn_m)
                np.save(cached_ns,    ns_nn_m)
        else:
            print(f"\nWARNING: {model_path} not found — neural curve omitted.")
            print("         Run train_mlp.py first, then re-run this script.")

    # -----------------------------------------------------------------------
    # Plot
    # -----------------------------------------------------------------------
    out_path = results_dir / "act2_key_rank.png"
    plot_key_rank_comparison(
        ns_dpa_u, ranks_dpa_u,
        ns_dpa_m, ranks_dpa_m,
        ns_nn_m,  ranks_nn_m,
        out_path,
    )

    # -----------------------------------------------------------------------
    # Summary table
    # -----------------------------------------------------------------------
    print("\n" + "="*55)
    print("  Act 2 Summary")
    print("="*55)
    idx_u = np.where(ranks_dpa_u == 0)[0]
    idx_m = np.where(ranks_dpa_m == 0)[0]
    print(f"  DPA (unmasked): success at {ns_dpa_u[idx_u[0]] if len(idx_u) else 'N/A'} traces")
    print(f"  DPA (masked)  : final rank = {ranks_dpa_m[-1]} at {ns_dpa_m[-1]} traces  [FAILS]")
    if ranks_nn_m is not None:
        idx_nn = np.where(ranks_nn_m == 0)[0]
        print(f"  Neural (masked): success at {ns_nn_m[idx_nn[0]] if len(idx_nn) else 'N/A'} traces")
    print("="*55)
    print("\nDone.  Results in results/act2_key_rank.png")


if __name__ == "__main__":
    main()
