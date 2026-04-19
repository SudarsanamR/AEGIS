# =============================================================================
# python/analysis/plot_results.py
# AEGIS — Act 1 Raw Trace Visualisation
# =============================================================================
# Usage (from project root, venv activated):
#
#   python python/analysis/plot_results.py
#   python python/analysis/plot_results.py --traces traces --results results
#
# Inputs  (from traces/ by default):
#   traces_unmasked.npy  — shape (N,)     float32  HW leakage per trace
#   plaintexts.npy       — shape (N, 16)  uint8    plaintext bytes
#
# Outputs (to results/ by default):
#   results/act1_raw_traces.png  — 2-panel trace visualisation
#
# WHY this plot:
#   Judges and reviewers need an intuitive picture of the raw leakage data
#   before seeing the DPA result.  This figure answers: "what does the power
#   signal actually look like, and why is it exploitable?"
#
#   Panel 1 — Scatter of first 100 trace values vs trace index.
#     Shows: the signal is noisy (not a clean step function), but the
#     variation is systematic — traces cluster around their true HW class.
#
#   Panel 2 — Histogram of all 5000 values, coloured per HW class (0–8).
#     Shows: the 9 HW classes produce 9 overlapping Gaussian clusters.
#     DPA exploits this overlap — the correct key hypothesis de-mixes them.
# =============================================================================

import argparse
import sys
import numpy as np
import matplotlib.pyplot as plt
import matplotlib.cm as cm
from pathlib import Path

# ---------------------------------------------------------------------------
# Path setup
# ---------------------------------------------------------------------------
_SCRIPT_DIR = Path(__file__).resolve().parent        # python/analysis/
_PYTHON_DIR = _SCRIPT_DIR.parent                     # python/
if str(_PYTHON_DIR) not in sys.path:
    sys.path.insert(0, str(_PYTHON_DIR))

from analysis.aes_utils import AES_SBOX, hamming_weight   # noqa: E402

# ---------------------------------------------------------------------------
# Reproducibility (PYTHON/ML RULE 3)
# ---------------------------------------------------------------------------
np.random.seed(42)

# Correct key byte 0 for the NIST test key
CORRECT_KEY_BYTE = 0x00


# =============================================================================
# Helpers
# =============================================================================

def compute_true_hw_labels(plaintexts, key_byte=CORRECT_KEY_BYTE):
    """Compute the true HW(SubBytes(pt_byte0 XOR key)) for each trace.

    This is the ground-truth leakage class — what the hardware is actually
    leaking, before noise is added.  Used to colour the histogram.

    Parameters
    ----------
    plaintexts : np.ndarray, shape (N, 16), uint8
    key_byte   : int

    Returns
    -------
    hw_labels : np.ndarray, shape (N,), uint8   values in 0..8
    """
    pt_byte0 = plaintexts[:, 0]
    sbox_out = AES_SBOX[pt_byte0 ^ np.uint8(key_byte)]
    return hamming_weight(sbox_out)


# =============================================================================
# Plotting
# =============================================================================

def plot_raw_traces(traces, plaintexts, out_path, n_scatter=100):
    """Two-panel raw leakage visualisation.

    Parameters
    ----------
    traces     : np.ndarray, shape (N,), float32
    plaintexts : np.ndarray, shape (N, 16), uint8
    out_path   : Path
    n_scatter  : int — how many traces to show in the scatter panel
    """
    hw_labels = compute_true_hw_labels(plaintexts)

    # Colour map: 9 HW classes (0–8) mapped to a perceptually uniform palette
    # WHY tab10: distinct, colourblind-friendly, widely recognised in papers
    cmap   = cm.colormaps['tab10'].resampled(9)  # MODIFIED: get_cmap deprecated in 3.7
    colours = [cmap(hw) for hw in hw_labels[:n_scatter]]

    fig, axes = plt.subplots(1, 2, figsize=(16, 5))
    fig.suptitle(
        "Act 1 — Raw Power Leakage Traces  |  Unmasked AES, Simulated HW Model",
        fontsize=13, fontweight='bold'
    )

    # ------------------------------------------------------------------
    # Panel 1 — Scatter: trace value vs trace index (first n_scatter)
    # ------------------------------------------------------------------
    ax = axes[0]

    ax.scatter(
        range(n_scatter),
        traces[:n_scatter],
        c=colours,
        s=18,
        zorder=3,
        label='_nolegend_',
    )

    # Horizontal line at overall mean — reference for noise centre
    ax.axhline(
        traces.mean(),
        color='black', linewidth=1.0, linestyle='--',
        label=f'Mean = {traces.mean():.1f}',
        zorder=2,
    )

    # Add a colour legend for HW classes
    legend_handles = [
        plt.Line2D([0], [0], marker='o', color='w',
                   markerfacecolor=cmap(hw), markersize=7,
                   label=f'HW = {hw}')
        for hw in range(9)
    ]
    ax.legend(
        handles=legend_handles,
        title='True HW class',
        fontsize=7,
        title_fontsize=8,
        loc='upper right',
        ncol=2,
    )

    ax.set_title(f"First {n_scatter} Traces (coloured by true HW class)", fontsize=11)
    ax.set_xlabel("Trace Index", fontsize=10)
    ax.set_ylabel("Simulated Power Sample (HW + noise)", fontsize=10)
    ax.set_xlim(-1, n_scatter)
    ax.grid(True, alpha=0.3, zorder=1)

    # ------------------------------------------------------------------
    # Panel 2 — Histogram: all N traces, one histogram per HW class
    # ------------------------------------------------------------------
    ax = axes[1]

    # WHY per-class histograms stacked:
    #   A single histogram hides the class structure.  Overlaid per-class
    #   histograms show exactly how much overlap exists between adjacent
    #   HW classes — the noise floor determines attack difficulty.
    bins = np.linspace(traces.min() - 1, traces.max() + 1, 60)

    for hw in range(9):
        mask = hw_labels == hw
        if mask.sum() == 0:
            continue
        ax.hist(
            traces[mask],
            bins=bins,
            alpha=0.55,
            color=cmap(hw),
            label=f'HW={hw}  (n={mask.sum()})',
            density=True,    # normalise so rare classes are still visible
        )

    ax.set_title(f"Trace Distribution by True HW Class  (N={len(traces)})", fontsize=11)
    ax.set_xlabel("Simulated Power Sample", fontsize=10)
    ax.set_ylabel("Density (normalised per class)", fontsize=10)
    ax.legend(fontsize=7, ncol=2, title='HW class', title_fontsize=8)
    ax.grid(True, alpha=0.3)

    # ------------------------------------------------------------------
    # Annotation: noise sigma estimate from HW=4 class (most populated)
    # ------------------------------------------------------------------
    hw4_traces = traces[hw_labels == 4]
    if len(hw4_traces) > 10:
        sigma_est = hw4_traces.std()
        ax.annotate(
            f"Est. noise σ ≈ {sigma_est:.2f}\n(from HW=4 class)",
            xy=(hw4_traces.mean(), ax.get_ylim()[1] * 0.85),
            xytext=(hw4_traces.mean() + 4, ax.get_ylim()[1] * 0.85),
            arrowprops=dict(arrowstyle='->', color='black'),
            fontsize=8,
        )

    plt.tight_layout()
    plt.savefig(out_path, dpi=150)
    plt.close(fig)
    print(f"Saved: {out_path}")


# =============================================================================
# Summary statistics printed to terminal
# =============================================================================

def print_trace_summary(traces, hw_labels):
    """Print per-class mean and count — useful for verifying the leakage model."""
    print(f"\n{'HW Class':>10}  {'Count':>7}  {'Mean Power':>12}  {'Std':>8}")
    print("-" * 44)
    for hw in range(9):
        mask = hw_labels == hw
        n = mask.sum()
        if n == 0:
            continue
        mean = traces[mask].mean()
        std  = traces[mask].std()
        print(f"{hw:>10}  {n:>7}  {mean:>12.3f}  {std:>8.3f}")
    print()
    # Sanity: per-class mean should increase monotonically with HW
    # (higher HW = more switching = more power)
    means = [traces[hw_labels == hw].mean() for hw in range(9)
             if (hw_labels == hw).sum() > 0]
    # Check monotonicity only for classes with enough samples to have a
    # reliable mean.  HW=0 and HW=8 have <20 samples out of 5000 (the
    # binomial probability is low at the extremes), so their sample means
    # are noisy and may appear non-monotone even when the model is correct.
    MIN_SAMPLES = 50
    reliable = [(hw, traces[hw_labels == hw].mean())
                for hw in range(9)
                if (hw_labels == hw).sum() >= MIN_SAMPLES]
    if len(reliable) >= 2:
        monotone = all(reliable[i][1] < reliable[i+1][1]
                       for i in range(len(reliable) - 1))
        checked = [hw for hw, _ in reliable]
        print(f"Per-class means monotone (classes {checked}): "
              f"{'YES  PASS' if monotone else 'NO  WARN — check leakage model'}")
    else:
        print("Per-class means: insufficient data for monotone check")


# =============================================================================
# Entry Point
# =============================================================================

def main():
    parser = argparse.ArgumentParser(
        description="AEGIS — Act 1 raw trace visualisation"
    )
    parser.add_argument(
        "--traces",
        type=str,
        default="traces",
        help="Directory containing .npy trace files (default: traces/)",
    )
    parser.add_argument(
        "--results",
        type=str,
        default="results",
        help="Directory to write plot PNG files (default: results/)",
    )
    parser.add_argument(
        "--n-scatter",
        type=int,
        default=100,
        help="Number of traces to show in scatter panel (default: 100)",
    )
    args = parser.parse_args()

    traces_dir  = Path(args.traces)
    results_dir = Path(args.results)
    results_dir.mkdir(parents=True, exist_ok=True)

    # -----------------------------------------------------------------------
    # Load
    # -----------------------------------------------------------------------
    traces_path     = traces_dir / "traces_unmasked.npy"
    plaintexts_path = traces_dir / "plaintexts.npy"

    if not traces_path.exists():
        sys.exit(f"ERROR: {traces_path} not found.\n"
                 "Run collect_traces.py --mode simulate first.")
    if not plaintexts_path.exists():
        sys.exit(f"ERROR: {plaintexts_path} not found.\n"
                 "Run collect_traces.py --mode simulate first.")

    traces     = np.load(traces_path)
    plaintexts = np.load(plaintexts_path)

    N = len(traces)
    print(f"Loaded {N} traces.")

    # -----------------------------------------------------------------------
    # Compute ground-truth HW labels (known because we know the key)
    # -----------------------------------------------------------------------
    hw_labels = compute_true_hw_labels(plaintexts)

    # -----------------------------------------------------------------------
    # Print summary statistics
    # -----------------------------------------------------------------------
    print_trace_summary(traces, hw_labels)

    # -----------------------------------------------------------------------
    # Plot
    # -----------------------------------------------------------------------
    out_path = results_dir / "act1_raw_traces.png"
    plot_raw_traces(traces, plaintexts, out_path, n_scatter=args.n_scatter)

    print("\nDone.")
    print("Act 1 Python pipeline complete:")
    print("  results/act1_raw_traces.png")
    print("  results/act1_dpa_correlation.png")
    print("  results/act1_dpa_key_rank.png")
    print("\nNext: Step 1.1 — rtl/crypto/aes_subbytes.v")


if __name__ == "__main__":
    main()
