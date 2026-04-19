# =============================================================================
# python/attacks/neural_attack.py
# AEGIS — Act 2: Neural Network Side-Channel Attack
# =============================================================================
# Usage (from project root, venv activated):
#
#   python python/attacks/neural_attack.py
#   python python/attacks/neural_attack.py --traces traces --model traces
#
# Inputs:
#   traces/traces_masked.npy    — shape (N,)     float32  masked trace values
#   traces/plaintexts.npy       — shape (N, 16)  uint8    plaintext bytes
#   traces/aegis_mlp.pth        — trained MLP (from train_mlp.py)
#
# Outputs:
#   results/act2_neural_correlation.png  — log-likelihood score vs key guess
#
# Attack methodology (profiling / template attack):
#
#   PROFILING PHASE (train_mlp.py):
#     Train MLP to predict P(HW_class | trace) using known-key traces.
#
#   ATTACK PHASE (this script):
#     For each key hypothesis kg in 0..255:
#       For each trace i:
#         expected_hw = HW(SubBytes(pt[i,13] XOR kg))   ← predicted class
#         score[kg] += log(P(class=expected_hw | trace_i))
#     best_kg = argmax(score)
#
#   WHY log-likelihood:
#     Multiplying N probabilities underflows to zero for large N.  Summing
#     log-probabilities is numerically stable and equivalent.
#     For the correct key: expected_hw aligns with what the model learned,
#     so the model assigns high probability → large positive log-prob.
#     For wrong keys: misaligned expected class → lower model probability
#     → lower (more negative) log-prob → lower cumulative score.
#
#   WHY this beats DPA on masked traces:
#     DPA uses a linear correlation model: corr(HW(sbox(pt^kg)), trace).
#     With boolean masking, the leakage is HW(sbox(pt^k) XOR mask), which
#     is UNCORRELATED with HW(sbox(pt^k)) under a uniform mask.
#     The MLP learns the non-linear masked leakage function directly from
#     training data, so it succeeds where the linear DPA model fails.
# =============================================================================

import argparse
import sys
import numpy as np
import torch
import torch.nn as nn
from pathlib import Path
import matplotlib.pyplot as plt

# ---------------------------------------------------------------------------
# Reproducibility (PYTHON/ML RULE 3)
# ---------------------------------------------------------------------------
np.random.seed(42)
torch.manual_seed(42)

# ---------------------------------------------------------------------------
# Path setup
# ---------------------------------------------------------------------------
_SCRIPT_DIR = Path(__file__).resolve().parent
_PYTHON_DIR = _SCRIPT_DIR.parent
if str(_PYTHON_DIR) not in sys.path:
    sys.path.insert(0, str(_PYTHON_DIR))

from analysis.aes_utils import AES_SBOX, hamming_weight   # noqa: E402

# ---------------------------------------------------------------------------
# Attack constants — must match generate_ml_dataset.py and dpa_attack.py
# ---------------------------------------------------------------------------
ATTACK_BYTE   = 13
TRUE_KEY_BYTE = 0x0D
MASK_ROUND1   = np.uint8(0x59)   # NEW: constant round-1 mask from RTL LFSR seed


# =============================================================================
# Model Definition — must match train_mlp.py exactly
# =============================================================================

class AegisMLP(nn.Module):
    """Identical to train_mlp.py — fixed per PYTHON/ML RULE 6."""

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


# =============================================================================
# Neural Attack — log-likelihood scoring
# =============================================================================

def neural_attack(model, traces, plaintexts, device, batch_size=1024):
    """Score all 256 key hypotheses using model log-likelihood.

    Parameters
    ----------
    model      : AegisMLP (eval mode, loaded weights)
    traces     : np.ndarray, shape (N,), float32
    plaintexts : np.ndarray, shape (N, 16), uint8
    device     : torch.device
    batch_size : int — inference batch size

    Returns
    -------
    scores : np.ndarray, shape (256,), float64
        Sum of log P(expected_HW_class | trace) over all N traces.
        Higher = more likely to be the correct key.
    """
    N = len(traces)
    pt_byte = plaintexts[:, ATTACK_BYTE]   # shape (N,), uint8

    # -----------------------------------------------------------------------
    # Step 1: get model's soft probability output for every trace
    #   shape (N, 9) — P(HW_class=k | trace_i) for k in 0..8
    # -----------------------------------------------------------------------
    model.eval()
    X = torch.from_numpy(traces.reshape(-1, 1)).to(device)  # (N, 1)

    log_probs_list = []
    with torch.no_grad():
        for i in range(0, N, batch_size):
            batch  = X[i:i+batch_size]
            logits = model(batch)
            # log_softmax is numerically more stable than log(softmax(logits))
            lp = torch.nn.functional.log_softmax(logits, dim=1)
            log_probs_list.append(lp.cpu().numpy())

    # log_probs[i, k] = log P(HW_class=k | trace_i)
    log_probs = np.concatenate(log_probs_list, axis=0)   # (N, 9)

    # -----------------------------------------------------------------------
    # Step 2: for each key hypothesis, sum log-probs of the expected class
    # -----------------------------------------------------------------------
    scores = np.zeros(256, dtype=np.float64)

    for kg in range(256):
        # MODIFIED: use MASKED hypothesis — HW(sbox[pt^kg]^mask)
        # WHY: the trace leaks HW(sbox[pt^key]^mask), so the model was trained
        # to predict this masked quantity.  For the correct key, our expected
        # masked HW matches the model's prediction perfectly (100% alignment).
        # For wrong keys, the masked HW is misaligned → lower log-prob.
        # Using the unmasked hypothesis HW(sbox[pt^kg]) fails because
        # Cov(HW(x), HW(x^mask)) = 0 — model assigns random probabilities.
        expected_hw = hamming_weight(
            AES_SBOX[pt_byte ^ np.uint8(kg)] ^ MASK_ROUND1    # MODIFIED
        ).astype(np.int64)  # shape (N,), values 0..8

        # Gather log P(expected_hw[i] | trace_i) for all traces at once
        # log_probs[np.arange(N), expected_hw] selects the probability of
        # the expected class for each trace — fully vectorised, no Python loop
        scores[kg] = log_probs[np.arange(N), expected_hw].sum()

    return scores


# =============================================================================
# Key Rank Curve — neural attack (mirrors dpa_attack.py structure)
# =============================================================================

def compute_neural_key_rank(model, traces, plaintexts, device, step=50):
    """Compute key rank of TRUE_KEY_BYTE as trace count increases.

    Parameters
    ----------
    model      : AegisMLP
    traces     : np.ndarray, shape (N,)
    plaintexts : np.ndarray, shape (N, 16)
    device     : torch.device
    step       : int

    Returns
    -------
    ns    : np.ndarray — trace counts
    ranks : np.ndarray — key rank at each count
    """
    counts = np.arange(step, len(traces) + 1, step)
    ranks  = np.empty(len(counts), dtype=np.int32)

    for i, n in enumerate(counts):
        s = neural_attack(model, traces[:n], plaintexts[:n], device)
        # Rank = number of guesses scoring HIGHER than the correct key
        ranks[i] = int(np.sum(s > s[TRUE_KEY_BYTE]))

    return counts, ranks


# =============================================================================
# Plotting
# =============================================================================

def plot_neural_scores(scores, out_path):
    """Bar chart of neural log-likelihood score vs key guess."""
    fig, ax = plt.subplots(figsize=(14, 5))

    colours = ['red' if kg == TRUE_KEY_BYTE else 'steelblue' for kg in range(256)]
    ax.bar(range(256), scores, color=colours, width=1.0, linewidth=0)

    # Annotate correct key
    ax.annotate(
        f"Correct key\n0x{TRUE_KEY_BYTE:02X}\nscore={scores[TRUE_KEY_BYTE]:.0f}",
        xy=(TRUE_KEY_BYTE, scores[TRUE_KEY_BYTE]),
        xytext=(TRUE_KEY_BYTE + 20, scores[TRUE_KEY_BYTE] + (scores.max()-scores.min())*0.05),
        arrowprops=dict(arrowstyle='->', color='red'),
        color='red', fontsize=9,
    )

    ax.set_title("Neural Attack — Log-Likelihood Score vs Key Hypothesis (Byte 13)\n"
                 "Act 2: MLP Attack on Boolean-Masked AES, Simulated Traces",
                 fontsize=12)
    ax.set_xlabel("Key Guess (0x00 – 0xFF)", fontsize=11)
    ax.set_ylabel("Cumulative Log-Likelihood Score", fontsize=11)
    ax.set_xlim(-1, 256)
    ax.legend(handles=[
        plt.Rectangle((0,0),1,1, fc='red',       label=f"Correct key (0x{TRUE_KEY_BYTE:02X})"),
        plt.Rectangle((0,0),1,1, fc='steelblue',  label="Wrong key guess"),
    ], loc='upper right', fontsize=9)
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
        description="AEGIS — Neural SCA attack on masked AES"
    )
    parser.add_argument("--traces",  type=str, default="traces",
                        help="Directory with traces_masked.npy and plaintexts.npy")
    parser.add_argument("--model",   type=str, default="traces",
                        help="Directory containing aegis_mlp.pth")
    parser.add_argument("--results", type=str, default="results",
                        help="Output directory for plots")
    parser.add_argument("--rank-step", type=int, default=50,
                        help="Step for key rank curve (default: 50)")
    args = parser.parse_args()

    traces_dir  = Path(args.traces)
    model_dir   = Path(args.model)
    results_dir = Path(args.results)
    results_dir.mkdir(parents=True, exist_ok=True)

    # -----------------------------------------------------------------------
    # Load data
    # -----------------------------------------------------------------------
    traces     = np.load(traces_dir / "traces_masked.npy")
    plaintexts = np.load(traces_dir / "plaintexts.npy")
    N          = len(traces)
    print(f"Loaded {N} masked traces.")

    # -----------------------------------------------------------------------
    # Load model
    # -----------------------------------------------------------------------
    model_path = model_dir / "aegis_mlp.pth"
    if not model_path.exists():
        sys.exit(f"ERROR: {model_path} not found.  Run train_mlp.py first.")

    device    = torch.device("cuda" if torch.cuda.is_available() else "cpu")
    ckpt      = torch.load(model_path, map_location=device)
    T         = ckpt["T"]
    model     = AegisMLP(T=T).to(device)
    model.load_state_dict(ckpt["state_dict"])
    model.eval()
    print(f"Loaded model from {model_path} (T={T})")

    # -----------------------------------------------------------------------
    # Full attack on all N traces
    # -----------------------------------------------------------------------
    print(f"\nRunning neural attack on {N} traces…")
    scores = neural_attack(model, traces, plaintexts, device)

    best_guess = int(np.argmax(scores))
    print(f"\n{'='*50}")
    print(f"  Best key guess : 0x{best_guess:02X}  (score={scores[best_guess]:.1f})")
    print(f"  Correct key    : 0x{TRUE_KEY_BYTE:02X}  (score={scores[TRUE_KEY_BYTE]:.1f})")
    print(f"  Attack {'SUCCEEDED' if best_guess == TRUE_KEY_BYTE else 'FAILED — increase trace count'}")
    print(f"{'='*50}\n")

    rank_at_N = int(np.sum(scores > scores[TRUE_KEY_BYTE]))
    print(f"Key rank at {N} traces: {rank_at_N}  (0 = top candidate)")

    # Plot
    plot_neural_scores(scores, results_dir / "act2_neural_scores.png")

    # -----------------------------------------------------------------------
    # Key rank curve vs trace count
    # -----------------------------------------------------------------------
    print(f"\nComputing neural key rank curve (step={args.rank_step})…")
    ns, ranks = compute_neural_key_rank(model, traces, plaintexts, device,
                                        step=args.rank_step)

    success_idx = np.where(ranks == 0)[0]
    if len(success_idx) > 0:
        print(f"Neural attack first reaches rank 0 at {ns[success_idx[0]]} traces.")
    else:
        print("Neural attack did not reach rank 0 — check model accuracy.")

    # Save ns/ranks for key_rank_analysis.py to combine with DPA results
    np.save(results_dir / "neural_ranks_masked.npy",  ranks)
    np.save(results_dir / "neural_ns.npy",             ns)
    print(f"Saved rank arrays to {results_dir}/ for key_rank_analysis.py")

    print("\nDone.  Next: python python/analysis/key_rank_analysis.py")


if __name__ == "__main__":
    main()
