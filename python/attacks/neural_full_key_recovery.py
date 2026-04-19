# =============================================================================
# python/attacks/neural_full_key_recovery.py
# AEGIS — Neural Full 16-Byte AES Key Recovery
# =============================================================================
# Usage (from project root, venv activated):
#
#   python python/attacks/neural_full_key_recovery.py
#
# Inputs:
#   traces/plaintexts.npy   — shape (N, 16) uint8
#   traces/aegis_mlp.pth    — trained MLP (from train_mlp.py)
#
# WHY per-byte traces and not traces_masked.npy:
#
#   traces_masked.npy contains HW(sbox[pt[:,13]^key[13]]^mask) + noise —
#   leakage from byte 13 ONLY.  Applying the model to that trace for byte 0
#   gives random scores because the trace carries zero information about byte 0.
#
#   The correct approach (matching real hardware):
#     A real oscilloscope captures a TIME-SERIES trace.  Each time sample
#     corresponds to a different byte's SubBytes operation.  The attacker
#     selects the sample that leaks byte j when attacking byte j.
#
#   In simulation we replicate this by generating each byte's trace
#   independently:
#     trace_b[i] = HW(sbox[pt[i,b] ^ key[b]] ^ MASK_ROUND1) + noise
#
#   The model is fully generic — it maps a noisy scalar in [0,8] to a HW
#   class.  Since every byte's masked leakage follows the same distribution
#   (same S-Box HW statistics, same mask, same noise), the model trained on
#   byte 13 generalises perfectly to all 16 bytes.  No retraining needed.
# =============================================================================

import sys
import numpy as np
import torch
import torch.nn as nn
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
np.random.seed(42)
torch.manual_seed(42)

# ---------------------------------------------------------------------------
# Constants
# ---------------------------------------------------------------------------
MASK_ROUND1 = np.uint8(0x59)   # lfsr_next(MASK_SEED=0xAC)
NOISE_SIGMA = 0.5
TRUE_KEY    = bytes.fromhex("000102030405060708090a0b0c0d0e0f")


# =============================================================================
# Model — identical to train_mlp.py and neural_attack.py
# =============================================================================

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


# =============================================================================
# Per-byte trace simulation
# =============================================================================

def simulate_byte_traces(plaintexts, key_byte, byte_idx):
    """Simulate the leakage trace for one specific plaintext byte.

    Mirrors what a real oscilloscope would capture at the time sample
    corresponding to byte byte_idx's SubBytes operation.

    Parameters
    ----------
    plaintexts : np.ndarray, shape (N, 16), uint8
    key_byte   : int   — TRUE key byte at position byte_idx
    byte_idx   : int   — which plaintext/key byte to simulate

    Returns
    -------
    traces : np.ndarray, shape (N,), float32
    """
    sbox_out = AES_SBOX[plaintexts[:, byte_idx] ^ np.uint8(key_byte)]
    masked   = sbox_out ^ MASK_ROUND1
    hw       = hamming_weight(masked).astype(np.float32)
    # Different random seed per byte so noise is independent across bytes
    rng      = np.random.RandomState(42 + byte_idx)
    return hw + rng.normal(0.0, NOISE_SIGMA, len(plaintexts)).astype(np.float32)


# =============================================================================
# Single-byte attack
# =============================================================================

def attack_one_byte(model, traces, pt_byte_col, device):
    """Score all 256 key hypotheses for one byte using log-likelihood.

    Parameters
    ----------
    model      : AegisMLP (eval mode)
    traces     : np.ndarray, shape (N,), float32  — leakage for THIS byte
    pt_byte_col: np.ndarray, shape (N,), uint8    — plaintext column for this byte
    device     : torch.device

    Returns
    -------
    scores : np.ndarray, shape (256,), float64
    """
    N = len(traces)
    X = torch.from_numpy(traces.reshape(-1, 1)).to(device)
    with torch.no_grad():
        lp = torch.nn.functional.log_softmax(model(X), dim=1).cpu().numpy()
        # lp[i, k] = log P(HW_class=k | trace_i)

    scores = np.zeros(256, dtype=np.float64)
    for kg in range(256):
        # Expected masked HW under this key hypothesis
        exp_hw      = hamming_weight(
            AES_SBOX[pt_byte_col ^ np.uint8(kg)] ^ MASK_ROUND1
        ).astype(np.int64)
        scores[kg]  = lp[np.arange(N), exp_hw].sum()

    return scores


# =============================================================================
# Summary plot
# =============================================================================

def plot_full_key_recovery(results, out_path):
    """16-panel subplot — one bar chart per byte.

    Correct key marked red; all others steelblue.
    """
    fig, axes = plt.subplots(4, 4, figsize=(18, 10))
    fig.suptitle(
        "Neural Full Key Recovery — 16-Byte AES-128 Key\n"
        "Boolean-Masked AES, Simulated Per-Byte Traces",
        fontsize=13, fontweight='bold'
    )

    for b, ax in enumerate(axes.flat):
        scores  = results[b]["scores"]
        best_kg = results[b]["best"]
        true_kg = TRUE_KEY[b]
        margin  = results[b]["margin"]

        colours = ['red' if kg == true_kg else 'steelblue' for kg in range(256)]
        ax.bar(range(256), scores - scores.min(), color=colours,
               width=1.0, linewidth=0)

        status = "✓" if best_kg == true_kg else "✗"
        ax.set_title(
            f"Byte {b:2d}  {status}  "
            f"got=0x{best_kg:02X}  true=0x{true_kg:02X}  "
            f"Δ={margin:.0f}",
            fontsize=7
        )
        ax.set_xlim(-1, 256)
        ax.axis('off') if False else None
        ax.tick_params(labelsize=6)
        ax.set_xlabel("Key guess", fontsize=6)
        ax.set_yticks([])

    plt.tight_layout()
    plt.savefig(out_path, dpi=120)
    plt.close(fig)
    print(f"Saved: {out_path}")


# =============================================================================
# Main
# =============================================================================

def main():
    traces_dir  = Path("traces")
    results_dir = Path("results")
    results_dir.mkdir(parents=True, exist_ok=True)

    # -----------------------------------------------------------------------
    # Load plaintexts and model
    # -----------------------------------------------------------------------
    plaintexts = np.load(traces_dir / "plaintexts.npy")   # (N, 16) uint8
    N          = len(plaintexts)
    print(f"Loaded {N} plaintexts.")

    model_path = traces_dir / "aegis_mlp.pth"
    if not model_path.exists():
        sys.exit("ERROR: traces/aegis_mlp.pth not found.  Run train_mlp.py first.")

    device = torch.device("cuda" if torch.cuda.is_available() else "cpu")
    ckpt   = torch.load(model_path, map_location=device)
    model  = AegisMLP(T=ckpt["T"]).to(device)
    model.load_state_dict(ckpt["state_dict"])
    model.eval()
    print(f"Loaded model (T={ckpt['T']}, device={device})\n")

    # -----------------------------------------------------------------------
    # Attack all 16 bytes
    # -----------------------------------------------------------------------
    print(f"{'Byte':>5}  {'Recovered':>10}  {'True':>6}  {'Match':>6}  {'Margin (nats)':>14}")
    print("-" * 50)

    results   = {}
    recovered = []

    for b in range(16):
        # Simulate the trace that leaks byte b (uses TRUE_KEY[b] — known to us
        # because this is a simulation; in a real attack the hardware provides
        # this trace directly from the oscilloscope)
        traces_b = simulate_byte_traces(plaintexts, TRUE_KEY[b], b)

        scores  = attack_one_byte(model, traces_b, plaintexts[:, b], device)
        best    = int(np.argmax(scores))
        sorted_s = np.sort(scores)
        margin  = sorted_s[-1] - sorted_s[-2]   # gap to 2nd-best guess

        match   = "✓" if best == TRUE_KEY[b] else "✗"
        rank    = int(np.sum(scores > scores[TRUE_KEY[b]]))

        print(f"  {b:2d}    0x{best:02X}        0x{TRUE_KEY[b]:02X}    {match}      {margin:+.1f}  "
              f"(rank={rank})")

        results[b]  = {"scores": scores, "best": best, "margin": margin}
        recovered.append(best)

    # -----------------------------------------------------------------------
    # Summary
    # -----------------------------------------------------------------------
    n_correct = sum(r == t for r, t in zip(recovered, TRUE_KEY))
    print(f"\nRecovered: {' '.join(f'{b:02x}' for b in recovered)}")
    print(f"True key:  {TRUE_KEY.hex()}")
    print(f"Bytes correct: {n_correct}/16")

    if n_correct == 16:
        print("\nFull key recovered successfully.")
    else:
        wrong = [b for b, (r, t) in enumerate(zip(recovered, TRUE_KEY)) if r != t]
        print(f"\nFailed bytes: {wrong}")
        print("These bytes need more traces or a byte-specific model.")
        print("Try: increase N in simulate_byte_traces (e.g. use 10000 traces)")

    # -----------------------------------------------------------------------
    # Plot
    # -----------------------------------------------------------------------
    plot_full_key_recovery(results, results_dir / "act2_full_key_recovery.png")
    print("\nDone.")


if __name__ == "__main__":
    main()
