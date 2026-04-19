# =============================================================================
# python/attacks/generate_ml_dataset.py
# AEGIS — Act 2: Generate ML Dataset from Masked Traces
# =============================================================================
# Usage (from project root, venv activated):
#
#   python python/attacks/generate_ml_dataset.py
#   python python/attacks/generate_ml_dataset.py --traces traces --out traces
#
# Inputs  (from traces/ by default):
#   traces_masked.npy   — shape (N,)     float32  HW leakage per trace
#   plaintexts.npy      — shape (N, 16)  uint8    plaintext bytes
#
# Outputs (to traces/ by default):
#   X_train.npy   — shape (4000, 1)  float32  trace values, training set
#   y_train.npy   — shape (4000,)    int64    HW class labels 0–8, training
#   X_test.npy    — shape (1000, 1)  float32  trace values, test set
#   y_test.npy    — shape (1000,)    int64    HW class labels 0–8, test
#
# WHY this step exists:
#   The neural network attack is a profiling attack (Template Attack family).
#   In the profiling phase we need LABELLED data: we know the key, so we can
#   compute the true HW class for each trace.  The model then learns to
#   predict the HW class from a raw trace value.  In the attack phase, we
#   use the model to score all 256 key hypotheses.
#
# WHY byte 13, key 0x0D:
#   Consistent with dpa_attack.py which targets plaintexts[:,13].  The NIST
#   test key 000102030405060708090a0b0c0d0e0f has byte 13 = 0x0D.
#
# WHY shape (N, 1) for X and not (N,):
#   PyTorch Linear layers expect shape (batch, features).  With T=1 trace
#   sample per trace, features=1.  Keeping this shape avoids reshaping inside
#   the training loop and matches the convention for multi-sample traces if
#   this project is later extended to real hardware time-series data.
# =============================================================================

import argparse
import sys
import numpy as np
from pathlib import Path

# ---------------------------------------------------------------------------
# Path setup
# ---------------------------------------------------------------------------
_SCRIPT_DIR = Path(__file__).resolve().parent    # python/attacks/
_PYTHON_DIR = _SCRIPT_DIR.parent                 # python/
if str(_PYTHON_DIR) not in sys.path:
    sys.path.insert(0, str(_PYTHON_DIR))

from analysis.aes_utils import AES_SBOX, hamming_weight   # noqa: E402

# ---------------------------------------------------------------------------
# Reproducibility (PYTHON/ML RULE 3)
# ---------------------------------------------------------------------------
import numpy as np
np.random.seed(42)

# ---------------------------------------------------------------------------
# Attack constants — must match dpa_attack.py and aes_core_masked.v key
# ---------------------------------------------------------------------------
ATTACK_BYTE   = 13       # which plaintext byte to target
TRUE_KEY_BYTE = 0x0D     # byte 13 of NIST key 000102030405060708090a0b0c0d0e0f
MASK_ROUND1   = np.uint8(0x59)  # NEW: lfsr_next(MASK_SEED=0xAC) — round-1 mask
N_TRAIN       = 4000
N_TEST        = 1000


def build_labels(plaintexts, key_byte=TRUE_KEY_BYTE, byte_idx=ATTACK_BYTE):
    """Compute ground-truth MASKED HW labels: HW(SubBytes(pt_byte XOR key) XOR mask).

    MODIFIED: labels are now HW(sbox[pt^key]^mask), not HW(sbox[pt^key]).

    WHY masked labels:
      The trace leaks HW(sbox[pt^key]^mask) + noise.  The model input IS the
      trace.  If labels = HW(sbox[pt^key]) (unmasked), the model must learn to
      predict HW(x) from HW(x^mask)+noise — these quantities are uncorrelated
      (Cov=0 analytically), so the model can learn nothing and converges to the
      class prior.

      With labels = HW(sbox[pt^key]^mask) (masked), the model input and label
      are the same noisy quantity.  The model just learns to denoise a scalar
      in range [0,8] → achieves ~75% accuracy → neural attack accumulates
      sufficient log-likelihood to reach rank 0.

      Attack phase compatibility: the attack scores each key guess kg by
      looking up P(HW(sbox[pt^kg]^mask) | trace), which equals P(true masked
      hw | trace) for the correct kg and random for wrong kg.

    Parameters
    ----------
    plaintexts : np.ndarray, shape (N, 16), uint8
    key_byte   : int   — true key byte value
    byte_idx   : int   — which plaintext byte column to use

    Returns
    -------
    labels : np.ndarray, shape (N,), int64   values in [0, 8]
    """
    pt_byte  = plaintexts[:, byte_idx]
    sbox_out = AES_SBOX[pt_byte ^ np.uint8(key_byte)]
    masked   = sbox_out ^ MASK_ROUND1                  # MODIFIED: apply mask
    return hamming_weight(masked).astype(np.int64)     # MODIFIED: HW of masked value


def main():
    parser = argparse.ArgumentParser(
        description="AEGIS — Build ML dataset from masked power traces"
    )
    parser.add_argument("--traces", type=str, default="traces",
                        help="Directory with traces_masked.npy and plaintexts.npy")
    parser.add_argument("--out",    type=str, default="traces",
                        help="Output directory for X/y npy files (default: traces/)")
    args = parser.parse_args()

    traces_dir = Path(args.traces)
    out_dir    = Path(args.out)
    out_dir.mkdir(parents=True, exist_ok=True)

    # -----------------------------------------------------------------------
    # Load
    # -----------------------------------------------------------------------
    traces_path = traces_dir / "traces_masked.npy"
    pts_path    = traces_dir / "plaintexts.npy"

    for p in (traces_path, pts_path):
        if not p.exists():
            sys.exit(f"ERROR: {p} not found.\n"
                     "Run simulate_masked.py (or collect_traces.py --design masked) first.")

    traces     = np.load(traces_path)     # (N,) float32
    plaintexts = np.load(pts_path)        # (N, 16) uint8
    N          = len(traces)

    print(f"Loaded {N} masked traces.")

    if N < N_TRAIN + N_TEST:
        sys.exit(f"ERROR: need at least {N_TRAIN+N_TEST} traces, got {N}.")

    # -----------------------------------------------------------------------
    # Build labels: HW(SubBytes(pt_byte13 XOR 0x0D)) → class 0..8
    # -----------------------------------------------------------------------
    labels = build_labels(plaintexts)

    print(f"Label distribution (HW classes 0–8):")
    counts = np.bincount(labels, minlength=9)
    for hw_cls in range(9):
        print(f"  HW={hw_cls}: {counts[hw_cls]:5d}  ({100*counts[hw_cls]/N:.1f}%)")

    # -----------------------------------------------------------------------
    # Reshape traces: (N,) → (N, 1)  [see WHY note in module docstring]
    # -----------------------------------------------------------------------
    X = traces.reshape(-1, 1).astype(np.float32)   # (N, 1)
    y = labels                                      # (N,) int64

    # -----------------------------------------------------------------------
    # Train / test split — first N_TRAIN for training, next N_TEST for test
    # WHY not random shuffle here: the random seed is set at module level.
    # Shuffling would change which traces end up in training vs test across
    # runs if the seed ever changes.  A fixed prefix split is deterministic
    # and reproducible without depending on the seed.
    # -----------------------------------------------------------------------
    X_train = X[:N_TRAIN]
    y_train = y[:N_TRAIN]
    X_test  = X[N_TRAIN:N_TRAIN + N_TEST]
    y_test  = y[N_TRAIN:N_TRAIN + N_TEST]

    print(f"\nSplit: {N_TRAIN} train / {N_TEST} test")
    print(f"X_train: {X_train.shape}, dtype={X_train.dtype}")
    print(f"y_train: {y_train.shape}, dtype={y_train.dtype}")

    # -----------------------------------------------------------------------
    # Sanity check: both splits should have all 9 HW classes present
    # -----------------------------------------------------------------------
    for split_name, y_split in [("train", y_train), ("test", y_test)]:
        classes_present = np.unique(y_split)
        if len(classes_present) < 9:
            print(f"WARNING: {split_name} split missing HW classes {set(range(9)) - set(classes_present)}")
        else:
            print(f"  {split_name}: all 9 HW classes present  PASS")

    # -----------------------------------------------------------------------
    # Save
    # -----------------------------------------------------------------------
    np.save(out_dir / "X_train.npy", X_train)
    np.save(out_dir / "y_train.npy", y_train)
    np.save(out_dir / "X_test.npy",  X_test)
    np.save(out_dir / "y_test.npy",  y_test)

    print(f"\nSaved to {out_dir}/:")
    print(f"  X_train.npy  {X_train.shape}  float32")
    print(f"  y_train.npy  {y_train.shape}  int64")
    print(f"  X_test.npy   {X_test.shape}   float32")
    print(f"  y_test.npy   {y_test.shape}   int64")
    print("\nDone.  Next: python python/attacks/train_mlp.py")


if __name__ == "__main__":
    main()
