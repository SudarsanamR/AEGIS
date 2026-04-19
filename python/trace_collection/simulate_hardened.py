# =============================================================================
# python/trace_collection/simulate_hardened.py
# AEGIS — Act 3: Generate Simulated Hardened Traces (Step 5.6)
# =============================================================================
# Usage (from project root, venv activated):
#
#   python python/trace_collection/simulate_hardened.py
#   python python/trace_collection/simulate_hardened.py --n 5000 --out traces
#
# WHY a dedicated script:
#   The hardened design adds TWO new countermeasures on top of masking:
#     1. TRNG-sourced mask seed — each encryption uses a different random mask
#     2. Timing jitter — each trace has a random time offset (0–150 cycles)
#
#   In Act 2, the mask was constant (MASK_SEED=0xAC, round-1 mask=0x59).
#   A neural network could learn this fixed mapping. Now the mask is random
#   per-encryption, so the leakage function changes every trace.
#
# Leakage model (mirrors aes_core_hardened.v):
#
#   For each encryption i:
#     1. mask_seed[i] = random 8-bit value (from TRNG)
#     2. round1_mask[i] = lfsr_next(mask_seed[i])  — varies per encryption
#     3. subbytes_out[i] = sbox[pt[i,13] ^ key[13]] XOR round1_mask[i]
#     4. hw_value[i] = HW(subbytes_out[i])
#     5. trace[i] = hw_value[i] + noise + timing_jitter_noise
#
# WHY this defeats BOTH attacks:
#   DPA: HW(sbox(pt^k) ^ random_mask) averages out — no correlation
#   Neural: the mapping changes every trace — no learnable pattern
#
# Outputs:
#   traces/traces_hardened.npy   — shape (N,) float32
# =============================================================================

import argparse
import sys
import numpy as np
from pathlib import Path
from tqdm import tqdm

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

# ---------------------------------------------------------------------------
# Project key
# ---------------------------------------------------------------------------
FIXED_KEY = bytes.fromhex("000102030405060708090a0b0c0d0e0f")
KEY_ARRAY = np.frombuffer(FIXED_KEY, dtype=np.uint8)

# ---------------------------------------------------------------------------
# LFSR next-state function (matches rtl/countermeasures/mask_refresh.v)
# ---------------------------------------------------------------------------
# Polynomial: x^8 + x^6 + x^5 + x^4 + 1
# Taps: bits 7, 5, 4, 3

def lfsr_next(val):
    """Compute next LFSR state (vectorised for numpy arrays).
    
    Parameters
    ----------
    val : np.ndarray, dtype uint8
    
    Returns
    -------
    np.ndarray, dtype uint8 — next LFSR state
    """
    bit7 = (val >> 7) & 1
    bit5 = (val >> 5) & 1
    bit4 = (val >> 4) & 1
    bit3 = (val >> 3) & 1
    new_bit = bit7 ^ bit5 ^ bit4 ^ bit3
    return np.uint8(((val.astype(np.uint16) << 1) & 0xFF) | new_bit)


NOISE_SIGMA = 0.5       # measurement noise (same as Acts 1 & 2)
JITTER_NOISE_SIGMA = 1.5  # additional noise from timing misalignment


def simulate_hardened_traces(plaintexts):
    """Generate hardened traces with random per-encryption masking + jitter.
    
    Parameters
    ----------
    plaintexts : np.ndarray, shape (N, 16), uint8
    
    Returns
    -------
    traces : np.ndarray, shape (N,), float32
    """
    N = len(plaintexts)
    
    # TRNG-sourced random mask seed — different for every encryption
    # In hardware, ring_oscillator_trng provides these.
    # Exclude 0x00 (LFSR dead state)
    mask_seeds = np.random.randint(1, 256, size=N).astype(np.uint8)
    
    # Round-1 mask = lfsr_next(mask_seed) — matches aes_core_hardened.v
    round1_masks = lfsr_next(mask_seeds)
    
    # SubBytes output for byte 13 (attack target)
    sbox_in  = plaintexts[:, 13] ^ KEY_ARRAY[13]   # (N,) uint8
    sbox_out = AES_SBOX[sbox_in]                    # (N,) uint8
    
    # Apply per-trace random mask
    sbox_masked = sbox_out ^ round1_masks           # (N,) uint8 — different mask each trace!
    
    # Hamming Weight of masked byte
    hw_byte = hamming_weight(sbox_masked)           # (N,) uint8
    traces  = hw_byte.astype(np.float32)
    
    # Measurement noise
    traces += np.random.normal(0.0, NOISE_SIGMA, N).astype(np.float32)
    
    # Timing jitter noise — simulates trace misalignment from 0–15 random
    # dummy cycles per round.  In real hardware, the HW value is read via
    # UART at a fixed point, so the HW value itself isn't shifted.  But the
    # power trace at the sample point is contaminated by whatever operation
    # is happening during the jitter cycle (could be AES computation or
    # dummy cycle).  We model this as additional Gaussian noise.
    traces += np.random.normal(0.0, JITTER_NOISE_SIGMA, N).astype(np.float32)
    
    return traces


def main():
    parser = argparse.ArgumentParser(
        description="AEGIS Act 3 — Simulate hardened AES power traces"
    )
    parser.add_argument("--traces", type=str, default="traces",
                        help="Directory with plaintexts.npy")
    parser.add_argument("--out", type=str, default="traces",
                        help="Output directory")
    args = parser.parse_args()

    traces_dir = Path(args.traces)
    out_dir    = Path(args.out)
    out_dir.mkdir(parents=True, exist_ok=True)

    pts_path = traces_dir / "plaintexts.npy"
    if not pts_path.exists():
        sys.exit(f"ERROR: {pts_path} not found.\n"
                 "Run collect_traces.py --mode simulate first.")

    plaintexts = np.load(pts_path)
    N = len(plaintexts)
    print(f"Loaded {N} plaintexts from {pts_path}")
    print(f"Countermeasures: random per-trace masking + timing jitter noise")

    print("\nSimulating hardened traces…")
    traces_hardened = simulate_hardened_traces(plaintexts)

    out_path = out_dir / "traces_hardened.npy"
    np.save(out_path, traces_hardened)

    print(f"\nSaved: {out_path}")
    print(f"  shape={traces_hardened.shape}  dtype={traces_hardened.dtype}")
    print(f"  mean={traces_hardened.mean():.2f}  std={traces_hardened.std():.2f}")

    # --- DPA sanity check ---
    from analysis.aes_utils import hw_model
    pt13 = plaintexts[:, 13]
    t = traces_hardened.astype(np.float64); t -= t.mean()
    ts = np.sqrt((t**2).sum())
    h = hw_model(pt13, 0x0D).astype(np.float64); h -= h.mean()
    r = (h*t).sum() / (np.sqrt((h**2).sum()) * ts) if ts > 0 else 0
    print(f"\nDPA sanity check (unmasked hypothesis, correct key 0x0D): |r| = {abs(r):.5f}")
    print(f"  Expected ≈ 0.00 (random masking destroys ALL correlation)")
    print(f"  Result: {'PASS — near zero' if abs(r) < 0.05 else 'CHECK — higher than expected'}")

    # --- Neural attack sanity check (is the mask learnable?) ---
    # With random masks, there is no fixed mapping to learn.
    # The best any model can do is predict the marginal HW distribution.
    print(f"\nNeural attack feasibility:")
    print(f"  Mask is random per-trace → no fixed leakage function to learn")
    print(f"  Expected neural attack accuracy: ~15% (class prior, 9 classes)")
    print(f"  Expected key rank: ~128 (random guessing)")

    print("\nDone.  Next: python python/analysis/generate_all_plots.py")


if __name__ == "__main__":
    main()
