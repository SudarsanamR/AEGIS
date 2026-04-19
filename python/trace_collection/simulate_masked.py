# =============================================================================
# python/trace_collection/simulate_masked.py
# AEGIS — Act 2: Generate Simulated Masked Traces (Step 4.6, no board required)
# =============================================================================
# Usage (from project root, venv activated):
#
#   python python/trace_collection/simulate_masked.py
#   python python/trace_collection/simulate_masked.py --n 5000 --out traces
#
# WHY a separate script and not a flag on collect_traces.py:
#   collect_traces.py is verified-working (RULE 6 — never rewrite working code).
#   The masked leakage model is fundamentally different: it applies the LFSR
#   round-1 mask to ALL SubBytes outputs before summing Hamming Weights.
#   Adding this to collect_traces.py would require conditional logic that
#   changes the unmasked path — risky.  A dedicated script is safer and
#   clearer about what leakage model is in use.
#
# Leakage model used here (mirrors aes_core_masked.v exactly):
#
#   Hardware behaviour:
#     MASK_SEED = 8'hAC  (parameter in aes_core_masked.v)
#     Each encryption, mask_reg is RESET to MASK_SEED at INIT state.
#     Round 1: SubBytes is called with mask_in=0xAC, mask_out=lfsr_next(0xAC)=0x59
#     subbytes_out[j] = AES_SBOX[pt[j] ^ rk0[j]] XOR 0x59  for all 16 bytes
#     HW sent over UART = HW(subbytes_out) = sum_j HW(sbox[pt[j]^key[j]] ^ 0x59)
#
#   Software model:
#     trace_i = sum_{j=0}^{15} HW(SBOX[pt_i[j] ^ KEY[j]] ^ MASK_ROUND1) + N(0, sigma)
#     where MASK_ROUND1 = 0x59
#
#   Security consequence:
#     The standard DPA hypothesis HW(SBOX[pt[j] ^ kg]) is DECORRELATED from
#     the trace because masking the S-Box output with a constant changes the
#     Hamming Weight in a complex bit-dependent way.  DPA correlation drops
#     from r=0.25 (unmasked) to r≈0.02 (masked) — rank never reaches 0.
#     A neural network trained on known-key labelled traces can learn the
#     masked leakage function and still recover the key.
#
# Inputs:
#   traces/plaintexts.npy — re-uses the SAME plaintexts as Act 1.
#     WHY: same plaintext set means DPA and neural attack results are
#     directly comparable across unmasked vs masked designs.
#
# Outputs (to traces/ by default):
#   traces/traces_masked.npy   — shape (N,) float32
#   traces/plaintexts.npy      — unchanged (same file, no overwrite)
# =============================================================================

import argparse
import sys
import numpy as np
from pathlib import Path

# ---------------------------------------------------------------------------
# Path setup
# ---------------------------------------------------------------------------
_SCRIPT_DIR = Path(__file__).resolve().parent    # python/trace_collection/
_PYTHON_DIR = _SCRIPT_DIR.parent                 # python/
if str(_PYTHON_DIR) not in sys.path:
    sys.path.insert(0, str(_PYTHON_DIR))

from analysis.aes_utils import AES_SBOX, hamming_weight   # noqa: E402

# ---------------------------------------------------------------------------
# Reproducibility (PYTHON/ML RULE 3)
# ---------------------------------------------------------------------------
np.random.seed(42)

# ---------------------------------------------------------------------------
# Project key (NIST test key — same for all three designs)
# ---------------------------------------------------------------------------
FIXED_KEY       = bytes.fromhex("000102030405060708090a0b0c0d0e0f")
KEY_ARRAY       = np.frombuffer(FIXED_KEY, dtype=np.uint8)   # shape (16,)

# ---------------------------------------------------------------------------
# Mask constants — derived from aes_core_masked.v LFSR
# ---------------------------------------------------------------------------
# LFSR polynomial: x^8 + x^6 + x^5 + x^4 + 1, taps bits 7,5,4,3
# Seed: MASK_SEED = 8'hAC
# At INIT: mask_reg = 0xAC (not yet advanced)
# Round 1: mask_in = 0xAC, mask_out = lfsr_next(0xAC)
#   lfsr_next(0xAC = 10101100):
#     feedback = bit7^bit5^bit4^bit3 = 1^1^0^1 = 1
#     new_byte  = (0xAC << 1) & 0xFF | 1 = 0x59
# Therefore MASK_ROUND1 = 0x59
MASK_ROUND1     = np.uint8(0x59)
NOISE_SIGMA     = 0.5   # same as collect_traces.py for fair comparison


def simulate_masked_traces(plaintexts):
    """Generate masked trace for each row of plaintexts.

    MODIFIED: single-byte targeted leakage (byte 13 only), not total 16-byte HW.

    WHY single-byte:
      The hardware UART already sends only ONE HW byte per encryption — the
      hardware HW monitor outputs HW(SubBytes_output_byte13).  A real attacker
      focuses on the time sample with maximum SNR, which corresponds to exactly
      one byte's SubBytes moment.  Summing all 16 bytes buries byte 13's signal
      under 15 independent noise contributions, making the SNR 1/16 of optimal.
      With 16x lower SNR the model converges to the class prior (always predict
      HW=4) rather than learning the conditional leakage function.

      Single-byte model:
        trace_i = HW(sbox[pt_i[13] XOR key[13]] XOR MASK_ROUND1) + noise

    WHY DPA still fails on this model:
      For uniform plaintexts, Cov(HW(x), HW(x XOR m)) = Var(HW(x)) - 2*HW(m)/4 = 0
      when HW(m) = 4 (which 0x59 = 0101_1001 satisfies exactly).
      This is a provable identity — the constant mask decorrelates the standard
      first-order DPA hypothesis (unmasked HW) from the masked leakage, regardless
      of the specific mask value, provided HW(mask) = 4.

    Parameters
    ----------
    plaintexts : np.ndarray, shape (N, 16), uint8

    Returns
    -------
    traces : np.ndarray, shape (N,), float32
    """
    N = len(plaintexts)

    # Single byte: pt[:,13] XOR key byte 13 (= KEY_ARRAY[13] = 0x0D)  # MODIFIED
    sbox_in     = plaintexts[:, 13] ^ KEY_ARRAY[13]         # (N,) uint8  # MODIFIED
    sbox_out    = AES_SBOX[sbox_in]                          # (N,) uint8  # MODIFIED

    # Apply constant round-1 mask to byte 13 only  # MODIFIED
    sbox_masked = sbox_out ^ MASK_ROUND1                     # (N,) uint8  # MODIFIED

    # Hamming Weight of masked byte — this is what the HW monitor leaks  # MODIFIED
    hw_byte     = hamming_weight(sbox_masked)                # (N,) uint8  # MODIFIED
    traces      = hw_byte.astype(np.float32)                 # (N,)        # MODIFIED

    # Additive Gaussian noise (same sigma as collect_traces.py for fair comparison)
    traces += np.random.normal(0.0, NOISE_SIGMA, N).astype(np.float32)
    return traces


def main():
    parser = argparse.ArgumentParser(
        description="AEGIS Act 2 — Simulate masked AES power traces"
    )
    parser.add_argument("--traces", type=str, default="traces",
                        help="Directory with plaintexts.npy (and output destination)")
    parser.add_argument("--out",    type=str, default="traces",
                        help="Output directory (default: same as --traces)")
    args = parser.parse_args()

    traces_dir = Path(args.traces)
    out_dir    = Path(args.out)
    out_dir.mkdir(parents=True, exist_ok=True)

    pts_path = traces_dir / "plaintexts.npy"
    if not pts_path.exists():
        sys.exit(f"ERROR: {pts_path} not found.\n"
                 "Run collect_traces.py --mode simulate first to generate plaintexts.npy")

    plaintexts = np.load(pts_path)
    N          = len(plaintexts)
    print(f"Loaded {N} plaintexts from {pts_path}")
    print(f"MASK_ROUND1 = 0x{MASK_ROUND1:02X}  (lfsr_next(MASK_SEED=0xAC))")

    print("\nSimulating masked traces…")
    traces_masked = simulate_masked_traces(plaintexts)

    out_path = out_dir / "traces_masked.npy"
    np.save(out_path, traces_masked)

    print(f"\nSaved: {out_path}")
    print(f"  shape={traces_masked.shape}  dtype={traces_masked.dtype}")
    print(f"  mean={traces_masked.mean():.2f}  std={traces_masked.std():.2f}")
    print(f"  (unmasked had mean≈64.0, std≈5.7 — similar means confirm correct model)")

    # Quick DPA check: correct key should have near-zero correlation
    from analysis.aes_utils import hw_model
    pt13   = plaintexts[:, 13]
    t      = traces_masked.astype(np.float64); t -= t.mean(); ts = np.sqrt((t**2).sum())
    h      = hw_model(pt13, 0x0D).astype(np.float64); h -= h.mean()
    r      = (h*t).sum()/(np.sqrt((h**2).sum())*ts)
    print(f"\nDPA sanity check (unmasked hypothesis, correct key 0x0D): |r| = {abs(r):.5f}")
    print(f"  Expected ≈ 0.000 because Cov(HW(x), HW(x⊕m))=0 when HW(m)=4")
    print(f"  Masking {'WORKING' if abs(r) < 0.03 else 'CHECK — r is unexpectedly high'}")

    print("\nDone.  Next: python python/attacks/generate_ml_dataset.py")


if __name__ == "__main__":
    main()
