# =============================================================================
# python/attacks/dpa_full_key_recovery.py
# Recover all 16 AES key bytes using CPA
# =============================================================================

import numpy as np
import matplotlib.pyplot as plt
from pathlib import Path
import sys

# Path setup
SCRIPT_DIR = Path(__file__).resolve().parent
PYTHON_DIR = SCRIPT_DIR.parent
if str(PYTHON_DIR) not in sys.path:
    sys.path.insert(0, str(PYTHON_DIR))

from analysis.aes_utils import hw_model

# =============================================================================
# Pearson correlation attack
# =============================================================================

def run_dpa(traces, pt_byte):

    t = traces.astype(np.float64)

    t_cent = t - t.mean()
    t_std = np.sqrt((t_cent ** 2).sum())

    corr = np.zeros(256)

    for kg in range(256):

        h = hw_model(pt_byte, kg).astype(np.float64)

        h_cent = h - h.mean()
        h_std = np.sqrt((h_cent ** 2).sum())

        if h_std == 0 or t_std == 0:
            corr[kg] = 0
        else:
            corr[kg] = (h_cent * t_cent).sum() / (h_std * t_std)

    return corr


# =============================================================================
# Plot correlation for a byte
# =============================================================================

def plot_correlation(byte_index, corr, correct_key, results_dir):

    fig, ax = plt.subplots(figsize=(12,4))

    colors = ['red' if i == correct_key else 'steelblue' for i in range(256)]

    ax.bar(range(256), np.abs(corr), color=colors)

    ax.set_title(f"Byte {byte_index} DPA Correlation")
    ax.set_xlabel("Key Guess")
    ax.set_ylabel("|Pearson correlation|")

    out = results_dir / f"byte_{byte_index}_correlation.png"
    plt.tight_layout()
    plt.savefig(out, dpi=150)
    plt.close()

    print(f"Saved {out}")


# =============================================================================
# Main attack
# =============================================================================

def main():

    traces_dir = Path("traces")
    results_dir = Path("results")
    results_dir.mkdir(exist_ok=True)

    traces = np.load(traces_dir / "traces_unmasked.npy")
    plaintexts = np.load(traces_dir / "plaintexts.npy")

    print(f"Loaded {len(traces)} traces")

    recovered_key = []

    # True AES key (for verification only)
    TRUE_KEY = [
        0x00,0x01,0x02,0x03,
        0x04,0x05,0x06,0x07,
        0x08,0x09,0x0A,0x0B,
        0x0C,0x0D,0x0E,0x0F
    ]

    # Attack each byte independently
    for byte_index in range(16):

        print(f"\nAttacking byte {byte_index}...")

        pt_byte = plaintexts[:, byte_index]

        corr = run_dpa(traces, pt_byte)

        best_guess = int(np.argmax(np.abs(corr)))

        recovered_key.append(best_guess)

        print(f"Recovered byte {byte_index}: 0x{best_guess:02X}")

        plot_correlation(byte_index, corr, TRUE_KEY[byte_index], results_dir)

    # Print final key
    print("\nRecovered AES-128 key:")

    print(" ".join(f"{b:02X}" for b in recovered_key))


if __name__ == "__main__":
    main()