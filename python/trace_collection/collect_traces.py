# =============================================================================
# python/trace_collection/collect_traces.py
# AEGIS — Power Trace Acquisition
# =============================================================================
# Usage (from project root, venv activated):
#
#   Simulate traces (no hardware required):
#     python python/trace_collection/collect_traces.py --mode simulate
#
#   Collect from hardware (Arty S7 connected via UART):
#     python python/trace_collection/collect_traces.py --mode hardware --port COM3
#
#   Override number of traces or output directory:
#     python python/trace_collection/collect_traces.py --mode simulate --n 1000 --out traces
#
# Output files written to <out_dir>/ :
#   traces_unmasked.npy  — shape (N,)     float32, one HW leakage value per trace
#   plaintexts.npy       — shape (N, 16)  uint8, plaintext bytes (column-major)
#
# WHY a dual-mode script:
#   The board may not be available during development.  --simulate mode runs
#   the full software AES (from aes_utils.py) and applies a realistic noise
#   model so the DPA pipeline can be written, tested, and debugged before
#   touching hardware.  When the board arrives, only the --port argument
#   changes; every downstream script (dpa_attack.py, train_mlp.py, …) is
#   completely unaffected.
# =============================================================================

import argparse
import sys
import numpy as np
from pathlib import Path
from tqdm import tqdm

# ---------------------------------------------------------------------------
# Add project python/ directory to path so we can import aes_utils regardless
# of where the script is run from.  Uses a relative path — no hardcoded roots.
# ---------------------------------------------------------------------------
_SCRIPT_DIR = Path(__file__).resolve().parent            # trace_collection/
_PYTHON_DIR = _SCRIPT_DIR.parent                         # python/
if str(_PYTHON_DIR) not in sys.path:
    sys.path.insert(0, str(_PYTHON_DIR))

from analysis.aes_utils import aes128_encrypt, hamming_weight  # noqa: E402

# ---------------------------------------------------------------------------
# Reproducibility — set BEFORE any numpy random calls (PYTHON/ML RULE 3)
# ---------------------------------------------------------------------------
np.random.seed(42)

# ---------------------------------------------------------------------------
# Fixed project key (NIST test key — same for all three designs in Act 1)
# WHY fixed key: DPA/neural attacks need many encryptions under the SAME key.
#   The attack recovers the key; the key must be known so we can verify.
# ---------------------------------------------------------------------------
FIXED_KEY = bytes.fromhex("000102030405060708090a0b0c0d0e0f")
FIXED_KEY_LIST = list(FIXED_KEY)

# ---------------------------------------------------------------------------
# Noise model for simulation mode
# ---------------------------------------------------------------------------
# WHY additive Gaussian noise:
#   Real oscilloscope traces contain thermal noise, quantisation noise, and
#   switching noise from unrelated logic.  We model this as N(0, sigma²).
#   sigma=0.5 on a signal whose range is [0, 8] HW units gives an SNR that
#   is attackable with ~500 traces — realistic for a student FPGA setup.
#   Increasing sigma tests DPA robustness; decreasing sigma makes the attack
#   too easy to be an interesting demo.
NOISE_SIGMA = 0.5


# =============================================================================
# Simulate Mode
# =============================================================================

def simulate_traces(n_traces: int):
    """Generate synthetic power traces using the HW leakage model.

    For each trace i:
      1. Draw a random 16-byte plaintext.
      2. Run software AES-128 with FIXED_KEY.
      3. Compute HW(SubBytes_output_round1) as the "true" leakage.
      4. Add Gaussian noise to produce the simulated oscilloscope sample.

    The leakage is the HW of the FULL 16-byte SubBytes output (not just byte 0)
    summed together, because the simulated hardware leaks the total switching
    activity of the SubBytes combinational block.
    WHY total HW and not just byte 0:
      The DPA attack targets byte 0 specifically.  The other 15 bytes add
      noise from the attacker's perspective — exactly as they would on real
      hardware.  This makes the simulation a realistic adversarial setting.

    Parameters
    ----------
    n_traces : int

    Returns
    -------
    traces     : np.ndarray, shape (n_traces,),    float32
    plaintexts : np.ndarray, shape (n_traces, 16), uint8
    """
    traces     = np.empty(n_traces, dtype=np.float32)
    plaintexts = np.empty((n_traces, 16), dtype=np.uint8)

    for i in tqdm(range(n_traces), desc="Simulating traces", unit="trace"):
        # Random 16-byte plaintext — uniform over all 256 values per byte
        pt = np.random.randint(0, 256, size=16, dtype=np.uint8)
        plaintexts[i] = pt

        # Run software AES; capture the Round-1 SubBytes output
        _, round1_sbox = aes128_encrypt(pt.tolist(), FIXED_KEY_LIST)

        # Total Hamming Weight of the SubBytes block output = simulated leakage
        # WHY sum over all 16 bytes: models the whole SubBytes block switching
        true_hw = int(np.sum(hamming_weight(round1_sbox)))

        # Add Gaussian noise
        traces[i] = true_hw + np.random.normal(0.0, NOISE_SIGMA)

    return traces, plaintexts


# =============================================================================
# Hardware Mode
# =============================================================================
# Protocol (matches rtl/interface/control_fsm.v):
#   PC sends  32 bytes: plaintext[0..15] || key[0..15]
#   FPGA responds 17 bytes: ciphertext[0..15] || hamming_weight[0]
#
# WHY 17 and not 18:
#   The FPGA streams back the 16 ciphertext bytes plus 1 byte containing
#   HW(SubBytes_output_byte0).  Only byte 0 is sent to keep the UART
#   throughput manageable.  The DPA attack only needs one HW sample per
#   trace — which byte it comes from is a design choice; we use byte 0
#   consistently (ATTACK INTEGRITY rule).

def hardware_traces(n_traces: int, port: str, baud: int = 9600):
    """Collect power traces from the Arty S7 over UART.

    Parameters
    ----------
    n_traces : int
    port     : str   — e.g. "COM3" on Windows, "/dev/ttyUSB0" on Linux
    baud     : int   — default 9600 (matches UART spec)

    Returns
    -------
    traces     : np.ndarray, shape (n_traces,),    float32
    plaintexts : np.ndarray, shape (n_traces, 16), uint8
    """
    try:
        import serial   # pyserial — confirmed in requirements.txt
    except ImportError:
        sys.exit("ERROR: pyserial not installed.  Run: python -m pip install pyserial")

    traces     = np.empty(n_traces, dtype=np.float32)
    plaintexts = np.empty((n_traces, 16), dtype=np.uint8)

    print(f"Opening UART on {port} at {baud} baud…")
    try:
        ser = serial.Serial(port, baud, timeout=5)
    except serial.SerialException as exc:
        sys.exit(f"ERROR: Could not open {port}: {exc}")

    with ser:
        for i in tqdm(range(n_traces), desc="Collecting hardware traces", unit="trace"):
            pt = np.random.randint(0, 256, size=16, dtype=np.uint8)
            plaintexts[i] = pt

            # Build 32-byte payload: plaintext then key
            payload = bytes(pt.tolist()) + FIXED_KEY

            ser.reset_input_buffer()
            ser.write(payload)

            # Read 17 bytes back: 16 ciphertext + 1 HW byte
            response = ser.read(17)
            if len(response) != 17:
                print(f"\nWARN: trace {i} — expected 17 bytes, got {len(response)}.  "
                      "Retrying trace.")
                # Back up and retry this trace index
                i -= 1
                continue

            # Final byte is HW(SubBytes_output_byte0)
            hw_byte = response[16]

            # Store raw HW as the trace sample — no noise added on hardware
            traces[i] = float(hw_byte)

    return traces, plaintexts


# =============================================================================
# Entry Point
# =============================================================================

def main():
    parser = argparse.ArgumentParser(
        description="AEGIS — Collect or simulate AES power traces"
    )
    parser.add_argument(
        "--mode",
        choices=["simulate", "hardware"],
        required=True,
        help="'simulate' generates synthetic traces; 'hardware' reads from FPGA via UART",
    )
    parser.add_argument(
        "--n",
        type=int,
        default=5000,
        help="Number of traces to collect (default: 5000)",
    )
    parser.add_argument(
        "--port",
        type=str,
        default="COM3",
        help="Serial port for hardware mode, e.g. COM3 (default: COM3)",
    )
    parser.add_argument(
        "--baud",
        type=int,
        default=9600,
        help="UART baud rate (default: 9600)",
    )
    parser.add_argument(
        "--out",
        type=str,
        default="traces",
        help="Output directory for .npy files (default: traces/)",
    )
    parser.add_argument(
        "--design",
        choices=["unmasked", "masked", "hardened"],
        default="unmasked",
        help="Which design variant is running (sets output filename suffix)",
    )
    args = parser.parse_args()

    # Resolve output directory relative to the current working directory
    # WHY pathlib: avoids Windows backslash escape issues (PYTHON RULE 2)
    out_dir = Path(args.out)
    out_dir.mkdir(parents=True, exist_ok=True)

    # -----------------------------------------------------------------------
    # Collect traces
    # -----------------------------------------------------------------------
    print(f"Mode    : {args.mode}")
    print(f"Design  : {args.design}")
    print(f"Traces  : {args.n}")
    print(f"Output  : {out_dir.resolve()}")

    if args.mode == "simulate":
        traces, plaintexts = simulate_traces(args.n)
    else:
        if args.port is None:
            sys.exit("ERROR: --port is required in hardware mode (e.g. --port COM3)")
        traces, plaintexts = hardware_traces(args.n, args.port, args.baud)

    # -----------------------------------------------------------------------
    # Save outputs — filenames match FILE NAMING CONVENTION in project spec
    # -----------------------------------------------------------------------
    traces_path     = out_dir / f"traces_{args.design}.npy"
    plaintexts_path = out_dir / "plaintexts.npy"

    np.save(traces_path,     traces)
    np.save(plaintexts_path, plaintexts)

    print(f"\nSaved: {traces_path}     shape={traces.shape},    dtype={traces.dtype}")
    print(f"Saved: {plaintexts_path}  shape={plaintexts.shape}, dtype={plaintexts.dtype}")

    # -----------------------------------------------------------------------
    # Sanity check: confirm trace values are in a plausible range
    # -----------------------------------------------------------------------
    # HW of 16 bytes ranges from 0 to 128.  With noise the simulated signal
    # stays near the 50–70 range (most bytes have ~4 set bits each × 16).
    # If the mean is wildly outside [10, 120], something is wrong.
    mean_hw = float(np.mean(traces))
    print(f"\nTrace mean HW = {mean_hw:.2f}  (expected range ~50–70 for random plaintexts)")
    if not (10 < mean_hw < 120):
        print("WARNING: mean HW is outside expected range — check leakage model.")
    else:
        print("Sanity check PASSED.")

    # -----------------------------------------------------------------------
    # Quick histogram summary in text form (no plot dependency here)
    # -----------------------------------------------------------------------
    min_hw, max_hw = float(np.min(traces)), float(np.max(traces))
    std_hw         = float(np.std(traces))
    print(f"HW stats: min={min_hw:.2f}, max={max_hw:.2f}, std={std_hw:.2f}")

    print("\nDone.  Run python/attacks/dpa_attack.py next.")


if __name__ == "__main__":
    main()
