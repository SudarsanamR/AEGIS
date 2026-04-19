# =============================================================================
# python/analysis/aes_utils.py
# AEGIS — Shared AES-128 Utilities
# =============================================================================
# Purpose:
#   Central helper module imported by every Python script in the project.
#   Provides:
#     - AES_SBOX        : The 256-entry AES S-Box lookup table (numpy array)
#     - hamming_weight  : HW of a scalar or numpy array of uint8 values
#     - hw_model        : The leakage model  HW(SubBytes(pt_byte ^ key_guess))
#     - aes128_encrypt  : Software AES-128 encrypt (NIST-verified, column-major)
#
# WHY a shared module:
#   dpa_attack.py, generate_ml_dataset.py, neural_attack.py, and key_rank.py
#   all need the same S-Box and the same leakage model.  Duplicating the table
#   in each file is a maintenance hazard — one wrong byte and the attack breaks
#   silently.  A single source of truth prevents that class of bug.
#
# Column-major state ordering (matches rtl/ modules):
#   byte index 0 = row0,col0  (bits [127:120] in 128-bit Verilog vector)
#   byte index 1 = row1,col0
#   byte index 2 = row2,col0
#   byte index 3 = row3,col0
#   byte index 4 = row0,col1
#   ...
#   byte index 15 = row3,col3
#
# NIST test vector (FIPS 197, Appendix C.1):
#   Plaintext  : 00112233445566778899aabbccddeeff
#   Key        : 000102030405060708090a0b0c0d0e0f
#   Ciphertext : 69c4e0d86a7b0430d8cdb78070b4c55a  ← verified by reference library
# =============================================================================

import numpy as np

# ---------------------------------------------------------------------------
# Random seed — set here so importing this module alone does not side-effect
# the caller's seed.  Callers that need reproducibility must set their OWN
# seed AFTER importing (see PYTHON/ML RULE 3 in project spec).
# ---------------------------------------------------------------------------

# ---------------------------------------------------------------------------
# AES S-Box
# ---------------------------------------------------------------------------
# The full 256-entry AES substitution table from FIPS 197, Section 5.1.1.
# Stored as a numpy uint8 array so vectorized indexing is O(1) with no loop.
AES_SBOX = np.array([
    0x63, 0x7c, 0x77, 0x7b, 0xf2, 0x6b, 0x6f, 0xc5,
    0x30, 0x01, 0x67, 0x2b, 0xfe, 0xd7, 0xab, 0x76,
    0xca, 0x82, 0xc9, 0x7d, 0xfa, 0x59, 0x47, 0xf0,
    0xad, 0xd4, 0xa2, 0xaf, 0x9c, 0xa4, 0x72, 0xc0,
    0xb7, 0xfd, 0x93, 0x26, 0x36, 0x3f, 0xf7, 0xcc,
    0x34, 0xa5, 0xe5, 0xf1, 0x71, 0xd8, 0x31, 0x15,
    0x04, 0xc7, 0x23, 0xc3, 0x18, 0x96, 0x05, 0x9a,
    0x07, 0x12, 0x80, 0xe2, 0xeb, 0x27, 0xb2, 0x75,
    0x09, 0x83, 0x2c, 0x1a, 0x1b, 0x6e, 0x5a, 0xa0,
    0x52, 0x3b, 0xd6, 0xb3, 0x29, 0xe3, 0x2f, 0x84,
    0x53, 0xd1, 0x00, 0xed, 0x20, 0xfc, 0xb1, 0x5b,
    0x6a, 0xcb, 0xbe, 0x39, 0x4a, 0x4c, 0x58, 0xcf,
    0xd0, 0xef, 0xaa, 0xfb, 0x43, 0x4d, 0x33, 0x85,
    0x45, 0xf9, 0x02, 0x7f, 0x50, 0x3c, 0x9f, 0xa8,
    0x51, 0xa3, 0x40, 0x8f, 0x92, 0x9d, 0x38, 0xf5,
    0xbc, 0xb6, 0xda, 0x21, 0x10, 0xff, 0xf3, 0xd2,
    0xcd, 0x0c, 0x13, 0xec, 0x5f, 0x97, 0x44, 0x17,
    0xc4, 0xa7, 0x7e, 0x3d, 0x64, 0x5d, 0x19, 0x73,
    0x60, 0x81, 0x4f, 0xdc, 0x22, 0x2a, 0x90, 0x88,
    0x46, 0xee, 0xb8, 0x14, 0xde, 0x5e, 0x0b, 0xdb,
    0xe0, 0x32, 0x3a, 0x0a, 0x49, 0x06, 0x24, 0x5c,
    0xc2, 0xd3, 0xac, 0x62, 0x91, 0x95, 0xe4, 0x79,
    0xe7, 0xc8, 0x37, 0x6d, 0x8d, 0xd5, 0x4e, 0xa9,
    0x6c, 0x56, 0xf4, 0xea, 0x65, 0x7a, 0xae, 0x08,
    0xba, 0x78, 0x25, 0x2e, 0x1c, 0xa6, 0xb4, 0xc6,
    0xe8, 0xdd, 0x74, 0x1f, 0x4b, 0xbd, 0x8b, 0x8a,
    0x70, 0x3e, 0xb5, 0x66, 0x48, 0x03, 0xf6, 0x0e,
    0x61, 0x35, 0x57, 0xb9, 0x86, 0xc1, 0x1d, 0x9e,
    0xe1, 0xf8, 0x98, 0x11, 0x69, 0xd9, 0x8e, 0x94,
    0x9b, 0x1e, 0x87, 0xe9, 0xce, 0x55, 0x28, 0xdf,
    0x8c, 0xa1, 0x89, 0x0d, 0xbf, 0xe6, 0x42, 0x68,
    0x41, 0x99, 0x2d, 0x0f, 0xb0, 0x54, 0xbb, 0x16,
], dtype=np.uint8)

# ---------------------------------------------------------------------------
# AES Inverse S-Box (needed by software AES for full correctness verification)
# ---------------------------------------------------------------------------
AES_INV_SBOX = np.array([
    0x52, 0x09, 0x6a, 0xd5, 0x30, 0x36, 0xa5, 0x38,
    0xbf, 0x40, 0xa3, 0x9e, 0x81, 0xf3, 0xd7, 0xfb,
    0x7c, 0xe3, 0x39, 0x82, 0x9b, 0x2f, 0xff, 0x87,
    0x34, 0x8e, 0x43, 0x44, 0xc4, 0xde, 0xe9, 0xcb,
    0x54, 0x7b, 0x94, 0x32, 0xa6, 0xc2, 0x23, 0x3d,
    0xee, 0x4c, 0x95, 0x0b, 0x42, 0xfa, 0xc3, 0x4e,
    0x08, 0x2e, 0xa1, 0x66, 0x28, 0xd9, 0x24, 0xb2,
    0x76, 0x5b, 0xa2, 0x49, 0x6d, 0x8b, 0xd1, 0x25,
    0x72, 0xf8, 0xf6, 0x64, 0x86, 0x68, 0x98, 0x16,
    0xd4, 0xa4, 0x5c, 0xcc, 0x5d, 0x65, 0xb6, 0x92,
    0x6c, 0x70, 0x48, 0x50, 0xfd, 0xed, 0xb9, 0xda,
    0x5e, 0x15, 0x46, 0x57, 0xa7, 0x8d, 0x9d, 0x84,
    0x90, 0xd8, 0xab, 0x00, 0x8c, 0xbc, 0xd3, 0x0a,
    0xf7, 0xe4, 0x58, 0x05, 0xb8, 0xb3, 0x45, 0x06,
    0xd0, 0x2c, 0x1e, 0x8f, 0xca, 0x3f, 0x0f, 0x02,
    0xc1, 0xaf, 0xbd, 0x03, 0x01, 0x13, 0x8a, 0x6b,
    0x3a, 0x91, 0x11, 0x41, 0x4f, 0x67, 0xdc, 0xea,
    0x97, 0xf2, 0xcf, 0xce, 0xf0, 0xb4, 0xe6, 0x73,
    0x96, 0xac, 0x74, 0x22, 0xe7, 0xad, 0x35, 0x85,
    0xe2, 0xf9, 0x37, 0xe8, 0x1c, 0x75, 0xdf, 0x6e,
    0x47, 0xf1, 0x1a, 0x71, 0x1d, 0x29, 0xc5, 0x89,
    0x6f, 0xb7, 0x62, 0x0e, 0xaa, 0x18, 0xbe, 0x1b,
    0xfc, 0x56, 0x3e, 0x4b, 0xc6, 0xd2, 0x79, 0x20,
    0x9a, 0xdb, 0xc0, 0xfe, 0x78, 0xcd, 0x5a, 0xf4,
    0x1f, 0xdd, 0xa8, 0x33, 0x88, 0x07, 0xc7, 0x31,
    0xb1, 0x12, 0x10, 0x59, 0x27, 0x80, 0xec, 0x5f,
    0x60, 0x51, 0x7f, 0xa9, 0x19, 0xb5, 0x4a, 0x0d,
    0x2d, 0xe5, 0x7a, 0x9f, 0x93, 0xc9, 0x9c, 0xef,
    0xa0, 0xe0, 0x3b, 0x4d, 0xae, 0x2a, 0xf5, 0xb0,
    0xc8, 0xeb, 0xbb, 0x3c, 0x83, 0x53, 0x99, 0x61,
    0x17, 0x2b, 0x04, 0x7e, 0xba, 0x77, 0xd6, 0x26,
    0xe1, 0x69, 0x14, 0x63, 0x55, 0x21, 0x0c, 0x7d,
], dtype=np.uint8)

# Round constants (Rcon), indices 1-10 matching FIPS 197 key schedule
# Rcon[i] = (x^(i-1) mod GF(2^8), 0x00, 0x00, 0x00)
# Only the first byte is non-trivial; the rest are 0x00 and applied separately
RCON = np.array([
    0x00,  # unused — AES round counting is 1-indexed; index 0 is a placeholder
    0x01, 0x02, 0x04, 0x08, 0x10,
    0x20, 0x40, 0x80, 0x1b, 0x36,
], dtype=np.uint8)


# =============================================================================
# Hamming Weight
# =============================================================================

# Precomputed HW lookup for 0..255.
# WHY precompute: the leakage model calls this inside tight loops over 5000
# traces × 256 key guesses.  Even numpy's bin_count approach adds overhead
# per call.  One vectorised index into _HW_TABLE is the fastest path.
_HW_TABLE = np.array([bin(i).count('1') for i in range(256)], dtype=np.uint8)


def hamming_weight(x):
    """Return the Hamming Weight (popcount) of x.

    Parameters
    ----------
    x : int or np.ndarray of dtype uint8
        Input value(s) in range 0..255.

    Returns
    -------
    np.ndarray (uint8) or int
        HW for each element.  Shape is preserved.
    """
    return _HW_TABLE[x]


# =============================================================================
# Leakage Model — Standard First-Order HW Model
# =============================================================================
# HW(SubBytes(plaintext_byte XOR key_guess))
# This matches the power model on the vulnerable FPGA design: the Hamming
# Weight of the SubBytes output is what the hardware leaks during Round 1.
#
# WHY target byte 0 only:
#   ATTACK INTEGRITY rule in project spec — full 16-byte recovery is out of
#   scope.  Byte 0 is sufficient to demonstrate the attack and plot key rank.

def hw_model(pt_byte0, key_guess):
    """Vectorised first-order HW leakage model for AES byte 0.

    Computes HW(SubBytes(pt_byte0[i] XOR key_guess)) for all traces at once.

    Parameters
    ----------
    pt_byte0  : np.ndarray, shape (N,), dtype uint8
        Plaintext byte 0 for each of N traces.
    key_guess : int
        Candidate key byte value (0..255).

    Returns
    -------
    np.ndarray, shape (N,), dtype uint8
        Predicted Hamming Weight under this key hypothesis.
    """
    # XOR then S-Box lookup — both fully vectorised, no Python loop
    sbox_out = AES_SBOX[pt_byte0 ^ np.uint8(key_guess)]
    return hamming_weight(sbox_out)


# =============================================================================
# GF(2^8) multiplication helper  (needed by MixColumns in software AES)
# =============================================================================
# WHY Russian Peasant:  Same algorithm as the hardware MixColumns module will
# use.  Having the same algorithm here means the software reference and the
# hardware output are derived from the same logic, making mismatch easier to
# diagnose.

def _gf_mul(a, b):
    """Multiply two bytes in GF(2^8) with irreducible poly 0x11b.

    Pure-Python scalar version — used only inside the software AES encrypt
    reference, not on the inner-loop attack path (which only touches SBox).
    """
    result = 0
    for _ in range(8):
        if b & 1:
            result ^= a
        hi = a & 0x80        # save the high bit before shift
        a = (a << 1) & 0xFF  # left shift, mask to 8 bits
        if hi:
            a ^= 0x1b        # conditional XOR with field polynomial
        b >>= 1
    return result & 0xFF


# =============================================================================
# Software AES-128 Encrypt  (column-major state, for simulation mode)
# =============================================================================
# This is the reference implementation used by collect_traces.py --simulate.
# It mirrors the column-major byte ordering used in the Verilog modules.
#
# State layout (column-major, matching rtl/ modules):
#   state[0]  = row0,col0   state[4]  = row0,col1
#   state[1]  = row1,col0   state[5]  = row1,col1
#   state[2]  = row2,col0   state[6]  = row2,col1
#   state[3]  = row3,col0   state[7]  = row3,col1
#   ... up to state[15] = row3,col3

def _key_expansion(key_bytes):
    """Expand a 16-byte AES-128 key into 11 round keys (each 16 bytes).

    Parameters
    ----------
    key_bytes : bytes or list of int, length 16

    Returns
    -------
    list of np.ndarray, length 11, each shape (16,) uint8
        round_keys[0] is the original key; round_keys[10] is the final key.
    """
    W = list(key_bytes)   # work in flat list of 44 words × 4 bytes = 176 bytes

    # AES key schedule produces 44 4-byte words for AES-128
    # W[0..3] are the original key words
    # WHY 44: we need 11 round keys × 4 words each
    for i in range(4, 44):
        temp = W[(i - 1) * 4: i * 4]
        if i % 4 == 0:
            # RotWord: rotate left by one byte
            temp = [temp[1], temp[2], temp[3], temp[0]]
            # SubWord: apply S-Box to each byte of the word
            temp = [int(AES_SBOX[b]) for b in temp]
            # XOR with Rcon — only the first byte; others are 0x00
            temp[0] ^= int(RCON[i // 4])
        W.extend([W[(i - 4) * 4 + j] ^ temp[j] for j in range(4)])

    # Slice out 11 round keys, each 16 bytes, as numpy arrays
    return [np.array(W[i * 16:(i + 1) * 16], dtype=np.uint8) for i in range(11)]


def _sub_bytes(state):
    """Apply AES SubBytes to all 16 bytes of the state."""
    return AES_SBOX[state]


def _shift_rows(state):
    """Apply AES ShiftRows in column-major layout.

    Column-major means the state is stored by columns, so ShiftRows (which
    shifts ROWS) is a non-contiguous operation.  The index mapping below is
    derived from the column-major layout description in the project spec.

    Row 0: no shift   — bytes at col-major indices 0, 4,  8, 12
    Row 1: shift 1    — bytes at col-major indices 1, 5,  9, 13  → 5, 9, 13, 1
    Row 2: shift 2    — bytes at col-major indices 2, 6, 10, 14  → 10,14,  2, 6
    Row 3: shift 3    — bytes at col-major indices 3, 7, 11, 15  → 15, 3,  7,11
    """
    s = state.copy()
    # Row 0 — no change
    # Row 1 — left-rotate by 1
    s[1], s[5], s[9], s[13] = state[5], state[9], state[13], state[1]
    # Row 2 — left-rotate by 2
    s[2], s[6], s[10], s[14] = state[10], state[14], state[2], state[6]
    # Row 3 — left-rotate by 3 (= right-rotate by 1)
    s[3], s[7], s[11], s[15] = state[15], state[3], state[7], state[11]
    return s


def _mix_columns(state):
    """Apply AES MixColumns column by column in GF(2^8)."""
    result = state.copy()
    for c in range(4):
        # Column c occupies bytes at indices 4c, 4c+1, 4c+2, 4c+3
        b = state[c * 4: c * 4 + 4]
        result[c * 4]     = (_gf_mul(0x02, b[0]) ^ _gf_mul(0x03, b[1])
                              ^ b[2] ^ b[3])
        result[c * 4 + 1] = (b[0] ^ _gf_mul(0x02, b[1])
                              ^ _gf_mul(0x03, b[2]) ^ b[3])
        result[c * 4 + 2] = (b[0] ^ b[1]
                              ^ _gf_mul(0x02, b[2]) ^ _gf_mul(0x03, b[3]))
        result[c * 4 + 3] = (_gf_mul(0x03, b[0]) ^ b[1]
                              ^ b[2] ^ _gf_mul(0x02, b[3]))
    return result


def aes128_encrypt(plaintext_bytes, key_bytes):
    """Software AES-128 encryption (column-major, FIPS 197 compliant).

    Parameters
    ----------
    plaintext_bytes : bytes or list of int, length 16
    key_bytes       : bytes or list of int, length 16

    Returns
    -------
    np.ndarray, shape (16,), dtype uint8
        Ciphertext bytes in the same column-major order.

    Also returns the SubBytes output of Round 1 as a side effect via the
    optional second element of the returned tuple — used by collect_traces.py
    to compute the simulated Hamming Weight leakage.

    Returns
    -------
    tuple (ciphertext, round1_sbox_out)
      ciphertext       : np.ndarray (16,) uint8
      round1_sbox_out  : np.ndarray (16,) uint8  — SubBytes output, Round 1
    """
    round_keys = _key_expansion(key_bytes)
    state = np.array(plaintext_bytes, dtype=np.uint8)

    # Initial AddRoundKey (round key 0)
    state = state ^ round_keys[0]

    round1_sbox_out = None   # will be captured during round 1

    for rnd in range(1, 11):
        state = _sub_bytes(state)

        # Capture SubBytes output in round 1 — this is what the HW leaks
        if rnd == 1:
            round1_sbox_out = state.copy()

        state = _shift_rows(state)
        if rnd < 10:
            state = _mix_columns(state)  # omitted in the final round
        state = state ^ round_keys[rnd]

    return state, round1_sbox_out


# =============================================================================
# Self-test — verifies NIST FIPS 197 Appendix B test vector
# =============================================================================
def _self_test():
    """Run on import to catch any corruption of the S-Box or key schedule."""
    pt  = bytes.fromhex("00112233445566778899aabbccddeeff")
    key = bytes.fromhex("000102030405060708090a0b0c0d0e0f")
    # CORRECTED ciphertext — verified against FIPS 197 Appendix C.1 and the
    # Python cryptography reference library.  The project spec originally listed
    # 69c4e0d86a7b04300d8a2611689e2c00 which is a transcription error.
    # Correct value per FIPS 197 C.1: 69c4e0d86a7b0430d8cdb78070b4c55a   # MODIFIED
    expected_ct = bytes.fromhex("69c4e0d86a7b0430d8cdb78070b4c55a")      # MODIFIED

    # FIPS 197 stores state row-major; our hardware and this module use
    # column-major.  Reorder plaintext for column-major ingestion.
    # FIPS row-major: [00 11 22 33 | 44 55 66 77 | 88 99 aa bb | cc dd ee ff]
    #                  col0-row0/1/2/3  col1-row0/1/2/3 ...
    # Column-major byte order:
    #   index 0 = row0,col0 = pt[0]  = 0x00
    #   index 1 = row1,col0 = pt[4]  = 0x44  (row 1 of the FIPS matrix)
    # ... FIPS 197 actually stores the state so that the input byte stream is
    # loaded column-first: pt byte 0 → state[0,0], pt byte 1 → state[1,0],
    # pt byte 2 → state[2,0], pt byte 3 → state[3,0],
    # pt byte 4 → state[0,1], etc.
    # This IS column-major, so the input byte order is already correct.
    ct, _ = aes128_encrypt(list(pt), list(key))
    ct_hex = bytes(ct).hex()
    assert ct_hex == expected_ct.hex(), (
        f"NIST self-test FAILED: got {ct_hex}, expected {expected_ct.hex()}"
    )

    # Spot-check S-Box: FIPS 197 §4.2.1 — 0x00 → 0x63
    assert AES_SBOX[0x00] == 0x63, "S-Box[0x00] should be 0x63"
    assert AES_SBOX[0x01] == 0x7c, "S-Box[0x01] should be 0x7c"
    assert AES_SBOX[0xff] == 0x16, "S-Box[0xFF] should be 0x16"

    # Spot-check HW table
    assert hamming_weight(np.uint8(0x00)) == 0
    assert hamming_weight(np.uint8(0xFF)) == 8
    assert hamming_weight(np.uint8(0xAA)) == 4  # 10101010 → 4 ones

    # Spot-check hw_model shape and value
    pt0 = np.zeros(4, dtype=np.uint8)      # all-zero plaintext byte 0
    hw  = hw_model(pt0, key_guess=0x00)    # key_guess = 0x00
    # SBox(0x00 XOR 0x00) = SBox(0x00) = 0x63 = 0b01100011 → HW = 4
    assert (hw == 4).all(), f"hw_model spot-check failed: {hw}"


# Run self-test every time this module is imported.
# WHY on import: if a future edit breaks the S-Box ordering, every downstream
# script fails immediately with a clear message instead of silently returning
# wrong key candidates.
_self_test()
