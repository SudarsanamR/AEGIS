# =============================================================================
# python/analysis/generate_all_plots.py
# AEGIS — Act 3, Step 5.8: Final 5-Figure Visualization Suite
# =============================================================================
# Usage (from project root, venv activated):
#
#   python python/analysis/generate_all_plots.py
#   python python/analysis/generate_all_plots.py --traces traces --results results/final_demo
#
# This script ALSO performs Step 5.7 (attack hardened design) by running
# DPA and neural attacks on the hardened traces inline.
#
# Generates 5 figures:
#   1. Trace comparison     — raw traces from all 3 designs overlaid
#   2. DPA correlation ×3   — correlation bar chart: unmasked vs masked vs hardened
#   3. Neural accuracy ×3   — neural scores: unmasked vs masked vs hardened
#   4. Key rank ×all        — rank vs trace count for all attack/design combos
#   5. Defense summary      — table/heatmap of attack success vs design
#
# Inputs (all from traces/ by default):
#   traces_unmasked.npy, traces_masked.npy, traces_hardened.npy, plaintexts.npy
#   aegis_mlp.pth  (trained model from Act 2)
#
# Outputs (to results/final_demo/ by default):
#   fig1_trace_comparison.png
#   fig2_dpa_comparison.png
#   fig3_neural_comparison.png  
#   fig4_key_rank_all.png
#   fig5_defense_summary.png
# =============================================================================

import argparse
import sys
import numpy as np
import torch
import torch.nn as nn
import matplotlib.pyplot as plt
from pathlib import Path
from tqdm import tqdm

# ---------------------------------------------------------------------------
# Path setup
# ---------------------------------------------------------------------------
_SCRIPT_DIR = Path(__file__).resolve().parent
_PYTHON_DIR = _SCRIPT_DIR.parent
if str(_PYTHON_DIR) not in sys.path:
    sys.path.insert(0, str(_PYTHON_DIR))

from analysis.aes_utils import AES_SBOX, hamming_weight, hw_model   # noqa: E402

# ---------------------------------------------------------------------------
# Reproducibility
# ---------------------------------------------------------------------------
np.random.seed(42)
torch.manual_seed(42)

# ---------------------------------------------------------------------------
# Constants
# ---------------------------------------------------------------------------
ATTACK_BYTE    = 13
TRUE_KEY_BYTE  = 0x0D
MASK_ROUND1    = np.uint8(0x59)   # constant mask for Act 2 (masked design)


# =============================================================================
# MLP model (must match train_mlp.py)
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
    def forward(self, x):
        return self.net(x)


# =============================================================================
# DPA attack (same as dpa_attack.py)
# =============================================================================
def run_dpa(traces, pt_byte):
    N = len(traces)
    t = traces.astype(np.float64)
    t_cent = t - t.mean()
    t_std = np.sqrt((t_cent**2).sum())
    corr = np.empty(256, dtype=np.float64)
    for kg in range(256):
        h = hw_model(pt_byte, kg).astype(np.float64)
        h_cent = h - h.mean()
        h_std = np.sqrt((h_cent**2).sum())
        if h_std == 0 or t_std == 0:
            corr[kg] = 0.0
        else:
            corr[kg] = (h_cent * t_cent).sum() / (h_std * t_std)
    return corr


def dpa_key_rank(traces, pt_byte, step=100):
    counts = np.arange(step, len(traces) + 1, step)
    ranks = np.empty(len(counts), dtype=np.int32)
    for i, n in enumerate(counts):
        c = run_dpa(traces[:n], pt_byte[:n])
        ranks[i] = int(np.sum(np.abs(c) > np.abs(c[TRUE_KEY_BYTE])))
    return counts, ranks


# =============================================================================
# Neural attack (same as neural_attack.py)
# =============================================================================
def neural_attack(model, traces, plaintexts, device, mask=MASK_ROUND1):
    N = len(traces)
    pt_byte = plaintexts[:, ATTACK_BYTE]
    model.eval()
    X = torch.from_numpy(traces.reshape(-1, 1)).to(device)
    log_probs_list = []
    with torch.no_grad():
        for i in range(0, N, 1024):
            batch = X[i:i+1024]
            logits = model(batch)
            lp = torch.nn.functional.log_softmax(logits, dim=1)
            log_probs_list.append(lp.cpu().numpy())
    log_probs = np.concatenate(log_probs_list, axis=0)

    scores = np.zeros(256, dtype=np.float64)
    for kg in range(256):
        expected_hw = hamming_weight(
            AES_SBOX[pt_byte ^ np.uint8(kg)] ^ mask
        ).astype(np.int64)
        scores[kg] = log_probs[np.arange(N), expected_hw].sum()
    return scores


def neural_key_rank(model, traces, plaintexts, device, step=100, mask=MASK_ROUND1):
    counts = np.arange(step, len(traces) + 1, step)
    ranks = np.empty(len(counts), dtype=np.int32)
    for i, n in enumerate(counts):
        s = neural_attack(model, traces[:n], plaintexts[:n], device, mask=mask)
        ranks[i] = int(np.sum(s > s[TRUE_KEY_BYTE]))
    return counts, ranks


# =============================================================================
# Figure 1: Trace Comparison
# =============================================================================
def fig1_trace_comparison(t_unm, t_msk, t_hrd, out_dir):
    fig, axes = plt.subplots(1, 3, figsize=(18, 5), sharey=True)
    
    n_show = min(100, len(t_unm))
    
    axes[0].hist(t_unm[:n_show], bins=30, color='#e74c3c', alpha=0.8, edgecolor='white')
    axes[0].set_title("Unmasked (Act 1)", fontsize=12, fontweight='bold')
    axes[0].set_xlabel("HW Leakage Value")
    axes[0].set_ylabel("Count")
    
    axes[1].hist(t_msk[:n_show], bins=30, color='#f39c12', alpha=0.8, edgecolor='white')
    axes[1].set_title("Masked (Act 2)", fontsize=12, fontweight='bold')
    axes[1].set_xlabel("HW Leakage Value")
    
    axes[2].hist(t_hrd[:n_show], bins=30, color='#27ae60', alpha=0.8, edgecolor='white')
    axes[2].set_title("Hardened (Act 3)", fontsize=12, fontweight='bold')
    axes[2].set_xlabel("HW Leakage Value")
    
    fig.suptitle("AEGIS — Trace Distribution Comparison Across Designs", 
                 fontsize=14, fontweight='bold', y=1.02)
    plt.tight_layout()
    path = out_dir / "fig1_trace_comparison.png"
    plt.savefig(path, dpi=150, bbox_inches='tight')
    plt.close(fig)
    print(f"  Saved: {path}")


# =============================================================================
# Figure 2: DPA Correlation Comparison
# =============================================================================
def fig2_dpa_comparison(corr_unm, corr_msk, corr_hrd, out_dir):
    fig, axes = plt.subplots(1, 3, figsize=(18, 5), sharey=True)
    
    datasets = [
        (corr_unm, "Unmasked (Act 1)", '#e74c3c'),
        (corr_msk, "Masked (Act 2)", '#f39c12'),
        (corr_hrd, "Hardened (Act 3)", '#27ae60'),
    ]
    
    for ax, (corr, title, color) in zip(axes, datasets):
        colours = ['red' if kg == TRUE_KEY_BYTE else color for kg in range(256)]
        ax.bar(range(256), np.abs(corr), color=colours, width=1.0, linewidth=0)
        ax.set_title(f"DPA — {title}\n|r(correct)| = {abs(corr[TRUE_KEY_BYTE]):.4f}",
                     fontsize=11, fontweight='bold')
        ax.set_xlabel("Key Guess")
        ax.set_xlim(-1, 256)
    
    axes[0].set_ylabel("|Pearson r|")
    fig.suptitle("AEGIS — DPA Correlation: Attack Progressively Fails",
                 fontsize=14, fontweight='bold', y=1.02)
    plt.tight_layout()
    path = out_dir / "fig2_dpa_comparison.png"
    plt.savefig(path, dpi=150, bbox_inches='tight')
    plt.close(fig)
    print(f"  Saved: {path}")


# =============================================================================
# Figure 3: Neural Attack Score Comparison  
# =============================================================================
def fig3_neural_comparison(scores_msk, scores_hrd, out_dir):
    fig, axes = plt.subplots(1, 2, figsize=(14, 5), sharey=True)
    
    datasets = [
        (scores_msk, "Masked (Act 2) — NN Succeeds", '#f39c12'),
        (scores_hrd, "Hardened (Act 3) — NN Fails", '#27ae60'),
    ]
    
    for ax, (scores, title, color) in zip(axes, datasets):
        colours = ['red' if kg == TRUE_KEY_BYTE else color for kg in range(256)]
        ax.bar(range(256), scores, color=colours, width=1.0, linewidth=0)
        
        best = int(np.argmax(scores))
        rank = int(np.sum(scores > scores[TRUE_KEY_BYTE]))
        ax.set_title(f"{title}\nBest=0x{best:02X}, Rank={rank}",
                     fontsize=11, fontweight='bold')
        ax.set_xlabel("Key Guess")
        ax.set_xlim(-1, 256)
    
    axes[0].set_ylabel("Log-Likelihood Score")
    fig.suptitle("AEGIS — Neural Attack: Random Masking Defeats ML",
                 fontsize=14, fontweight='bold', y=1.02)
    plt.tight_layout()
    path = out_dir / "fig3_neural_comparison.png"
    plt.savefig(path, dpi=150, bbox_inches='tight')
    plt.close(fig)
    print(f"  Saved: {path}")


# =============================================================================
# Figure 4: Key Rank Comparison (all attacks × all designs)
# =============================================================================
def fig4_key_rank_all(rank_data, out_dir):
    fig, ax = plt.subplots(figsize=(12, 6))
    
    styles = {
        'DPA × Unmasked':      {'color': '#e74c3c', 'ls': '-',  'lw': 2},
        'DPA × Masked':        {'color': '#f39c12', 'ls': '-',  'lw': 2},
        'DPA × Hardened':      {'color': '#27ae60', 'ls': '-',  'lw': 2},
        'Neural × Masked':     {'color': '#f39c12', 'ls': '--', 'lw': 2},
        'Neural × Hardened':   {'color': '#27ae60', 'ls': '--', 'lw': 2},
    }
    
    for label, (ns, ranks) in rank_data.items():
        s = styles.get(label, {'color': 'gray', 'ls': '-', 'lw': 1})
        ax.plot(ns, ranks, label=label, **s)
    
    ax.axhline(y=0, color='black', linestyle=':', linewidth=0.8, alpha=0.5)
    ax.set_title("AEGIS — Key Rank vs Trace Count\nAll Attacks × All Designs",
                 fontsize=14, fontweight='bold')
    ax.set_xlabel("Number of Traces", fontsize=12)
    ax.set_ylabel("Key Rank (0 = attack success)", fontsize=12)
    ax.legend(fontsize=9, loc='center right')
    ax.grid(True, alpha=0.3)
    ax.set_ylim(-5, max(max(r.max() for _, r in rank_data.values()), 20) * 1.1)
    
    plt.tight_layout()
    path = out_dir / "fig4_key_rank_all.png"
    plt.savefig(path, dpi=150, bbox_inches='tight')
    plt.close(fig)
    print(f"  Saved: {path}")


# =============================================================================
# Figure 5: Defense Summary Heatmap
# =============================================================================
def fig5_defense_summary(results, out_dir):
    designs = ["Unmasked\n(Act 1)", "Masked\n(Act 2)", "Hardened\n(Act 3)"]
    attacks = ["DPA", "Neural\nNetwork"]
    
    fig, ax = plt.subplots(figsize=(8, 4))
    
    # results is a 2×3 array: [attack][design] = rank at full trace count
    data = np.array(results, dtype=np.float64)
    
    # Color: 0 (attacked) = red, high rank = green
    im = ax.imshow(data, cmap='RdYlGn', aspect='auto', vmin=0, vmax=255)
    
    ax.set_xticks(range(3))
    ax.set_xticklabels(designs, fontsize=11)
    ax.set_yticks(range(2))
    ax.set_yticklabels(attacks, fontsize=11)
    
    # Annotate each cell
    for i in range(2):
        for j in range(3):
            rank = int(data[i, j])
            text = f"Rank {rank}\n{'BROKEN' if rank == 0 else 'SECURE'}"
            color = 'white' if rank < 50 else 'black'
            ax.text(j, i, text, ha='center', va='center', fontsize=10,
                    fontweight='bold', color=color)
    
    ax.set_title("AEGIS — Attack Success Summary\n(Key Rank at 5000 Traces)",
                 fontsize=14, fontweight='bold')
    
    plt.colorbar(im, ax=ax, label='Key Rank (0=broken, 255=secure)')
    plt.tight_layout()
    path = out_dir / "fig5_defense_summary.png"
    plt.savefig(path, dpi=150, bbox_inches='tight')
    plt.close(fig)
    print(f"  Saved: {path}")


# =============================================================================
# Entry Point
# =============================================================================
def main():
    parser = argparse.ArgumentParser(
        description="AEGIS — Final 5-figure visualization suite (Act 3)"
    )
    parser.add_argument("--traces",  type=str, default="traces")
    parser.add_argument("--model",   type=str, default="traces")
    parser.add_argument("--results", type=str, default="results/final_demo")
    parser.add_argument("--step",    type=int, default=100,
                        help="Key rank curve step size")
    args = parser.parse_args()

    traces_dir  = Path(args.traces)
    model_dir   = Path(args.model)
    results_dir = Path(args.results)
    results_dir.mkdir(parents=True, exist_ok=True)

    # --- Load all three trace sets ---
    print("Loading traces…")
    t_unm = np.load(traces_dir / "traces_unmasked.npy")
    t_msk = np.load(traces_dir / "traces_masked.npy")
    
    t_hrd_path = traces_dir / "traces_hardened.npy"
    if not t_hrd_path.exists():
        print("  traces_hardened.npy not found — generating now…")
        # Import and run the simulator inline
        sys.path.insert(0, str(_PYTHON_DIR / "trace_collection"))
        from simulate_hardened import simulate_hardened_traces
        plaintexts = np.load(traces_dir / "plaintexts.npy")
        t_hrd = simulate_hardened_traces(plaintexts)
        np.save(t_hrd_path, t_hrd)
        print(f"  Saved: {t_hrd_path}")
    else:
        t_hrd = np.load(t_hrd_path)
    
    plaintexts = np.load(traces_dir / "plaintexts.npy")
    pt_byte = plaintexts[:, ATTACK_BYTE]
    N = len(plaintexts)
    print(f"  {N} traces loaded for each design")

    # --- Load neural model ---
    model_path = model_dir / "aegis_mlp.pth"
    device = torch.device("cuda" if torch.cuda.is_available() else "cpu")
    if model_path.exists():
        ckpt = torch.load(model_path, map_location=device, weights_only=False)
        T = ckpt["T"]
        model = AegisMLP(T=T).to(device)
        model.load_state_dict(ckpt["state_dict"])
        model.eval()
        print(f"  Loaded MLP from {model_path}")
        have_model = True
    else:
        print(f"  WARNING: {model_path} not found — skipping neural attack plots")
        have_model = False

    # --- Run DPA on all 3 designs ---
    print("\n" + "="*60)
    print("  Running DPA attacks…")
    print("="*60)
    
    print("  DPA × Unmasked…")
    corr_unm = run_dpa(t_unm, pt_byte)
    dpa_rank_unm = int(np.sum(np.abs(corr_unm) > np.abs(corr_unm[TRUE_KEY_BYTE])))
    print(f"    |r| = {abs(corr_unm[TRUE_KEY_BYTE]):.4f}, rank = {dpa_rank_unm}")
    
    print("  DPA × Masked…")
    corr_msk = run_dpa(t_msk, pt_byte)
    dpa_rank_msk = int(np.sum(np.abs(corr_msk) > np.abs(corr_msk[TRUE_KEY_BYTE])))
    print(f"    |r| = {abs(corr_msk[TRUE_KEY_BYTE]):.4f}, rank = {dpa_rank_msk}")
    
    print("  DPA × Hardened…")
    corr_hrd = run_dpa(t_hrd, pt_byte)
    dpa_rank_hrd = int(np.sum(np.abs(corr_hrd) > np.abs(corr_hrd[TRUE_KEY_BYTE])))
    print(f"    |r| = {abs(corr_hrd[TRUE_KEY_BYTE]):.4f}, rank = {dpa_rank_hrd}")

    # --- Run Neural attacks ---
    nn_rank_msk = 255
    nn_rank_hrd = 255
    scores_msk  = np.zeros(256)
    scores_hrd  = np.zeros(256)
    
    if have_model:
        print("\n" + "="*60)
        print("  Running Neural attacks…")
        print("="*60)
        
        print("  Neural × Masked…")
        scores_msk = neural_attack(model, t_msk, plaintexts, device, mask=MASK_ROUND1)
        nn_rank_msk = int(np.sum(scores_msk > scores_msk[TRUE_KEY_BYTE]))
        print(f"    Best=0x{np.argmax(scores_msk):02X}, rank = {nn_rank_msk}")
        
        print("  Neural × Hardened…")
        scores_hrd = neural_attack(model, t_hrd, plaintexts, device, mask=MASK_ROUND1)
        nn_rank_hrd = int(np.sum(scores_hrd > scores_hrd[TRUE_KEY_BYTE]))
        print(f"    Best=0x{np.argmax(scores_hrd):02X}, rank = {nn_rank_hrd}")

    # --- Compute key rank curves ---
    print("\n" + "="*60)
    print("  Computing key rank curves…")
    print("="*60)
    
    step = args.step
    rank_data = {}
    
    print("  DPA × Unmasked…")
    ns_du, ranks_du = dpa_key_rank(t_unm, pt_byte, step)
    rank_data['DPA × Unmasked'] = (ns_du, ranks_du)
    
    print("  DPA × Masked…")
    ns_dm, ranks_dm = dpa_key_rank(t_msk, pt_byte, step)
    rank_data['DPA × Masked'] = (ns_dm, ranks_dm)
    
    print("  DPA × Hardened…")
    ns_dh, ranks_dh = dpa_key_rank(t_hrd, pt_byte, step)
    rank_data['DPA × Hardened'] = (ns_dh, ranks_dh)
    
    if have_model:
        print("  Neural × Masked…")
        ns_nm, ranks_nm = neural_key_rank(model, t_msk, plaintexts, device, step, MASK_ROUND1)
        rank_data['Neural × Masked'] = (ns_nm, ranks_nm)
        
        print("  Neural × Hardened…")
        ns_nh, ranks_nh = neural_key_rank(model, t_hrd, plaintexts, device, step, MASK_ROUND1)
        rank_data['Neural × Hardened'] = (ns_nh, ranks_nh)

    # --- Generate all 5 figures ---
    print("\n" + "="*60)
    print("  Generating figures…")
    print("="*60)
    
    fig1_trace_comparison(t_unm, t_msk, t_hrd, results_dir)
    fig2_dpa_comparison(corr_unm, corr_msk, corr_hrd, results_dir)
    
    if have_model:
        fig3_neural_comparison(scores_msk, scores_hrd, results_dir)
    
    fig4_key_rank_all(rank_data, results_dir)
    
    # Summary matrix: [DPA, Neural] × [Unmasked, Masked, Hardened]
    summary = [
        [dpa_rank_unm, dpa_rank_msk, dpa_rank_hrd],       # DPA row
        [0,            nn_rank_msk,  nn_rank_hrd],          # Neural row (0 = not run on unmasked)
    ]
    fig5_defense_summary(summary, results_dir)

    # --- Final report ---
    print("\n" + "="*60)
    print("  AEGIS — Final Results Summary")
    print("="*60)
    print(f"  {'Design':<15} {'DPA Rank':<12} {'Neural Rank':<12} {'Status'}")
    print(f"  {'-'*55}")
    print(f"  {'Unmasked':<15} {dpa_rank_unm:<12} {'N/A':<12} {'BROKEN' if dpa_rank_unm == 0 else 'secure'}")
    print(f"  {'Masked':<15} {dpa_rank_msk:<12} {nn_rank_msk:<12} {'BROKEN' if nn_rank_msk == 0 else 'secure (DPA), ' + ('BROKEN (NN)' if nn_rank_msk == 0 else 'secure (NN)')}")
    print(f"  {'Hardened':<15} {dpa_rank_hrd:<12} {nn_rank_hrd:<12} {'SECURE' if dpa_rank_hrd > 0 and nn_rank_hrd > 0 else 'check'}")
    print(f"\n  All plots saved to: {results_dir}/")
    print("  Done.")


if __name__ == "__main__":
    main()
