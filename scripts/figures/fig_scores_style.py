"""Score-distribution figures in one shared style (paper style: Times, normal weight, x axis from 1e-4), from the
raw scores written by scripts/analysis/b1_fasteval.py to outputs/rows/ (no training).
R1/R5 = HorusEye (proprietary / open-source), R4/R8 = Kitsune. Outputs in outputs/figures/:
  fig_scores_both_v1n.pdf     Fig. 3: 2 x 6: (a) HorusEye | (b) Kitsune; SQL injection, Hide & Seek, Hakai
  fig_scores_all_horuseye.pdf supplement: 4 x 8, all 16 attacks x 2 corpora, HorusEye
  fig_scores_all_kitsune.pdf  supplement: 4 x 8, all 16 attacks x 2 corpora, Kitsune
Oracle cut = (k+1)-th highest benign score, k = floor((5e-5 + 1e-6) * n_benign) (7 / 6 FPs);
calibrated tau = (1 - 5e-5) quantile of benign validation scores (B2_calibration.csv);
panel box = TPR at FPR<=5e-5 and ROC-AUC from B1_repro.csv.
Writes outputs/figures/fig_scores_panel_values.csv (the numbers printed in the panels).
Environment: FONT_NORMAL=0 for the bold draft style, XLO_1E4=0 for an x axis starting at 1e-3."""
import os

import matplotlib
matplotlib.use("Agg")
import matplotlib.pyplot as plt  # noqa: E402
from matplotlib.lines import Line2D  # noqa: E402
from matplotlib.ticker import LogLocator, NullFormatter  # noqa: E402
import numpy as np  # noqa: E402
import pandas as pd  # noqa: E402

HERE = os.path.dirname(os.path.abspath(__file__))
TAB = os.path.join(HERE, "..", "..", "results", "tables")       # B1_repro.csv, B2_calibration.csv
ROWS = os.path.join(HERE, "..", "..", "outputs", "rows")         # raw scores (git-ignored; from b1_fasteval.py)
OUTF = os.path.join(HERE, "..", "..", "outputs", "figures")
os.makedirs(OUTF, exist_ok=True)
NORMAL = os.environ.get("FONT_NORMAL", "1") == "1"     # paper style (default): Times, normal weight
import sys  # noqa: E402
sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
import figstyle  # noqa: E402
W = figstyle.apply(NORMAL)                             # shared typography (same values as before)
BENIGN, ATTACK = "#4C72B0", "#DD8452"
XLO = 1e-3                                             # x-axis start (variants may extend it)
BINS = np.logspace(-3, 1, 80)                          # 20 bins per decade
BOXFS = 7
XTICKS = [1e-2, 1e0]
TITLEFS = 10                                   # inner ticks only: no collisions at panel edges
RUNS = {("HorusEye", "A"): "R1_A_HE", ("HorusEye", "B"): "R5_B_HE",
        ("Kitsune", "A"): "R4_A_KIT", ("Kitsune", "B"): "R8_B_KIT"}
NAMES = {"MITM": "ARP spoofing", "Uploading_attack": "Uploading", "SQL_injection": "SQL injection",
         "Password_attack": "Password", "Vulnerability_scanner": "Vuln. scanner", "Sparta": "SSH brute force",
         "bruteforce": "MQTT brute force", "UDP_scan": "UDP scan", "DOS_synflooding": "SYN flood", "Okiru": "Okiru",
         "Muhstik": "Muhstik", "Hide_and_seek": "Hide & Seek", "Hakai": "Hakai", "Torii": "Torii",
         "Ransomware": "Ransomware", "XSS_attack": "XSS"}
ORDER16 = list(NAMES)                                  # same order as Table 2 of the paper

rows = {k: pd.read_pickle(os.path.join(ROWS, r + ".pkl")) for k, r in RUNS.items()}
b1 = pd.read_csv(os.path.join(TAB, "B1_repro.csv")).set_index(["run", "attack"])
cal = pd.read_csv(os.path.join(TAB, "B2_calibration.csv"))
TAU = {(m, c): cal[(cal.model == m) & (cal.corpus_train == c) & (cal.tau_kind == "calib_5e5")].tau.iloc[0]
       for m in ("HorusEye", "Kitsune") for c in ("A", "B")}
ZERO = {c: float((rows[("HorusEye", c)].query("attack == 'Okiru' and label == 0").score <= 0).mean()) for c in ("A", "B")}
printed = []


def panel(ax, det, corpus, attack, title):
    r = rows[(det, corpus)]
    ra = r[r.attack == attack]
    for lab, col in ((0, BENIGN), (1, ATTACK)):
        x = ra[ra.label == lab].score.values
        ax.hist(np.clip(x[x > 0], XLO, 10), bins=BINS, density=True, histtype="step", color=col, lw=1.4)
    ben = np.sort(ra[ra.label == 0].score.values)[::-1]
    k = int(np.floor((5e-5 + 1e-6) * len(ben)))
    ax.axvline(ben[k], color="k", ls="--", lw=1.1)
    ax.axvline(TAU[(det, corpus)], color="#C44E52", ls=":", lw=1.6)
    v = b1.loc[(RUNS[(det, corpus)], attack)]
    ax.text(0.97, 0.96, "TPR %.2f\nAUC %.2f" % (v.tpr_5e5, v.roc_auc), transform=ax.transAxes, ha="right", va="top",
            fontsize=BOXFS, fontweight=W, linespacing=1.0, bbox=dict(boxstyle="round,pad=0.2", fc="white", ec="0.6", lw=0.5, alpha=0.9))
    printed.append({"detector": det, "corpus": "proprietary" if corpus == "A" else "open-source", "attack": attack,
                    "TPR_5e5": round(float(v.tpr_5e5), 3), "ROC_AUC": round(float(v.roc_auc), 3), "max_FP": k,
                    "oracle_cut": float(ben[k]), "calibrated_tau": TAU[(det, corpus)]})
    ax.set_xscale("log")
    ax.set_yscale("log")
    ax.set_xlim(XLO, 1e1)
    ax.set_xticks(XTICKS)
    ax.xaxis.set_minor_formatter(NullFormatter())
    ax.yaxis.set_major_locator(LogLocator(base=10, numticks=4))
    ax.yaxis.set_minor_formatter(NullFormatter())
    ax.set_title(title, pad=3, fontsize=TITLEFS)


def legend(fig, det_note=True):
    h = [Line2D([], [], color=BENIGN, lw=1.4), Line2D([], [], color=ATTACK, lw=1.4),
         Line2D([], [], color="k", ls="--", lw=1.1), Line2D([], [], color="#C44E52", ls=":", lw=1.6),
         Line2D([], [], color="none")]
    lab = ["benign", "attack", "oracle cut (≤7 / ≤6 FP)", "calibrated τ",
           "benign at 0 (Gulliver):\n%.0f%% prop. / %.0f%% open\n(HorusEye only)" % (100 * ZERO["A"], 100 * ZERO["B"])]
    fig.legend(h, lab, loc="center left", bbox_to_anchor=(1.0, 0.5), frameon=False, fontsize=9, handlelength=2.2)


def common_ylim(axes):
    lo = min(a.get_ylim()[0] for a in axes)
    hi = max(a.get_ylim()[1] for a in axes)
    for a in axes:
        a.set_ylim(max(lo, 1e-4), hi)


def fig_both():
    global BOXFS
    BOXFS = 6.5
    fig = plt.figure(figsize=(7.2, 3.0))
    gs = fig.add_gridspec(2, 7, width_ratios=[1, 1, 1, 0.22, 1, 1, 1], wspace=0.12, hspace=0.75)
    atts = ["SQL_injection", "Hide_and_seek", "Hakai"]
    axes = []
    for ri, corpus in enumerate(("A", "B")):
        for gi, det in enumerate(("HorusEye", "Kitsune")):
            for j, a in enumerate(atts):
                ax = fig.add_subplot(gs[ri, j + 4 * gi])
                panel(ax, det, corpus, a, {"SQL_injection": "SQL\ninjection", "Hide_and_seek": "Hide &\nSeek"}.get(a, NAMES[a]))
                if j + 4 * gi == 0:
                    ax.set_ylabel("density")
                if j != 0:
                    ax.tick_params(labelleft=False)
                if ri == 1 and j == 1:  # one centred x label per group (avoids overlap at 10 pt)
                    ax.set_xlabel("score (RMSE)")
                axes.append(ax)
    common_ylim(axes)
    fig.subplots_adjust(left=0.14, right=0.99, top=0.80, bottom=0.17)
    for ri, lab in ((0, "proprietary"), (1, "open-source")):
        pos = axes[ri * 6].get_position()
        fig.text(0.0, (pos.y0 + pos.y1) / 2, lab, rotation=90, va="center", ha="left", fontsize=10, fontweight=W)
    x_a = (axes[0].get_position().x0 + axes[2].get_position().x1) / 2
    x_b = (axes[3].get_position().x0 + axes[5].get_position().x1) / 2
    fig.text(x_a, 0.965, "(a) HorusEye", ha="center", va="top", fontsize=10, fontweight=W)
    fig.text(x_b, 0.965, "(b) Kitsune", ha="center", va="top", fontsize=10, fontweight=W)
    legend(fig)
    fig.savefig(os.path.join(OUTF, "fig_scores_both.pdf"), bbox_inches="tight")
    plt.close(fig)


def fig_all(det, path):
    global BOXFS, XLO, BINS, XTICKS, TITLEFS
    BOXFS, TITLEFS = 8, 10
    if os.environ.get("XLO_1E4", "1") == "1":          # same x axis as Fig. 3
        XLO, BINS, XTICKS = 1e-4, np.logspace(-4, 1, 101), [1e-4, 1e-2, 1e0]
    fig, axs = plt.subplots(4, 8, figsize=(14, 7))
    axes = []
    for ci, corpus in enumerate(("A", "B")):
        for j, a in enumerate(ORDER16):
            ri = 2 * ci + j // 8
            ax = axs[ri, j % 8]
            panel(ax, det, corpus, a, NAMES[a])
            if j % 8 == 0:
                ax.set_ylabel("density")
            else:
                ax.tick_params(labelleft=False)
            if ri == 3:
                ax.set_xlabel("score (RMSE)")
            axes.append(ax)
    common_ylim(axes)
    fig.subplots_adjust(left=0.07, right=0.99, top=0.95, bottom=0.08, wspace=0.12, hspace=0.45)
    for ri, lab in ((0.5, "proprietary"), (2.5, "open-source")):
        y = (axs[int(ri - 0.5)][0].get_position().y1 + axs[int(ri + 0.5)][0].get_position().y0) / 2
        fig.text(0.005, y, lab, rotation=90, va="center", ha="left", fontsize=10, fontweight=W)
    legend(fig)
    fig.savefig(os.path.join(OUTF, path), bbox_inches="tight")
    plt.close(fig)


def fig_both_variant(tag, size, titlefs, legend_mode, hspace, wspace, top):
    """Fig. 2 variants: more space, x axis labelled from 1e-3, smaller titles, legend in the upper-right corner
    (in its own band above the group headers)."""
    global BOXFS, XTICKS, TITLEFS, XLO, BINS
    BOXFS, XTICKS, TITLEFS = 6.5, [1e-3, 1e-1], titlefs
    if os.environ.get("XLO_1E4", "1") == "1":          # Kitsune scores go down to ~3e-4: start the axis at 1e-4
        XLO, BINS, XTICKS = 1e-4, np.logspace(-4, 1, 101), [1e-4, 1e-2, 1e0]
    fig = plt.figure(figsize=size)
    gs = fig.add_gridspec(2, 7, width_ratios=[1, 1, 1, 0.25, 1, 1, 1], wspace=wspace, hspace=hspace)
    atts = ["SQL_injection", "Hide_and_seek", "Hakai"]
    axes = []
    for ri, corpus in enumerate(("A", "B")):
        for gi, det in enumerate(("HorusEye", "Kitsune")):
            for j, a in enumerate(atts):
                ax = fig.add_subplot(gs[ri, j + 4 * gi])
                panel(ax, det, corpus, a, NAMES[a])
                if j + 4 * gi == 0:
                    ax.set_ylabel("density", labelpad=1)
                if j != 0:
                    ax.tick_params(labelleft=False)
                if ri == 1 and j == 1:
                    ax.set_xlabel("score (RMSE)")
                axes.append(ax)
    common_ylim(axes)
    fig.subplots_adjust(left=0.13, right=0.99, top=top, bottom=0.13)
    for ri, lab in ((0, "proprietary"), (1, "open-source")):
        pos = axes[ri * 6].get_position()
        fig.text(0.0, (pos.y0 + pos.y1) / 2, lab, rotation=90, va="center", ha="left", fontsize=10, fontweight=W)
    x_a = (axes[0].get_position().x0 + axes[2].get_position().x1) / 2
    x_b = (axes[3].get_position().x0 + axes[5].get_position().x1) / 2
    yh = axes[0].get_position().y1 + (0.10 if titlefs >= 9 else 0.095)
    fig.text(x_a, yh, "(a) HorusEye", ha="center", va="bottom", fontsize=10, fontweight=W)
    fig.text(x_b, yh, "(b) Kitsune", ha="center", va="bottom", fontsize=10, fontweight=W)
    h = [Line2D([], [], color=BENIGN, lw=1.4), Line2D([], [], color=ATTACK, lw=1.4),
         Line2D([], [], color="k", ls="--", lw=1.1), Line2D([], [], color="#C44E52", ls=":", lw=1.6)]
    lab = ["benign", "attack", "oracle cut (≤7 / ≤6 FP)", "calibrated τ"]
    note = "benign at 0 (Gulliver, HorusEye only): %.0f%% prop. / %.0f%% open" % (100 * ZERO["A"], 100 * ZERO["B"])
    if legend_mode == "row":          # v1: one row in the top-right corner, note underneath
        fig.legend(h, lab, loc="upper right", bbox_to_anchor=(0.995, 1.0), ncol=4, frameon=False, fontsize=8,
                   handlelength=1.8, columnspacing=1.0, borderaxespad=0.1)
        fig.text(0.99, 0.935, note, ha="right", va="top", fontsize=7, fontweight=W)
    elif legend_mode == "box":        # v2: framed box in the top-right corner
        leg = fig.legend(h, lab, loc="upper right", bbox_to_anchor=(0.995, 1.0), ncol=2, frameon=True, fontsize=7.5,
                         handlelength=1.8, columnspacing=1.0, framealpha=1.0, edgecolor="0.6", title=note,
                         title_fontsize=6.5, borderaxespad=0.1)
        leg.get_frame().set_linewidth(0.6)
    else:                             # v3: two compact rows in the top-right corner, note underneath
        fig.legend(h, lab, loc="upper right", bbox_to_anchor=(0.995, 1.0), ncol=2, frameon=False, fontsize=8,
                   handlelength=1.8, columnspacing=1.2, borderaxespad=0.1)
        fig.text(0.99, 0.905, note, ha="right", va="top", fontsize=7, fontweight=W)
    fig.savefig(os.path.join(OUTF, "fig_scores_both_%s%s.pdf" % (tag, "n" if NORMAL else "")), bbox_inches="tight")
    plt.close(fig)


# release: Fig. 3 (variant v1, chosen for the paper) and the two supplement figures
fig_both_variant("v1", (7.2, 3.7), 9, "row", 0.62, 0.14, 0.76)
fig_all("HorusEye", "fig_scores_all_horuseye.pdf")
fig_all("Kitsune", "fig_scores_all_kitsune.pdf")
P = pd.DataFrame(printed).drop_duplicates(["detector", "corpus", "attack"])
P.to_csv(os.path.join(OUTF, "fig_scores_panel_values.csv"), index=False)
print("benign at 0 (HorusEye): prop %.3f, open %.3f" % (ZERO["A"], ZERO["B"]))
print("wrote outputs/figures/fig_scores_both_v1n.pdf, fig_scores_all_horuseye.pdf, fig_scores_all_kitsune.pdf")
