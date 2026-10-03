"""fig_ablation_v2.pdf (+ .png): ablation figure (Fig. 4) from results/tables (c6.load(): HorusEye = B5 18-epoch
models, Kitsune = C3 + C3b, Isolation Forest / kNN = C4b). Output: outputs/figures/.
Typography: figstyle.apply(normal=True), identical to fig_scores_both_v1n.pdf. No runs, no training."""
import math
import os
import sys

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
import figstyle  # noqa: E402
import c6  # noqa: E402
import matplotlib  # noqa: E402
matplotlib.use("Agg")
import matplotlib.pyplot as plt  # noqa: E402
from matplotlib.patches import Patch  # noqa: E402
from matplotlib.transforms import blended_transform_factory  # noqa: E402
import numpy as np  # noqa: E402
import pandas as pd  # noqa: E402

T = c6.T                                               # input tables (results/tables)
OUTF = os.path.join(os.path.dirname(os.path.abspath(__file__)), "..", "..", "outputs", "figures")
os.makedirs(OUTF, exist_ok=True)
figstyle.apply(normal=True)
COND = c6.COND
LAB = ["all 14\ndevices", "volume-\nmatched", "cameras\nonly", "gateways\n+ router", "5 random\ndevices\n(a)",
       "5 random\ndevices\n(b)", "1 day", "2 days", "3 days", "5 days"]
DETS = [("HorusEye", "#0072B2"), ("Kitsune", "#E69F00"), ("IsolationForest", "#009E73"), ("kNN", "#CC79A7")]
DLAB = {"IsolationForest": "Isolation Forest"}
REF = {"prop": 0.149, "open": 0.425}                   # released HorusEye (Table 2 macro TPR)

D = c6.load()
D.to_csv(os.path.join(OUTF, "fig_ablation_v2_values.csv"), index=False)


def val(det, cnd, col):
    x = D[(D.detector == det) & (D.condition == cnd)][col]
    return float(x.iloc[0]) if len(x) else np.nan


fig, (axa, axb) = plt.subplots(2, 1, figsize=(7.2, 3.75), sharex=True)   # panels made shorter below, fonts unchanged
n, w = len(COND), 0.19
xs = np.arange(n)
for ax in (axa, axb):
    ax.axvspan(5.5, n - 0.5, color="grey", alpha=0.08, lw=0, zorder=0)
    ax.yaxis.grid(True, color="grey", alpha=0.3, lw=0.6, zorder=0)
    ax.set_axisbelow(True)
    for sp in ("top", "right"):
        ax.spines[sp].set_visible(False)
    ax.set_xlim(-0.6, n - 0.4)
for j, (det, colr) in enumerate(DETS):
    off = (j - 1.5) * w
    tpr = np.array([val(det, c, "macro_tpr_5e5") for c in COND])
    roc = np.array([val(det, c, "macro_roc_auc") for c in COND])
    run = ~np.isnan(tpr)
    if det == "IsolationForest":                       # TPR ~ 0 everywhere: hatched stub so the run is visible
        axa.bar(xs[run] + off, np.full(run.sum(), 0.005), w, color=colr, edgecolor="white", lw=0.4,
                hatch="////", zorder=3)
    else:
        axa.bar(xs[run] + off, tpr[run], w, color=colr, edgecolor="white", lw=0.4, zorder=3)
    axb.bar(xs[~np.isnan(roc)] + off, roc[~np.isnan(roc)], w, color=colr, edgecolor="white", lw=0.4, zorder=3)

axa.set_ylim(0, 0.7)
axb.set_ylim(0.4, 1.0)
axa.set_ylabel("macro TPR")
axb.set_ylabel("macro ROC-AUC")
axa.text(0.008, 0.97, "(a) Macro TPR at FPR ≤ 5×10$^{-5}$", transform=axa.transAxes, ha="left", va="top",
         fontsize=8.5)                                  # small panel title
axa.text(0.995, 0.97, "Isolation Forest: TPR ≈ 0 (scores too coarse at this FPR)", transform=axa.transAxes,
         ha="right", va="top", fontsize=figstyle.SMALL, color="0.3")
axb.text(0.008, 0.97, "(b) Macro ROC-AUC", transform=axb.transAxes, ha="left", va="top", fontsize=8.5)
for y, ls, txt in ((REF["prop"], "--", "released HorusEye,\nproprietary"), (REF["open"], ":", "released HorusEye,\nopen-source")):
    axa.axhline(y, color="0.45", ls=ls, lw=0.9, zorder=2)
    axa.text(1.006, y, txt, transform=blended_transform_factory(axa.transAxes, axa.transData), ha="left",
             va="center", fontsize=figstyle.SMALL - 0.5, color="0.35", clip_on=False, linespacing=1.0)
tr = blended_transform_factory(axa.transData, axa.transAxes)
for i, cnd in enumerate(COND):                         # false-positive limit of each condition's benign test set
    nb = D[D.condition == cnd].n_benign_test
    if len(nb):
        axa.text(i, 1.01, "≤%d FP" % int(math.floor((5e-5 + 1e-6) * nb.iloc[0])), transform=tr, ha="center",
                 va="bottom", fontsize=figstyle.SMALL, color="0.4")
axa.text(2.5, 1.13, "Proprietary corpus (subsets)", transform=tr, ha="center", va="bottom", fontsize=figstyle.LABEL)
axa.text(7.5, 1.13, "Open-source corpus (training days)", transform=tr, ha="center", va="bottom", fontsize=figstyle.LABEL)
axb.set_xticks(xs)
axb.set_xticklabels(LAB)
axb.set_xlabel("Benign training data used (each model is tested on benign traffic of the same devices/days)")
h = [Patch(facecolor=c, edgecolor="white") for _, c in DETS]
fig.legend(h, [DLAB.get(d, d) for d, _ in DETS], loc="upper center", bbox_to_anchor=(0.48, 1.0), ncol=4,
           frameon=False, fontsize=figstyle.LEGEND, handlelength=1.6, columnspacing=1.4, borderaxespad=0.1)
fig.subplots_adjust(left=0.08, right=0.875, top=0.81, bottom=0.27, hspace=0.14)
fig.savefig(os.path.join(OUTF, "fig_ablation_v2.pdf"), bbox_inches="tight")
fig.savefig(os.path.join(OUTF, "fig_ablation_v2.png"), bbox_inches="tight", dpi=200)

# value check against the released value table of the figure
cur = pd.read_csv(os.path.join(T, "B8_fig_ablation_v2_values.csv"))
m = cur.merge(D, on=["detector", "condition"], how="outer", suffixes=("_cur", "_v2"), indicator=True)
diff = m[(m._merge != "both") | ((m.macro_tpr_5e5_cur - m.macro_tpr_5e5_v2).abs() > 1e-12) |
         ((m.macro_roc_auc_cur - m.macro_roc_auc_v2).abs() > 1e-12)]
print("bars:", len(D), "| values differing from results/tables/B8_fig_ablation_v2_values.csv:", len(diff))
if len(diff):
    print(diff.to_string(index=False))
