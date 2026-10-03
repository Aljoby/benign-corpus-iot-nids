"""fig_tpr_fpr.pdf (paper figure): macro TPR (16 new attacks) vs FPR for HorusEye and Kitsune under both corpora.
Input: results/tables/B8_C1_curves.csv (written by scripts/analysis/c1.py from the raw scores; no datasets needed).
Output: outputs/figures/fig_tpr_fpr.pdf. Default = the style of the paper's figure (matplotlib defaults);
STYLE=shared applies scripts/figures/figstyle.py (Times, as in Figs. 3-4)."""
import os
import sys

import matplotlib
matplotlib.use("Agg")
import matplotlib.pyplot as plt  # noqa: E402
import pandas as pd  # noqa: E402

HERE = os.path.dirname(os.path.abspath(__file__))
sys.path.insert(0, HERE)
if os.environ.get("STYLE") == "shared":
    import figstyle  # noqa: E402
    figstyle.apply(normal=True)
C = pd.read_csv(os.path.join(HERE, "..", "..", "results", "tables", "B8_C1_curves.csv"))
OUTF = os.path.join(HERE, "..", "..", "outputs", "figures")
os.makedirs(OUTF, exist_ok=True)
GRID = C.fpr.values
curves = {(k.split("_")[0], k.split("_")[1]): C[k].values for k in C.columns if k != "fpr"}
fig, ax = plt.subplots(figsize=(5.2, 3.6))
sty = {("A", "HorusEye"): ("#4C72B0", "-"), ("A", "Kitsune"): ("#4C72B0", "--"), ("B", "HorusEye"): ("#55A868", "-"), ("B", "Kitsune"): ("#55A868", "--")}
for k in [("A", "HorusEye"), ("A", "Kitsune"), ("B", "HorusEye"), ("B", "Kitsune")]:
    ax.plot(GRID, curves[k], color=sty[k][0], ls=sty[k][1], lw=1.6,
            label="%s, %s corpus" % (k[1], "proprietary" if k[0] == "A" else "open-source"))
for x in (5e-5, 5e-4):
    ax.axvline(x, color="grey", lw=0.8, ls=":")
ax.set_xscale("log")
ax.set_xlim(1e-5, 1e-2)
ax.set_ylim(0, 1)
ax.set_xlabel("False-positive rate (log)")
ax.set_ylabel("Macro TPR (16 attacks)")
ax.legend(fontsize=7, loc="upper left")
fig.tight_layout()
fig.savefig(os.path.join(OUTF, "fig_tpr_fpr.pdf"))
print("wrote outputs/figures/fig_tpr_fpr.pdf")
