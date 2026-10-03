"""C1: macro TPR vs FPR (16 new attacks) from the saved per-row scores of R1/R4/R5/R8 (B1 rows).
TPR at FPR<=x = the artifact rule (last ROC point with FPR <= x + 1e-6), evaluated on a log grid 1e-5..1e-2.
Outputs: fig_tpr_fpr.pdf, B8_C1_curves.csv (grid), B8_C1_points.csv (corpus effect / architecture gap at 6 FPRs)."""
import math
import os
import sys

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
import b8common as c  # noqa: E402
import hekit as hk  # noqa: E402
import numpy as np  # noqa: E402
import pandas as pd  # noqa: E402
from sklearn.metrics import roc_curve  # noqa: E402

RUNS = {("A", "HorusEye"): "R1_A_HE", ("A", "Kitsune"): "R4_A_KIT", ("B", "HorusEye"): "R5_B_HE", ("B", "Kitsune"): "R8_B_KIT"}
GRID = np.unique(np.r_[np.logspace(-5, -2, 61), [1e-5, 5e-5, 1e-4, 5e-4, 1e-3, 1e-2]])
PTS = [1e-5, 5e-5, 1e-4, 5e-4, 1e-3, 1e-2]


def tpr_at(fpr, tpr, x):
    ok = np.nonzero(fpr <= x + 1e-6)[0]
    return tpr[ok[-1]] if len(ok) else 0.0


curves, nb = {}, {}
for (corpus, det), run in RUNS.items():
    r = pd.read_pickle(os.path.join(c.T, "rows", run + ".pkl"))
    per = []
    for a in hk.NEW16:
        ra = r[r.attack == a]
        f, t, _ = roc_curve(ra.label.values, ra.score.values)
        per.append([tpr_at(f, t, x) for x in GRID])
        nb[corpus] = int((ra.label == 0).sum())
    curves[(corpus, det)] = np.mean(per, axis=0)
    hk.log("C1", corpus, det, "macro TPR at 5e-5 = %.4f" % curves[(corpus, det)][list(GRID).index(5e-5)])
pd.DataFrame({"fpr": GRID, **{"%s_%s" % k: v for k, v in curves.items()}}).to_csv(os.path.join(c.T, "B8_C1_curves.csv"), index=False)
rows = []
for x in PTS:
    i = list(GRID).index(x)
    v = {k: curves[k][i] for k in curves}
    rows.append({"fpr": x, "max_fp_prop": int(math.floor((x + 1e-6) * nb["A"])), "max_fp_open": int(math.floor((x + 1e-6) * nb["B"])),
                 "HE_prop": v[("A", "HorusEye")], "HE_open": v[("B", "HorusEye")], "Kit_prop": v[("A", "Kitsune")], "Kit_open": v[("B", "Kitsune")],
                 "corpus_effect_HE": v[("B", "HorusEye")] - v[("A", "HorusEye")], "corpus_effect_Kit": v[("B", "Kitsune")] - v[("A", "Kitsune")],
                 "arch_gap_prop": v[("A", "HorusEye")] - v[("A", "Kitsune")], "arch_gap_open": v[("B", "HorusEye")] - v[("B", "Kitsune")]})
P = pd.DataFrame(rows)
P.to_csv(os.path.join(c.T, "B8_C1_points.csv"), index=False)
import matplotlib  # noqa: E402
matplotlib.use("Agg")
import matplotlib.pyplot as plt  # noqa: E402
fig, ax = plt.subplots(figsize=(5.2, 3.6))
sty = {("A", "HorusEye"): ("#4C72B0", "-"), ("A", "Kitsune"): ("#4C72B0", "--"), ("B", "HorusEye"): ("#55A868", "-"), ("B", "Kitsune"): ("#55A868", "--")}
for k, v in curves.items():
    ax.plot(GRID, v, color=sty[k][0], ls=sty[k][1], lw=1.6,
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
fig.savefig(os.path.join(c.T, "fig_tpr_fpr.pdf"))
c.note("C1", "C1 corpus effect / architecture gap by FPR:\n" + P.round(4).to_string(index=False))
hk.log("C1 done")
