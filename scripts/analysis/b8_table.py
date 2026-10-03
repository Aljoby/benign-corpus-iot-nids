"""Builds the B8 summary table (rows = conditions, columns = detectors): 'TPR / ROC-AUC (≤k FP)'. Writes B8_summary_table.md/.csv."""
import math
import os

import numpy as np
import pandas as pd

T = os.path.join(os.path.dirname(os.path.abspath(__file__)), "..", "..", "outputs")


def rd(f):
    p = os.path.join(T, f)
    return pd.read_csv(p) if os.path.exists(p) else pd.DataFrame()


rows = []  # (condition, detector, tpr, roc, n_benign, source)
b1 = rd("B1_repro.csv")
for run, cond, det in (("R1_A_HE", "full proprietary (released models)", "HorusEye"), ("R4_A_KIT", "full proprietary (released models)", "Kitsune"),
                       ("R5_B_HE", "full open-source (released models)", "HorusEye"), ("R8_B_KIT", "full open-source (released models)", "Kitsune")):
    d = b1[(b1.run == run) & (b1.attack != "http_ddos")]
    rows.append((cond, det, d.tpr_5e5.mean(), d.roc_auc.mean(), int(d.n_benign.iloc[0]), "B1"))
b5 = rd("B5_ablation.csv")
for _, r in b5[b5.model == "HorusEye"].drop_duplicates("subset", keep="first").iterrows():
    rows.append((r.subset, "HorusEye (18 ep)", r.macro_tpr_5e5, r.macro_roc_auc, r.n_benign_test, "B5"))
for f, det_fn, src in (("B8_G1.csv", lambda r: r.detector + " (18 ep)", "G1"), ("B8_G4.csv", lambda r: r.detector + " (20 ep)", "G4"),
                       ("B8_G5.csv", lambda r: r.detector + " (18 ep)", "G5"), ("B8_G3.csv", lambda r: r.detector + " (20 ep, benign-only sel.)", "G3"),
                       ("B8_C3.csv", lambda r: r.detector, "C3"), ("B8_C4a.csv", lambda r: r.detector, "C4a"),
                       ("B8_C4b.csv", lambda r: r.detector, "C4b"), ("B8_C5.csv", lambda r: r.detector, "C5")):
    d = rd(f)
    for _, r in d.iterrows():
        if src == "G1" and r.detector != "HorusEye":
            continue
        if src in ("G4", "G5", "G3") and r.detector != "HorusEye":
            continue
        cond = r.condition
        if src == "G1":
            cond = cond if "test=" in cond else cond
        rows.append((cond, det_fn(r), r.macro_tpr_5e5, r.macro_roc_auc, int(r.n_benign_test), src + (" PARTIAL" if str(r.get("status", "ok")) == "PARTIAL" else "")))
D = pd.DataFrame(rows, columns=["condition", "detector", "macro_tpr_5e5", "macro_roc_auc", "n_benign_test", "source"])
D["max_fp"] = [int(math.floor((5e-5 + 1e-6) * n)) for n in D.n_benign_test]
D = D.drop_duplicates(["condition", "detector"], keep="first")
D.to_csv(os.path.join(T, "B8_summary_table.csv"), index=False)
cols = ["HorusEye", "HorusEye (18 ep)", "HorusEye (20 ep)", "HorusEye (20 ep, benign-only sel.)", "Kitsune", "IsolationForest", "kNN"]
order = ["full proprietary (released models)", "full open-source (released models)", "full_proprietary", "full_open-source",
         "all14", "all14_seed1", "all14_seed2", "vol_match", "cam8", "gw6", "rand5_a", "rand5_b"] + \
        ["rand5_seed%d" % s for s in range(2, 7)] + ["prop_files1", "prop_files2", "prop_files3",
         "train=all14, test=gw6_test", "train=gw6, test=all14_test", "train=all14, test=all14_test", "train=gw6, test=gw6_test",
         "os_days1", "os_days2", "os_days3", "os_days5", "open_full", "open_25pct", "open_50pct", "open_devhalf_A", "open_devhalf_B",
         "train=all14, test=gw6_test"]
conds = [c for c in dict.fromkeys(order) if c in set(D.condition)] + sorted(set(D.condition) - set(order))
L = ["| Condition | max FP | " + " | ".join(cols) + " |", "|---|---|" + "---|" * len(cols)]
for cnd in conds:
    s = D[D.condition == cnd]
    cells = []
    for col in cols:
        x = s[s.detector == col]
        cells.append("%.3f / %.3f" % (x.macro_tpr_5e5.iloc[0], x.macro_roc_auc.iloc[0]) if len(x) else "–")
    L.append("| %s | ≤%d | %s |" % (cnd, s.max_fp.iloc[0], " | ".join(cells)))
open(os.path.join(T, "B8_summary_table.md"), "w").write(
    "Cells: macro TPR@5e-5 / macro ROC-AUC over the 16 new attacks; max FP = false positives allowed at FPR≤5e-5 for that "
    "condition's benign test set. '–' = not run.\n\n" + "\n".join(L) + "\n")
print("\n".join(L))
