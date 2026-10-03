"""Ablation values for fig_ablation_v2 (one row per detector x setup) from the result tables:
HorusEye = B5 (18-epoch models), Kitsune = C3 (+C3b), Isolation Forest / kNN = C4b. No computation."""
import os

import pandas as pd

T = os.path.join(os.path.dirname(os.path.abspath(__file__)), "..", "..", "results", "tables")
COND = ["all14", "vol_match", "cam8", "gw6", "rand5_a", "rand5_b", "os_days1", "os_days2", "os_days3", "os_days5"]


def load():
    rows = []
    b5 = pd.read_csv(os.path.join(T, "B5_ablation.csv"))
    for _, r in b5[(b5.model == "HorusEye") & b5.subset.isin(COND)].drop_duplicates("subset", keep="first").iterrows():
        rows.append(("HorusEye", r.subset, r.macro_tpr_5e5, r.macro_roc_auc, r.n_benign_test))
    for f in ("B8_C3.csv", "B8_C4b.csv"):
        d = pd.read_csv(os.path.join(T, f))
        for _, r in d[d.condition.isin(COND)].iterrows():
            rows.append((r.detector, r.condition, r.macro_tpr_5e5, r.macro_roc_auc, r.n_benign_test))
    return pd.DataFrame(rows, columns=["detector", "condition", "macro_tpr_5e5", "macro_roc_auc", "n_benign_test"])
