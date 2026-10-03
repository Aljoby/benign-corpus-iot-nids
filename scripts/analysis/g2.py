"""G2: which devices produce the highest-scoring benign test packets (the ones that set the low-FPR threshold)?
Benign proprietary test set (all 14 devices, same 10 % sample as R1) with device labels; scores of
R1 (artifact HorusEye), R4 (artifact Kitsune), all14-retrained HorusEye and gw6-retrained HorusEye (B5).
Top 7 (= FPR 5e-5 limit), top 78 (= 5e-4), top 0.1 %. Counts per device and per type vs type share."""
import math
import os
import sys

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
import b8common as c  # noqa: E402
import hekit as hk  # noqa: E402
import numpy as np  # noqa: E402
import pandas as pd  # noqa: E402

c.enter("b1")
con_b, data_b, dev = hk.load_benign_test_dev()
attacks = hk.load_attacks(["Okiru"])          # one attack is enough: the benign rows in the ROC are the same for all
models = [("R1 artifact HorusEye", "b1", "art_mag", True), ("R4 artifact Kitsune", "b1", "art_kit", False),
          ("all14 retrained HorusEye (B5)", "b5_all14", "own", True), ("gw6 retrained HorusEye (B5)", "b5_gw6", "own", True)]
rows, share_rows = [], []
for name, wd, kind, g in models:
    c.enter(wd)
    if kind == "art_mag":
        sc = hk.artifact_scorer("mag", "A")
    elif kind == "art_kit":
        sc = hk.artifact_scorer("kit", "A")
    else:
        sc = hk.MagScorer(os.path.join("params", "CNN_DW_dilation_channel_port.pkl"), os.path.join("params", "scaler.pkl"))
    _, r = hk.evaluate(con_b, data_b, attacks, sc, g, keep_rows=True, tag="G2 " + name)
    b = r[r.label == 0].copy()
    b["device"] = dev[b.rid.values]
    b["type"] = [hk.dev_type(d) for d in b.device]
    nb = len(b)
    if name.startswith("R1"):
        hk.log("check: benign rows in ROC = %d (R1: 156505)" % nb)
    share = b.type.value_counts(normalize=True)
    b = b.sort_values("score", ascending=False)
    for tag, k in (("top7", 7), ("top78", 78), ("top0.1pct", int(math.ceil(0.001 * nb)))):
        top = b.head(k)
        tc = top.type.value_counts()
        for t in ("camera", "gateway", "router"):
            share_rows.append({"model": name, "top": tag, "k": k, "type": t, "count": int(tc.get(t, 0)),
                               "share_in_top": float(tc.get(t, 0)) / k, "share_of_all_benign": float(share.get(t, 0))})
        for d, n in top.device.value_counts().items():
            rows.append({"model": name, "top": tag, "k": k, "device": d, "type": hk.dev_type(d), "count": int(n),
                         "device_share_of_all_benign": float((b.device == d).mean())})
        hk.log("G2", name, tag, dict(tc))
pd.DataFrame(rows).to_csv(os.path.join(c.T, "B8_G2_tail_devices.csv"), index=False)
S = pd.DataFrame(share_rows)
S.to_csv(os.path.join(c.T, "B8_G2_tail_types.csv"), index=False)
L = ["# G2 — device attribution of the highest-scoring benign test packets (proprietary corpus)", "",
     "Benign test packets entering the ROC: %d. Type shares of all benign test packets are given in brackets." % nb, ""]
for name in S.model.unique():
    L.append("**%s**" % name)
    for tag in ("top7", "top78", "top0.1pct"):
        s = S[(S.model == name) & (S.top == tag)]
        L.append("- %s (k=%d): " % (tag, s.k.iloc[0]) + ", ".join(
            "%s %d (%.0f%% vs %.0f%% of all)" % (t, n, 100 * st, 100 * sa) for t, n, st, sa in
            zip(s.type, s["count"], s.share_in_top, s.share_of_all_benign)))
    L.append("")
open(os.path.join(c.T, "B8_G2_summary.md"), "w").write("\n".join(L) + "\n")
hk.log("G2 done")
