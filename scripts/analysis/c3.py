"""C3: Kitsune ablation. KitNET with the original hyper-parameters (maxAE 20, FMgrace 5000, one pass), one run each,
on all14, gw6, cam8, vol_match, rand5_a (drop from the end if time is short); test = benign test of the same devices +
all attacks (standalone Kitsune, ports dropped as in KITSUNE mode). Then the gateway cross-test (as G1)."""
import os
import sys
import time

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
import b8common as c  # noqa: E402
import hekit as hk  # noqa: E402
import b5_ablation as b5  # noqa: E402
import Kitsune.KitNET as kit  # noqa: E402
import numpy as np  # noqa: E402
from sklearn import preprocessing  # noqa: E402

c.enter("b5_common")
attacks = hk.load_attacks()
order = ["all14", "gw6", "cam8", "vol_match", "rand5_a"]
data = {}
for n in order:
    if n == "vol_match":
        con, _, devs, _ = b5.vol_match(20)
    else:
        con, _, devs = b5.proprietary_train(b5.SUBSETS[n][1])
    data[n] = (con, devs)

# timing: train KitNET on the first 20,000 rows of the all14 training split
con = data["all14"][0].drop(columns=[1, 2])
tr, _ = hk.train_test_split(con, test_size=0.2, random_state=20)
X = preprocessing.MinMaxScaler().fit_transform(tr.drop(columns=[0, "class"]).values[:200000])[:20000]
K = kit.KitNET(X.shape[1], 20, 5000, 10 ** 9)
t0 = time.time()
for i in range(len(X)):
    K.process(X[i, ], changeState=(i == 0))
rate = len(X) / (time.time() - t0)
est = {n: 0.8 * len(data[n][0]) / rate / 60 + 2.5 for n in order}      # + ~2.5 min evaluation
c.note("C3", "C3 timing: KitNET training %.0f rows/s on CPU -> estimated minutes per model incl. evaluation: %s" % (
    rate, {k: round(v, 1) for k, v in est.items()}))
models = {}
for n in order:
    left = c.minutes_left()
    if est[n] > left - 8:
        c.note("C3", "C3 %s SKIPPED: estimated %.0f min > %.0f min left in the box" % (n, est[n], left))
        continue
    try:
        con, devs = data[n]
        K, scaler, n_tr, sec = hk.train_kitsune(con)
        models[n] = (K, scaler, devs)
        con_b, data_b = hk.load_benign_test("A", devices=devs)
        m, _ = hk.evaluate(con_b, data_b, attacks, hk.KitTrainedScorer(K, scaler), False, tag="C3 " + n)
        c.record("C3", n, "Kitsune", m, {"devices": ";".join(devs), "n_train_rows": len(con), "n_train_rows_80pct": n_tr,
                                         "train_minutes": round(sec / 60, 1)})
    except Exception as e:
        import traceback
        traceback.print_exc()
        c.note("C3", "C3 %s ERROR %r" % (n, e))
# gateway cross-test
for tr_n, te_devs, te_name in (("all14", hk.GW, "gw6_test"), ("gw6", None, "all14_test")):
    if tr_n in models and c.minutes_left() > 4:
        K, scaler, _ = models[tr_n]
        con_b, data_b = hk.load_benign_test("A", devices=te_devs)
        m, _ = hk.evaluate(con_b, data_b, attacks, hk.KitTrainedScorer(K, scaler), False, tag="C3 cross " + tr_n)
        c.record("C3", "train=%s, test=%s" % (tr_n, te_name), "Kitsune", m, {"train": tr_n, "test": te_name})
    else:
        c.note("C3", "C3 cross-test train=%s SKIPPED (model missing or no time)" % tr_n)
hk.log("C3 done")
