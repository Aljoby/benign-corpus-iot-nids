"""C3b: complete the Kitsune ablation (same protocol as C3: KitNET, original hyper-parameters, one pass on the 80 %
training split, standalone, tested on the benign test data of the same devices / standard open-source test days + all
attacks). Setups missing from C3: rand5_b, os_days1, os_days2, os_days3, os_days5. os_days5 = the released Kitsune's
training data, so it should reproduce R8 exactly (check)."""
import os
import sys

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
import b8common as c  # noqa: E402
import hekit as hk  # noqa: E402
import b5_ablation as b5  # noqa: E402
import pandas as pd  # noqa: E402

c.enter("b5_common")
attacks = hk.load_attacks()
for n in ("rand5_b", "os_days1", "os_days2", "os_days3", "os_days5"):
    try:
        corpus, spec, _, _ = b5.SUBSETS[n]
        if corpus == "A":
            con, _, devs = b5.proprietary_train(spec)
            con_b, data_b = hk.load_benign_test("A", devices=devs)
            dev_txt = ";".join(devs)
        else:
            con = hk.load_benign_train("B", os_files=spec)[0]
            con_b, data_b = hk.load_benign_test("B")
            dev_txt = "os_files_" + ",".join(map(str, spec))
        K, scaler, n_tr, sec = hk.train_kitsune(con)
        m, _ = hk.evaluate(con_b, data_b, attacks, hk.KitTrainedScorer(K, scaler), False, tag="C3b " + n)
        c.record("C3", n, "Kitsune", m, {"devices": dev_txt, "n_train_rows": len(con), "n_train_rows_80pct": n_tr,
                                         "train_minutes": round(sec / 60, 1), "run": "C3b"})
    except Exception as e:
        import traceback
        traceback.print_exc()
        c.note("C3", "C3b %s ERROR %r" % (n, e))
# check: os_days5 vs released Kitsune (R8)
d = pd.read_csv(os.path.join(c.T, "B8_C3.csv"))
r = d[d.condition == "os_days5"]
b1 = pd.read_csv(os.path.join(c.T, "B1_repro.csv"))
r8 = b1[(b1.run == "R8_B_KIT") & (b1.attack != "http_ddos")]
if len(r):
    hk.log("CHECK os_days5 retrained vs released R8: macro TPR %.6f vs %.6f, ROC-AUC %.6f vs %.6f" % (
        r.macro_tpr_5e5.iloc[0], r8.tpr_5e5.mean(), r.macro_roc_auc.iloc[0], r8.roc_auc.mean()))
hk.log("C3b done")
