"""C4: reference detectors on the same scaled packet features as Magnifier (100 statistics + 2 ports, MinMax fit on
the 80 % training split = train_test_split(0.2, random_state=20) of each training set).
 - Isolation Forest: n_estimators=100, max_samples=256, random_state=0.
 - kNN: k=5, Euclidean, reference = 100,000 random training rows (seed 0) or all; score = distance to the 5th neighbour.
(a) full corpora: 16 attacks; benign-only calibration (tau = (1-5e-5) / (1-5e-4) quantile of the 20 % validation split);
    cross-corpus transfer FPR (other corpus's benign test rows, own scaler).
(b) ablation subsets all14 (= a), vol_match, cam8, gw6, rand5_a, rand5_b, open-source 1/2/3/5 days (5 = a),
    plus the gateway cross-test. Standalone (no Gulliver), same test protocol as B5."""
import os
import sys

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
import b8common as c  # noqa: E402
import hekit as hk  # noqa: E402
import b5_ablation as b5  # noqa: E402
import numpy as np  # noqa: E402
import pandas as pd  # noqa: E402

c.enter("b5_common")
attacks = hk.load_attacks()
DET = {"IsolationForest": hk.IFScorer, "kNN": hk.KNNScorer}
tests = {"A": hk.load_benign_test("A"), "B": hk.load_benign_test("B")}


def split(con):
    tr, ev = hk.train_test_split(con, test_size=0.2, random_state=20)
    return tr, ev


# ---------------- (a) full corpora
models = {}
cal = []
for corpus in ("A", "B"):
    con = b5.proprietary_train(b5.ALL14)[0] if corpus == "A" else hk.load_benign_train("B")[0]
    tr, ev = split(con)
    for dn, D in DET.items():
        if c.over_box(5):
            c.note("C4", "C4a %s %s SKIPPED (box)" % (corpus, dn)); continue
        try:
            sc = D(tr)
            models[(corpus, dn)] = sc
            m, rows = hk.evaluate(*tests[corpus], attacks, sc, False, keep_rows=True, tag="C4a %s %s" % (corpus, dn))
            c.record("C4a", "full_%s" % ("proprietary" if corpus == "A" else "open-source"), dn, m,
                     {"corpus": corpus, "n_train_rows_80pct": len(tr)})
            v = sc.score(ev)
            other = "B" if corpus == "A" else "A"
            con_o, data_o = tests[other]
            t = sc.score(hk.iForest_detect.filter(data_o.dropna(), con_o.reset_index(drop=True)))
            ben = rows[(rows.attack == hk.ATTACKS[0]) & (rows.label == 0)].score.values
            for kname, q in (("calib_5e5", 1 - 5e-5), ("calib_5e4", 1 - 5e-4)):
                tau = float(np.quantile(v, q))
                tprs = [float((rows[(rows.attack == a) & (rows.label == 1)].score >= tau).mean()) for a in hk.NEW16]
                cal.append({"detector": dn, "corpus_train": corpus, "tau_kind": kname, "tau": tau,
                            "fpr_own_test": float((ben >= tau).mean()), "n_fp_own": int((ben >= tau).sum()), "n_benign_own": len(ben),
                            "macro_tpr_calibrated": float(np.mean(tprs)),
                            "fpr_transfer_other_corpus": float((t >= tau).mean()), "n_fp_transfer": int((t >= tau).sum()),
                            "n_benign_other": len(t)})
            pd.DataFrame(cal).to_csv(os.path.join(c.T, "B8_C4a_calibration.csv"), index=False)
            hk.log("C4a calib", corpus, dn, cal[-2])
        except Exception as e:
            import traceback
            traceback.print_exc()
            c.note("C4", "C4a %s %s ERROR %r" % (corpus, dn, e))

# ---------------- (b) ablation subsets
subs = ["vol_match", "cam8", "gw6", "rand5_a", "rand5_b", "os_days1", "os_days2", "os_days3"]
gw_models = {}
for n in ["all14"] + subs + ["os_days5"]:
    corpus = b5.SUBSETS[n][0]
    for dn, D in DET.items():
        if c.over_box(4):
            c.note("C4", "C4b %s %s SKIPPED (box)" % (n, dn)); continue
        try:
            if n in ("all14", "os_days5"):
                sc = models[("A" if n == "all14" else "B", dn)]
                devs = b5.ALL14 if n == "all14" else None
            else:
                if corpus == "A":
                    if n == "vol_match":
                        con, _, devs, _ = b5.vol_match(20)
                    else:
                        con, _, devs = b5.proprietary_train(b5.SUBSETS[n][1])
                else:
                    con, devs = hk.load_benign_train("B", os_files=b5.SUBSETS[n][1])[0], None
                sc = D(split(con)[0])
            if n in ("all14", "gw6"):
                gw_models[(n, dn)] = sc
            con_b, data_b = hk.load_benign_test(corpus, devices=devs if corpus == "A" else None)
            m, _ = hk.evaluate(con_b, data_b, attacks, sc, False, tag="C4b %s %s" % (n, dn))
            c.record("C4b", n, dn, m, {"corpus": corpus})
        except Exception as e:
            import traceback
            traceback.print_exc()
            c.note("C4", "C4b %s %s ERROR %r" % (n, dn, e))
for tr_n, te_devs, te_name in (("all14", hk.GW, "gw6_test"), ("gw6", None, "all14_test")):
    for dn in DET:
        if (tr_n, dn) in gw_models and not c.over_box(2):
            con_b, data_b = hk.load_benign_test("A", devices=te_devs)
            m, _ = hk.evaluate(con_b, data_b, attacks, gw_models[(tr_n, dn)], False, tag="C4b cross %s %s" % (tr_n, dn))
            c.record("C4b", "train=%s, test=%s" % (tr_n, te_name), dn, m, {"train": tr_n, "test": te_name})
        else:
            c.note("C4", "C4b cross-test %s %s SKIPPED" % (tr_n, dn))
hk.log("C4 done")
