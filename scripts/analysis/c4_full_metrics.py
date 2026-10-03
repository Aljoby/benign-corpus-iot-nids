"""Full per-attack metrics of the two training-free reference detectors on the full corpora (same models and
protocol as C4a: Isolation Forest 100 trees / 256 samples / seed 0; kNN k=5, 100,000 reference rows, seed 0;
MinMax on the 80 % training split). Adds TPR at 5e-4, PR-AUC, thresholds and FP counts that C4a did not store, plus
the oracle cut (k+1-th highest benign test score). Checks that TPR@5e-5 and ROC-AUC equal B8_C4a.csv.
Outputs: outputs/C4_per_attack_full.csv, outputs/C4_oracle_cuts.csv"""
import math
import os
import sys

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
import b5_ablation as b5  # noqa: E402
import hekit as hk  # noqa: E402
import numpy as np  # noqa: E402
import pandas as pd  # noqa: E402

T = os.path.abspath(hk.OUTPUTS)
hk.workdir("c4_full")
attacks = hk.load_attacks()
rows, cuts = [], []
for corpus in ("A", "B"):
    con = b5.proprietary_train(b5.ALL14)[0] if corpus == "A" else hk.load_benign_train("B")[0]
    tr, _ = hk.train_test_split(con, test_size=0.2, random_state=20)
    con_b, data_b = hk.load_benign_test(corpus)
    for dn, D in (("IsolationForest", hk.IFScorer), ("kNN", hk.KNNScorer)):
        m, r = hk.evaluate(con_b, data_b, attacks, D(tr), False, keep_rows=True, tag="C4full %s %s" % (corpus, dn))
        m.insert(0, "detector", dn)
        m.insert(1, "corpus", "proprietary" if corpus == "A" else "open-source")
        rows.append(m)
        ben = np.sort(r[(r.attack == hk.ATTACKS[0]) & (r.label == 0)].score.values)[::-1]
        for fpr in (5e-5, 5e-4):
            k = int(math.floor((fpr + 1e-6) * len(ben)))
            cuts.append({"detector": dn, "corpus": "proprietary" if corpus == "A" else "open-source", "fpr_target": fpr,
                         "max_fp": k, "n_benign_test": len(ben), "oracle_cut": float(ben[k])})
M = pd.concat(rows, ignore_index=True)
M.to_csv(os.path.join(T, "C4_per_attack_full.csv"), index=False)
pd.DataFrame(cuts).to_csv(os.path.join(T, "C4_oracle_cuts.csv"), index=False)
ref = pd.read_csv(os.path.join(hk.OUTPUTS, "..", "results", "tables", "B8_C4a.csv"))
worst = 0.0
for _, x in M.iterrows():
    rr = ref[(ref.detector == x.detector) & (ref.condition == ("full_proprietary" if x.corpus == "proprietary" else "full_open-source"))].iloc[0]
    worst = max(worst, abs(rr["tpr_5e5:" + x.attack] - x.tpr_5e5), abs(rr["roc_auc:" + x.attack] - x.roc_auc))
hk.log("CHECK vs B8_C4a.csv: max |diff| TPR@5e-5 / ROC-AUC = %.2e" % worst)
