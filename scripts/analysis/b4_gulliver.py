"""B4: Gulliver retrained (original hyper-parameters) + seed spread; Magnifier = artifact model of that corpus.

Training replicates control_plane.py TRAIN mode: burst training rows (proprietary idx 0-3 of 14 devices /
open-source files 0,2,4,6,7), train_test_split(0.2, random_state=20), iForest_detect.train('all', ['pk_num',
'sum_len'], train, eval, HTTP-DDoS burst rows). HTTP DDoS is the validation attack in the original code (kept).
Seeds: the iForest random_state (original 114514) is replaced by each seed via a wrapper; rules go to a separate
work dir per (corpus, seed). 114514 is included as a check that retraining reproduces the artifact rules.
Outputs: B4_gulliver.csv, B4_summary.md
"""
import functools
import hashlib
import os
import sys
import time

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
import hekit as hk  # noqa: E402
import numpy as np  # noqa: E402
import pandas as pd  # noqa: E402
from sklearn.ensemble import IsolationForest  # noqa: E402

T = os.path.abspath(hk.OUTPUTS)
SEEDS = [114514, 0, 1, 2, 3, 4]


def md5(p):
    return hashlib.md5(open(p, "rb").read()).hexdigest()


def main():
    hk.workdir("b4_common")
    attack_eval_data = hk.load_iot_attack(attack_name='http_ddos', thr_time=1)
    attacks = hk.load_attacks()
    art = {f: md5(os.path.join(hk.RUN_REL, "result", f)) for f in
           ["tcp_rule_all.csv", "udp_rule_all.csv", "tcp_port_rule_all.csv", "udp_port_rule_all.csv"]}
    rows = []
    for corpus in ("A", "B"):
        _, data_tr = hk.load_benign_train(corpus)
        tr, ev = hk.train_test_split(data_tr, test_size=0.2, random_state=20)
        con_b, data_b = hk.load_benign_test(corpus)
        sc = hk.artifact_scorer("mag", corpus)
        for seed in SEEDS:
            t0 = time.time()
            try:
                hk.workdir("b4_%s_seed%d" % (corpus, seed), rules_from=None)
                hk.iForest_detect.IsolationForest = functools.partial(_iforest, seed=seed)
                hk.iForest_detect.train('all', hk.FEATURE_SET, tr, ev, attack_eval_data)
                hk.iForest_detect.IsolationForest = IsolationForest
                same = all(md5(os.path.join("result", f)) == h for f, h in art.items())
                m, _ = hk.evaluate(con_b, data_b, attacks, sc, True, tag="B4 %s s%d" % (corpus, seed))
                rec = {"corpus": corpus, "gulliver_train_corpus": corpus, "seed": seed,
                       "rules_identical_to_artifact": same,
                       "n_rules": {f: sum(1 for _ in open(os.path.join("result", f))) - 1 for f in art},
                       "passed_benign": int(m.n_passed_benign.iloc[0]), "n_benign": int(m.n_benign.iloc[0]),
                       "macro_tpr_5e5": hk.macro(m, "tpr_5e5"), "macro_tpr_5e4": hk.macro(m, "tpr_5e4"),
                       "macro_roc_auc": hk.macro(m, "roc_auc"), "macro_pr_auc": hk.macro(m, "pr_auc"),
                       "minutes": round((time.time() - t0) / 60, 1)}
                for _, x in m.iterrows():
                    rec["tpr_5e5:" + x.attack] = x.tpr_5e5
                rows.append(rec)
                hk.log("B4", corpus, seed, "macro tpr %.4f roc %.4f same_as_artifact=%s" % (rec["macro_tpr_5e5"], rec["macro_roc_auc"], same))
            except Exception as e:
                hk.iForest_detect.IsolationForest = IsolationForest
                hk.log("ERROR B4", corpus, seed, repr(e))
            pd.DataFrame(rows).to_csv(os.path.join(T, "B4_gulliver.csv"), index=False)
    df = pd.DataFrame(rows)
    b1 = pd.read_csv(os.path.join(T, "B1_repro.csv"))
    ref = {c: (hk.macro(b1[b1.run == r], "tpr_5e5"), hk.macro(b1[b1.run == r], "roc_auc"))
           for c, r in (("A", "R1_A_HE"), ("B", "R5_B_HE"))}
    L = ["# B4 — Gulliver retrained and seed spread", "",
         "Magnifier fixed to the artifact model of each corpus; Gulliver retrained with the original hyper-parameters "
         "(iForest 200 trees, max_samples 5000, contamination 0.15 / 0.05 ports) on that corpus's burst training rows. "
         "HTTP DDoS is the Gulliver validation attack in the original code and was kept. Macro over the 16 new attacks.", "",
         "Artifact reference (proprietary-trained rules, both corpora): proprietary macro TPR %.4f / ROC-AUC %.4f; "
         "open-source %.4f / %.4f." % (ref["A"][0], ref["A"][1], ref["B"][0], ref["B"][1]), "",
         "| Corpus | seed | rules = artifact? | passed benign | macro TPR@5e-5 | macro ROC-AUC |", "|---|---|---|---|---|---|"]
    for _, r in df.iterrows():
        L.append("| %s | %d | %s | %d / %d | %.4f | %.4f |" % ("proprietary" if r.corpus == "A" else "open-source", r.seed,
                 r.rules_identical_to_artifact, r.passed_benign, r.n_benign, r.macro_tpr_5e5, r.macro_roc_auc))
    L.append("")
    for c in ("A", "B"):
        s = df[(df.corpus == c) & (df.seed != 114514)]
        if len(s):
            L.append("%s, seeds 0-4 (n=%d): macro TPR@5e-5 %.4f ± %.4f (sd), range %.4f–%.4f; macro ROC-AUC %.4f ± %.4f." % (
                "proprietary" if c == "A" else "open-source", len(s), s.macro_tpr_5e5.mean(), s.macro_tpr_5e5.std(ddof=1),
                s.macro_tpr_5e5.min(), s.macro_tpr_5e5.max(), s.macro_roc_auc.mean(), s.macro_roc_auc.std(ddof=1)))
    open(os.path.join(T, "B4_summary.md"), "w").write("\n".join(L) + "\n")
    hk.log("wrote B4_gulliver.csv, B4_summary.md")


def _iforest(*a, seed, **k):
    k["random_state"] = seed
    return IsolationForest(*a, **k)


if __name__ == "__main__":
    main()
