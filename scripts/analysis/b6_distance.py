"""B6 part 3 only (extra, fills TBD corpus-distance-*): how separable are the two benign training corpora?

Balanced sample of 200k benign training rows per corpus (packet table: 100 statistics; burst table: pk_num,
sum_len, udp_tcp, 16 port bits), 5-fold stratified CV with (a) logistic regression on standardized features and
(b) histogram gradient boosting. Report mean CV ROC-AUC and the top-10 features by |standardized logistic
coefficient| (and by permutation importance of the boosting model on one held-out fold).
Outputs: B6_corpus_distance.csv, B6_summary.md
"""
import os
import sys

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
import hekit as hk  # noqa: E402
import numpy as np  # noqa: E402
import pandas as pd  # noqa: E402
from sklearn.experimental import enable_hist_gradient_boosting  # noqa: E402,F401
from sklearn.ensemble import HistGradientBoostingClassifier  # noqa: E402
from sklearn.inspection import permutation_importance  # noqa: E402
from sklearn.linear_model import LogisticRegression  # noqa: E402
from sklearn.model_selection import StratifiedKFold, cross_val_score  # noqa: E402
from sklearn.pipeline import make_pipeline  # noqa: E402
from sklearn.preprocessing import StandardScaler  # noqa: E402

from b2_calibration import stat_names  # noqa: E402

T = os.path.abspath(hk.OUTPUTS)
N = 200000


def main():
    hk.workdir("b6")
    rs = np.random.RandomState(20)
    sets = {}
    for c in ("A", "B"):
        con, data = hk.load_benign_train(c)
        sets[c] = (con.iloc[rs.choice(len(con), N, replace=False)],
                   data.dropna().iloc[rs.choice(len(data.dropna()), min(N, len(data.dropna())), replace=False)])
        hk.log("corpus", c, "sampled", len(sets[c][0]), len(sets[c][1]))
    burst_cols = ["pk_num", "sum_len", "udp_tcp"] + ["port_%d" % i for i in range(16)]
    feats = {"packet (100 stats)": (list(range(3, 103)), stat_names(), 0),
             "burst (pk_num, sum_len, proto, ports)": (burst_cols, burst_cols, 1)}
    rows, L = [], ["# B6 (part 3 only) — corpus distance between the two benign training corpora", "",
                   "Extra block (not in the requested order) run because two \\TBD keys need it. Balanced %d rows per corpus "
                   "(burst: all available if fewer), 5-fold stratified CV ROC-AUC (1 = perfectly separable)." % N, ""]
    for name, (cols, names, k) in feats.items():
        Xa, Xb = sets["A"][k][cols].values.astype(float), sets["B"][k][cols].values.astype(float)
        n = min(len(Xa), len(Xb))
        X = np.vstack([Xa[:n], Xb[:n]])
        y = np.r_[np.zeros(n), np.ones(n)]
        cv = StratifiedKFold(5, shuffle=True, random_state=20)
        lr = make_pipeline(StandardScaler(), LogisticRegression(max_iter=2000))
        auc_lr = cross_val_score(lr, X, y, cv=cv, scoring="roc_auc", n_jobs=5)
        gb = HistGradientBoostingClassifier(random_state=20)
        auc_gb = cross_val_score(gb, X, y, cv=cv, scoring="roc_auc", n_jobs=5)
        lr.fit(X, y)
        coef = lr[-1].coef_[0]
        top_lr = np.argsort(-np.abs(coef))[:10]
        tr, te = next(cv.split(X, y))
        gb.fit(X[tr], y[tr])
        sub = np.random.RandomState(20).choice(te, min(40000, len(te)), replace=False)  # mixed-class subset of the held-out fold
        pi = permutation_importance(gb, X[sub], y[sub], scoring="roc_auc", n_repeats=3, random_state=20, n_jobs=5)
        top_gb = np.argsort(-pi.importances_mean)[:10]
        rows.append({"features": name, "n_per_corpus": n, "auc_logreg_mean": auc_lr.mean(), "auc_logreg_sd": auc_lr.std(),
                     "auc_gboost_mean": auc_gb.mean(), "auc_gboost_sd": auc_gb.std(),
                     "top10_logreg": "; ".join("%s(%+.2f, %s)" % (names[i], coef[i], "open-source" if coef[i] > 0 else "proprietary") for i in top_lr),
                     "top10_gboost_perm": "; ".join("%s(%.3f)" % (names[i], pi.importances_mean[i]) for i in top_gb)})
        L += ["## %s" % name, "", "- CV ROC-AUC: logistic %.4f ± %.4f; gradient boosting %.4f ± %.4f" % (
            auc_lr.mean(), auc_lr.std(), auc_gb.mean(), auc_gb.std()),
              "- Top-10 (logistic, sign = corpus with larger values): " + rows[-1]["top10_logreg"],
              "- Top-10 (boosting, permutation importance in ROC-AUC): " + rows[-1]["top10_gboost_perm"], ""]
        hk.log(name, "AUC lr %.4f gb %.4f" % (auc_lr.mean(), auc_gb.mean()))
    pd.DataFrame(rows).to_csv(os.path.join(T, "B6_corpus_distance.csv"), index=False)
    open(os.path.join(T, "B6_summary.md"), "w").write("\n".join(L) + "\n")
    hk.log("wrote B6_corpus_distance.csv")


if __name__ == "__main__":
    main()
