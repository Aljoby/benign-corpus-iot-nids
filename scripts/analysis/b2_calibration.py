"""B2: benign-only threshold calibration, cross-corpus transfer, score-distribution figure; B2x: feature overlap.

Calibration: validation split = train_test_split(training rows, test_size=0.2, random_state=20), as in the
artifact's training code (packet table for Magnifier/Kitsune, burst table for Gulliver). HorusEye validation
scores = Magnifier scores with Gulliver-passed rows set to 0 (same as at test time).
tau = (1-5e-5) and (1-5e-4) quantiles of the validation scores; alarm if score >= tau.
Test scores come from outputs/rows/<run>.pkl (B1, identical to the artifact's test scores).
Transfer: each model scores the OTHER corpus's benign test rows (own scaler, same Gulliver rules) -> FPR at own tau.
Outputs: B2_calibration.csv, B2_thresholds.csv, fig_scores.pdf, B2x_overlap.csv
"""
import os
import sys

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
import hekit as hk  # noqa: E402
import numpy as np  # noqa: E402
import pandas as pd  # noqa: E402
from scipy.stats import ks_2samp  # noqa: E402

T = os.path.abspath(hk.OUTPUTS)
MODELS = {"HorusEye": ("mag", True, {"A": "R1_A_HE", "B": "R5_B_HE"}),
          "Magnifier": ("mag", False, {"A": "R2_A_MAG", "B": "R6_B_MAG"}),
          "Kitsune": ("kit", False, {"A": "R4_A_KIT", "B": "R8_B_KIT"})}
QS = {"calib_5e5": 1 - 5e-5, "calib_5e4": 1 - 5e-4}


def stat_names():
    lam = ["5", "3", "1", "0.1", "0.01"]
    names = []
    for w in range(5):
        names += ["MI_l%s_%s" % (lam[w], s) for s in ("w", "mean", "std")]
    hh = ("w", "mean", "std", "mag", "rad", "cov", "pcc")
    for w in range(5):
        names += ["HH_l%s_%s" % (lam[w], s) for s in hh]
    for w in range(5):
        names += ["HHjit_l%s_%s" % (lam[w], s) for s in ("w", "mean", "std")]
    for w in range(5):
        names += ["HpHp_l%s_%s" % (lam[w], s) for s in hh]
    return names  # 100 names for CSV columns 3..102 (netStat order)


def main():
    hk.workdir("b2")
    rows_out, thr_out = [], []
    test = {}
    for corpus in ("A", "B"):
        test[corpus] = hk.load_benign_test(corpus)
    for corpus in ("A", "B"):
        con_tr, data_tr = hk.load_benign_train(corpus)
        _, ev_con = hk.train_test_split(con_tr, test_size=0.2, random_state=20)
        _, ev_data = hk.train_test_split(data_tr, test_size=0.2, random_state=20)
        del con_tr, data_tr
        hk.log("corpus", corpus, "validation rows", len(ev_con), "burst", len(ev_data))
        other = "B" if corpus == "A" else "A"
        for model, (kind, g, runs) in MODELS.items():
            sc = hk.artifact_scorer(kind, corpus)
            if g:
                v, _, nv, nsc = hk.gulliver_scores(ev_con, ev_data, sc)
            else:
                v = sc.score(ev_con)
                nv, nsc = len(v), len(v)
            taus = {k: float(np.quantile(v, q)) for k, q in QS.items()}
            r = pd.read_pickle(os.path.join(T, "rows", runs[corpus] + ".pkl"))
            b1 = pd.read_csv(os.path.join(T, "B1_repro.csv"))
            b1 = b1[b1.run == runs[corpus]].set_index("attack")
            for kname, tau in taus.items():
                thr_out.append({"model": model, "corpus_train": corpus, "tau_kind": kname, "tau": tau,
                                "n_validation": nv, "n_validation_scored": nsc})
                ben = r[(r.attack == hk.ATTACKS[0]) & (r.label == 0)].score.values  # benign set (same for all attacks)
                rows_out.append({"model": model, "corpus_train": corpus, "corpus_eval": corpus, "attack": "benign",
                                 "tau_kind": kname, "tau": tau, "fpr_realized": float((ben >= tau).mean()),
                                 "n_fp": int((ben >= tau).sum()), "n_benign": len(ben), "tpr": None})
                for a in hk.ATTACKS:
                    ra = r[r.attack == a]
                    rows_out.append({"model": model, "corpus_train": corpus, "corpus_eval": corpus, "attack": a,
                                     "tau_kind": kname, "tau": tau,
                                     "fpr_realized": float((ra[ra.label == 0].score >= tau).mean()),
                                     "tpr": float((ra[ra.label == 1].score >= tau).mean()),
                                     "tpr_oracle": float(b1.loc[a, "tpr_5e5" if kname.endswith("5e5") else "tpr_5e4"]),
                                     "thr_oracle": float(b1.loc[a, "thr_5e5" if kname.endswith("5e5") else "thr_5e4"])})
            # transfer: other corpus's benign test rows, own scaler / rules
            con_o, data_o = test[other]
            if g:
                t, _, n_o, _ = hk.gulliver_scores(con_o, data_o, sc)
            else:
                t = sc.score(hk.iForest_detect.filter(data_o.dropna(), con_o.reset_index(drop=True)))
                n_o = len(t)
            for kname, tau in taus.items():
                rows_out.append({"model": model, "corpus_train": corpus, "corpus_eval": other, "attack": "benign",
                                 "tau_kind": kname, "tau": tau, "fpr_realized": float((t >= tau).mean()),
                                 "n_fp": int((t >= tau).sum()), "n_benign": n_o, "tpr": None})
            hk.log(model, corpus, "taus", {k: round(x, 4) for k, x in taus.items()})
    out = pd.DataFrame(rows_out)
    out.to_csv(os.path.join(T, "B2_calibration.csv"), index=False)
    pd.DataFrame(thr_out).to_csv(os.path.join(T, "B2_thresholds.csv"), index=False)
    figure(out)
    overlap(test)


def figure(cal):
    import matplotlib
    matplotlib.use("Agg")
    import matplotlib.pyplot as plt
    atts = ["SQL_injection", "Hide_and_seek", "Hakai"]
    fig, axes = plt.subplots(2, 3, figsize=(10, 5.2), sharex=True)
    for i, corpus in enumerate(("A", "B")):
        r = pd.read_pickle(os.path.join(T, "rows", {"A": "R1_A_HE", "B": "R5_B_HE"}[corpus] + ".pkl"))
        b1 = pd.read_csv(os.path.join(T, "B1_repro.csv"))
        b1 = b1[b1.run == {"A": "R1_A_HE", "B": "R5_B_HE"}[corpus]].set_index("attack")
        tau = cal[(cal.model == "HorusEye") & (cal.corpus_train == corpus) & (cal.tau_kind == "calib_5e5")].tau.iloc[0]
        for j, a in enumerate(atts):
            ax = axes[i, j]
            ra = r[r.attack == a]
            bins = np.logspace(-3, 1, 80)
            for lab, col, name in ((0, "#4C72B0", "benign"), (1, "#DD8452", "attack")):
                x = ra[ra.label == lab].score.values
                z = (x <= 0).mean()
                ax.hist(np.clip(x[x > 0], 1e-3, 10), bins=bins, density=True, histtype="step", color=col, lw=1.4,
                        label="%s (%.0f%% at 0)" % (name, 100 * z))
            ben = np.sort(ra[ra.label == 0].score.values)[::-1]
            k = int(np.floor((5e-5 + 1e-6) * len(ben)))      # max benign packets allowed above the cut (7 / 6)
            ax.axvline(ben[k], color="k", ls="--", lw=1, label="oracle cut (%d FPs)" % k)
            ax.axvline(tau, color="#C44E52", ls=":", lw=1.4, label="calibrated τ")
            ax.set_xscale("log")
            ax.set_yscale("log")
            ax.set_title("%s — %s corpus" % (a.replace("_", " "), "proprietary" if corpus == "A" else "open-source"), fontsize=9)
            ax.legend(fontsize=6, loc="upper left")
            if i == 1:
                ax.set_xlabel("HorusEye score (RMSE)")
            if j == 0:
                ax.set_ylabel("density")
    fig.tight_layout()
    fig.savefig(os.path.join(T, "fig_scores.pdf"))
    hk.log("wrote fig_scores.pdf")


def overlap(test):
    names = stat_names()
    atts = ["Hakai", "Torii", "Ransomware", "XSS_attack", "Muhstik", "Hide_and_seek", "SQL_injection", "Okiru"]
    attacks = hk.load_attacks(atts)
    rows = []
    for corpus in ("A", "B"):
        ben = test[corpus][0]
        for a in atts:
            att = attacks[a][0]
            ks = np.array([ks_2samp(att[c].values, ben[c].values).statistic for c in range(3, 103)])
            order = np.argsort(ks)
            rows.append({"attack": a, "benign_corpus": corpus, "n_attack_rows": len(att), "n_benign_rows": len(ben),
                         "ks_median": float(np.median(ks)), "ks_max": float(ks.max()),
                         "frac_features_ks_lt_0.1": float((ks < 0.1).mean()),
                         "frac_features_ks_gt_0.5": float((ks > 0.5).mean()),
                         "top5_separating": "; ".join("%s=%.2f" % (names[k], ks[k]) for k in order[::-1][:5]),
                         "top5_overlapping": "; ".join("%s=%.2f" % (names[k], ks[k]) for k in order[:5])})
            hk.log("KS", a, corpus, "median %.3f max %.3f" % (np.median(ks), ks.max()))
    pd.DataFrame(rows).to_csv(os.path.join(T, "B2x_overlap.csv"), index=False)


if __name__ == "__main__":
    main()
