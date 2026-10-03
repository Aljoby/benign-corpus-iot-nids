"""B3: cluster bootstrap CIs (1,000 resamples of flow keys; benign and attack resampled separately).

Data: outputs/rows/<run>.pkl from B1 (key, label, score per row entering the ROC; identical to the artifact).
Per replicate, benign keys are resampled once (shared by all attacks of that run, and by the paired run of the
other detector on the same corpus, since both score the same rows); attack keys are resampled per attack.
Row weight = multiplicity of its key. Metrics with weights:
 - TPR@FPR<=a: the last ROC point with FPR<=a (as control_plane.py): threshold just above the benign score at
   which the weighted benign mass from the top first exceeds a*W_b; TPR = attack mass strictly above it.
 - ROC-AUC: tie-aware Mann-Whitney (= trapezoidal ROC AUC).
Both are validated against B1 (weights = 1) before bootstrapping.
Outputs: B3_ci.csv, B3_summary.md
"""
import os
import sys

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
import numpy as np  # noqa: E402
import pandas as pd  # noqa: E402

T = os.path.join(os.path.dirname(os.path.abspath(__file__)), "..", "..", "outputs")
NB = 1000
ALPHA = 5e-5
RUNS = {"A": {"HorusEye": "R1_A_HE", "Kitsune": "R4_A_KIT", "Magnifier": "R2_A_MAG"},
        "B": {"HorusEye": "R5_B_HE", "Kitsune": "R8_B_KIT", "Magnifier": "R6_B_MAG"}}


def log(*a):
    import time
    print(time.strftime("%H:%M:%S"), *a, flush=True)


class Prep:
    """Per (run, attack): score groups and key codes, for fast weighted metrics."""

    def __init__(self, df, bkey_codes):
        s = df.score.values
        uniq, gid = np.unique(s, return_inverse=True)          # ascending score groups
        self.G = len(uniq)
        self.y = df.label.values
        self.gb, self.ga = gid[self.y == 0], gid[self.y == 1]
        self.kb = bkey_codes.loc[df.key.values[self.y == 0]].values  # benign key codes (shared space)
        ak, self.ka = np.unique(df.key.values[self.y == 1], return_inverse=True)
        self.n_akeys = len(ak)

    def metrics(self, wb_key, wa_key):
        wb = wb_key[self.kb]
        wa = wa_key[self.ka]
        Wb_g = np.bincount(self.gb, weights=wb, minlength=self.G)
        Wa_g = np.bincount(self.ga, weights=wa, minlength=self.G)
        Wb, Wa = Wb_g.sum(), Wa_g.sum()
        C = np.cumsum(Wb_g) - Wb_g                               # benign mass strictly below each group
        auc = float((Wa_g * (C + 0.5 * Wb_g)).sum() / (Wa * Wb))
        # TPR at last ROC point with FPR <= ALPHA (+1e-6 as in the artifact)
        top_b = np.cumsum(Wb_g[::-1])                            # benign mass at or above group (desc)
        viol = np.nonzero(top_b > (ALPHA + 1e-6) * Wb)[0]
        if len(viol) == 0:
            tpr = 1.0
        else:
            j = viol[0]                                          # first violating group from the top
            tpr = float(Wa_g[::-1][:j].sum() / Wa)
        return tpr, auc


def main():
    att_all = None
    preps, keyspace = {}, {}
    for corpus, runs in RUNS.items():
        frames = {d: pd.read_pickle(os.path.join(T, "rows", r + ".pkl")) for d, r in runs.items()}
        bkeys = pd.unique(pd.concat([f[f.label == 0].key for f in frames.values()]))
        codes = pd.Series(np.arange(len(bkeys)), index=bkeys)
        codes = codes[~codes.index.duplicated()]
        keyspace[corpus] = len(codes)
        for d, f in frames.items():
            atts = sorted(f.attack.unique())
            att_all = atts
            for a in atts:
                preps[(corpus, d, a)] = Prep(f[f.attack == a], codes)
        log("corpus", corpus, "benign keys", len(codes))
    # validation vs B1
    b1 = pd.read_csv(os.path.join(T, "B1_repro.csv")).set_index(["run", "attack"])
    worst = 0
    for (corpus, d, a), p in preps.items():
        tpr, auc = p.metrics(np.ones(keyspace[corpus]), np.ones(p.n_akeys))
        ref = b1.loc[(RUNS[corpus][d], a)]
        worst = max(worst, abs(tpr - ref.tpr_5e5), abs(auc - ref.roc_auc))
    log("VALIDATION vs B1 (weights=1): max abs diff %.2e" % worst)
    if worst > 1e-6:
        log("WARNING: weighted metrics do not reproduce B1 exactly")
    new16 = [a for a in att_all if a != "http_ddos"]
    rng = np.random.RandomState(20)
    reps = []  # (rep, corpus, detector, attack, tpr, auc)
    point = []
    for corpus in RUNS:
        for d in RUNS[corpus]:
            for a in att_all:
                p = preps[(corpus, d, a)]
                tpr, auc = p.metrics(np.ones(keyspace[corpus]), np.ones(p.n_akeys))
                point.append((corpus, d, a, tpr, auc))
    for b in range(NB):
        for corpus in RUNS:
            nk = keyspace[corpus]
            wb = np.bincount(rng.randint(0, nk, nk), minlength=nk).astype(float)
            aw = {}
            for a in att_all:  # attack keys resampled per attack, shared across detectors (same rows)
                na = preps[(corpus, "HorusEye", a)].n_akeys
                aw[a] = np.bincount(rng.randint(0, na, na), minlength=na).astype(float)
            for d in RUNS[corpus]:
                for a in att_all:
                    p = preps[(corpus, d, a)]
                    w = aw[a] if p.n_akeys == len(aw[a]) else np.bincount(rng.randint(0, p.n_akeys, p.n_akeys), minlength=p.n_akeys).astype(float)
                    tpr, auc = p.metrics(wb, w)
                    reps.append((b, corpus, d, a, tpr, auc))
        if b % 100 == 0:
            log("replicate", b)
    R = pd.DataFrame(reps, columns=["rep", "corpus", "detector", "attack", "tpr_5e5", "roc_auc"])
    P = pd.DataFrame(point, columns=["corpus", "detector", "attack", "tpr_5e5", "roc_auc"])
    ci = []
    for (c, d, a), g in R.groupby(["corpus", "detector", "attack"]):
        pt = P[(P.corpus == c) & (P.detector == d) & (P.attack == a)].iloc[0]
        for m in ("tpr_5e5", "roc_auc"):
            ci.append({"corpus": c, "detector": d, "attack": a, "metric": m, "point": pt[m],
                       "lo": g[m].quantile(0.025), "hi": g[m].quantile(0.975)})
    M = R[R.attack.isin(new16)].groupby(["rep", "corpus", "detector"])[["tpr_5e5", "roc_auc"]].mean().reset_index()
    MP = P[P.attack.isin(new16)].groupby(["corpus", "detector"])[["tpr_5e5", "roc_auc"]].mean()
    for (c, d), g in M.groupby(["corpus", "detector"]):
        for m in ("tpr_5e5", "roc_auc"):
            ci.append({"corpus": c, "detector": d, "attack": "MACRO16", "metric": m, "point": MP.loc[(c, d), m],
                       "lo": g[m].quantile(0.025), "hi": g[m].quantile(0.975)})
    CI = pd.DataFrame(ci)
    CI.to_csv(os.path.join(T, "B3_ci.csv"), index=False)
    # differences
    W = M.pivot_table(index="rep", columns=["corpus", "detector"], values=["tpr_5e5", "roc_auc"])
    lines = ["# B3 — cluster-bootstrap confidence intervals", "",
             "1,000 resamples of flow keys (benign and attack separately; benign keys shared across attacks and detectors "
             "of a corpus, attack keys shared across detectors). Macro = mean over the 16 new attacks (HTTP DDoS excluded). "
             "95 %% percentile intervals. Weighted metrics reproduce B1 exactly (max diff %.1e)." % worst, "",
             "## Macro point estimates and 95 % CIs", "", "| Corpus | Detector | Macro TPR@5e-5 | Macro ROC-AUC |", "|---|---|---|---|"]
    for (c, d) in MP.index:
        r = CI[(CI.corpus == c) & (CI.detector == d) & (CI.attack == "MACRO16")].set_index("metric")
        lines.append("| %s | %s | %.3f [%.3f, %.3f] | %.3f [%.3f, %.3f] |" % (
            "proprietary" if c == "A" else "open-source", d, r.loc["tpr_5e5", "point"], r.loc["tpr_5e5", "lo"], r.loc["tpr_5e5", "hi"],
            r.loc["roc_auc", "point"], r.loc["roc_auc", "lo"], r.loc["roc_auc", "hi"]))
    lines += ["", "## Corpus effect (open-source − proprietary) and architecture gap (HorusEye − Kitsune)", "",
              "| Quantity | Metric | Point | 95 % CI |", "|---|---|---|---|"]
    diffs = {}
    for m in ("tpr_5e5", "roc_auc"):
        for d in ("HorusEye", "Kitsune", "Magnifier"):
            x = W[(m, "B", d)] - W[(m, "A", d)]
            pt = MP.loc[("B", d), m] - MP.loc[("A", d), m]
            diffs[("corpus", d, m)] = (pt, x.quantile(.025), x.quantile(.975))
            lines.append("| corpus effect, %s | %s | %.3f | [%.3f, %.3f] |" % (d, m, pt, x.quantile(.025), x.quantile(.975)))
        for c in ("A", "B"):
            x = W[(m, c, "HorusEye")] - W[(m, c, "Kitsune")]
            pt = MP.loc[(c, "HorusEye"), m] - MP.loc[(c, "Kitsune"), m]
            diffs[("arch", c, m)] = (pt, x.quantile(.025), x.quantile(.975))
            lines.append("| architecture gap, %s | %s | %.3f | [%.3f, %.3f] |" % (
                "proprietary" if c == "A" else "open-source", m, pt, x.quantile(.025), x.quantile(.975)))
    fp = pd.read_csv(os.path.join(T, "B1_repro.csv"))
    fp = fp[fp.run.isin(["R1_A_HE", "R4_A_KIT", "R5_B_HE", "R8_B_KIT"])]
    lines += ["", "Benign rows at or above the FPR<=5e-5 threshold (point estimate, from B1): max %d (proprietary limit 7, "
              "open-source limit 6); per run: %s." % (fp.fp_5e5.max(), fp.groupby("run").fp_5e5.max().to_dict())]
    open(os.path.join(T, "B3_summary.md"), "w").write("\n".join(lines) + "\n")
    pd.DataFrame([{"what": k[0], "who": k[1], "metric": k[2], "point": v[0], "lo": v[1], "hi": v[2]} for k, v in diffs.items()]).to_csv(
        os.path.join(T, "B3_differences.csv"), index=False)
    log("wrote B3_ci.csv, B3_summary.md")


if __name__ == "__main__":
    main()
