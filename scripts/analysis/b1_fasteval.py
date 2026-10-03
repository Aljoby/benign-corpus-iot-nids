"""B1 (tables in outputs/) + B1x (passed packets scored by Magnifier) + validation of the fast evaluator.

Configs per corpus: HE (Magnifier+Gulliver), MAG, KIT (standalone), KITG (diagnostic), HE_PASS (B1x).
Outputs (outputs/): B1_repro.csv, B1x_cascade.csv, B1_fasteval_validation.csv, rows/<run>.pkl (key,label,score)
"""
import glob
import os
import sys

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
import hekit as hk  # noqa: E402
import pandas as pd  # noqa: E402

T = os.path.abspath(hk.OUTPUTS)
REPRO_OUT = os.path.join(T, "repro")              # outputs of scripts/run_all.sh (R1-R8)
RUNS = {  # run id: (corpus, scorer kind, gulliver, pass_scored, repro output to validate against)
    "R1_A_HE": ("A", "mag", True, False, "R1_A_HE"), "R2_A_MAG": ("A", "mag", False, False, "R2_A_MAG"),
    "R3_A_KITHE": ("A", "kit", True, False, "R3_A_KITHE"), "R4_A_KIT": ("A", "kit", False, False, "R4_A_KIT"),
    "B1x_A_HE_PASS": ("A", "mag", True, True, None),
    "R5_B_HE": ("B", "mag", True, False, "R5_B_HE"), "R6_B_MAG": ("B", "mag", False, False, "R6_B_MAG"),
    "R7_B_KITHE": ("B", "kit", True, False, "R7_B_KITHE"), "R8_B_KIT": ("B", "kit", False, False, "R8_B_KIT"),
    "B1x_B_HE_PASS": ("B", "mag", True, True, None),
}


def main():
    hk.workdir("b1")
    os.makedirs(os.path.join(T, "rows"), exist_ok=True)
    attacks = hk.load_attacks()
    allm, val = [], []
    for corpus in ("A", "B"):
        con_b, data_b = hk.load_benign_test(corpus)
        hk.log("corpus", corpus, "benign con", len(con_b), "burst", len(data_b))
        scorers = {"mag": hk.artifact_scorer("mag", corpus), "kit": hk.artifact_scorer("kit", corpus)}
        for run, (c, kind, g, ps, ref) in RUNS.items():
            if c != corpus:
                continue
            m, rows = hk.evaluate(con_b, data_b, attacks, scorers[kind], g, keep_rows=True, pass_scored=ps, tag=run)
            m.insert(0, "run", run)
            allm.append(m)
            rows.to_pickle(os.path.join(T, "rows", run + ".pkl"))
            if ref:
                rec = glob.glob(os.path.join(REPRO_OUT, ref, "**", "record_attack.csv"), recursive=True)[0]
                r = pd.read_csv(rec, index_col=0).set_index("attack_type")
                for _, x in m.iterrows():
                    o = r.loc[x.attack]
                    val.append({"run": run, "attack": x.attack,
                                **{"d_" + k: abs(x[k2] - o[k]) for k, k2 in
                                   (("tpr_1", "tpr_5e5"), ("tpr_2", "tpr_5e4"), ("pr_auc", "pr_auc"), ("roc_auc", "roc_auc"))}})
    df = pd.concat(allm, ignore_index=True)
    cols = ["run", "attack", "tpr_5e5", "tpr_5e4", "pr_auc", "roc_auc", "n_benign", "n_attack", "fp_5e5", "fp_5e4",
            "thr_5e5", "thr_5e4", "n_scored_benign", "n_passed_benign", "n_passed_attack"]
    df[df.run.str.startswith("R")][cols].to_csv(os.path.join(T, "B1_repro.csv"), index=False)
    df[cols].to_csv(os.path.join(T, "B1_all_configs.csv"), index=False)
    v = pd.DataFrame(val)
    v.to_csv(os.path.join(T, "B1_fasteval_validation.csv"), index=False)
    hk.log("VALIDATION max abs diff vs repro outputs:", v.drop(columns=["run", "attack"]).max().round(6).to_dict())
    hk.log("VALIDATION per run max:", v.groupby("run").max(numeric_only=True).max(axis=1).round(6).to_dict())


if __name__ == "__main__":
    main()
