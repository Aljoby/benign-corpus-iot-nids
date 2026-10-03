"""Stage 4: compare the re-run results (outputs/repro/R1-R8) with Tables 2-3 of the submitted manuscript
(results/tables/submitted_paper_tables_2_3.csv) and with the student's saved results
(horuseye_artifact/new_attacks_results). Outputs: outputs/repro/compare_long.csv, outputs/repro/compare_summary.csv."""
import glob
import os

import pandas as pd

HERE = os.path.dirname(os.path.abspath(__file__))
REPO = os.path.join(HERE, "..")
OUT = os.path.join(REPO, "outputs", "repro")
PAPER = pd.read_csv(os.path.join(REPO, "results", "tables", "submitted_paper_tables_2_3.csv"))
SAVED = os.path.join(REPO, "horuseye_artifact", "new_attacks_results")
METRICS = ["tpr_1", "tpr_2", "pr_auc", "roc_auc"]          # TPR@5e-5, TPR@5e-4, PR-AUC, ROC-AUC
RUNS = {  # run -> (experiment, system in the paper tables or None for diagnostics, saved student results)
    "R1_A_HE": ("A", "HorusEye", ["result (Ex_A_HE_True)/HorusEye"]),
    "R2_A_MAG": ("A", "Magnifier", []),
    "R3_A_KITHE": ("A", None, ["result (Ex_A_HE_True)/Kitsune"]),
    "R4_A_KIT": ("A", "Kitsune", ["result (Ex_A_HE_True)/Kitsune"]),
    "R5_B_HE": ("B", "HorusEye", ["result (Ex_B_HE_True_retrained)/Open-Source/HorusEye"]),
    "R6_B_MAG": ("B", "Magnifier", ["result (Ex_B_HE_False)/Open-Source/Magnifier"]),
    "R7_B_KITHE": ("B", None, ["result (Ex_B_HE_True)/Open-Source/Kitsune"]),
    "R8_B_KIT": ("B", "Kitsune", ["result (Ex_B_HE_True)/Open-Source/Kitsune"]),
}


def rec(path):
    return pd.read_csv(path, index_col=0).set_index("attack_type")[METRICS]


rows, summ = [], []
for run, (exp, system, saved) in RUNS.items():
    f = glob.glob(os.path.join(OUT, run, "**", "record_attack.csv"), recursive=True)
    if not f:
        summ.append({"run": run, "status": "no output"})
        continue
    r = rec(f[0])
    sv = {s: rec(os.path.join(SAVED, s, "record_attack.csv")) for s in saved if os.path.exists(os.path.join(SAVED, s, "record_attack.csv"))}
    p = PAPER[(PAPER.experiment == exp) & (PAPER.system == system)].set_index("attack") if system else None
    dp, ds = [], []
    for att in r.index:
        row = {"run": run, "attack": att}
        for m in METRICS:
            row["repro_" + m] = r.loc[att, m]
            if p is not None and att in p.index and m in p.columns:
                row["paper_" + m] = p.loc[att, m]
                dp.append(abs(r.loc[att, m] - p.loc[att, m]))
            for s, d in sv.items():
                if att in d.index:
                    ds.append(abs(r.loc[att, m] - d.loc[att, m]))
        rows.append(row)
    summ.append({"run": run, "max_abs_diff_vs_paper": max(dp) if dp else None, "max_abs_diff_vs_saved": max(ds) if ds else None})
pd.DataFrame(rows).to_csv(os.path.join(OUT, "compare_long.csv"), index=False)
S = pd.DataFrame(summ)
S.to_csv(os.path.join(OUT, "compare_summary.csv"), index=False)
print(S.to_string(index=False))
print("Expected: max diff vs paper <= 0.0005 for all paper configurations except R2 (MQTT brute-force PR-AUC typo in the "
      "submitted Table 3: 0.088 printed, 0.604 reproduced); max diff vs saved = 0.0 for R1, R4, R5, R6, R8.")
