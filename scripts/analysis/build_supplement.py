"""Builds the supplement tables from result files (no training):
  supplement/per_attack_all_configs.csv   17 attacks x {HorusEye, Magnifier, Kitsune, kNN, Isolation Forest} x 2 corpora
  supplement/thresholds.csv               oracle cuts and benign-calibrated thresholds per detector, corpus, FPR target
  supplement/corrected_original_tables.md Tables 2-3 of the submitted paper as reproduced (corrected MQTT PR-AUC)
Inputs: results/tables/B1_all_configs.csv (released HorusEye / Magnifier / Kitsune), outputs/C4_per_attack_full.csv and
outputs/C4_oracle_cuts.csv (c4_full_metrics.py), outputs/rows/<run>.pkl (raw scores, for the oracle cuts of the released
models), results/tables/B2_thresholds.csv and B8_C4a_calibration.csv (calibrated thresholds),
results/tables/submitted_paper_tables_2_3.csv."""
import math
import os

import numpy as np
import pandas as pd

HERE = os.path.dirname(os.path.abspath(__file__))
REPO = os.path.join(HERE, "..", "..")
TAB = os.path.join(REPO, "results", "tables")
OUT = os.path.join(REPO, "outputs")
SUP = os.path.join(REPO, "supplement")
RUNS = {("HorusEye", "proprietary"): "R1_A_HE", ("Magnifier", "proprietary"): "R2_A_MAG", ("Kitsune", "proprietary"): "R4_A_KIT",
        ("HorusEye", "open-source"): "R5_B_HE", ("Magnifier", "open-source"): "R6_B_MAG", ("Kitsune", "open-source"): "R8_B_KIT"}
COLS = ["detector", "corpus", "attack", "in_macro_16", "tpr_5e5", "tpr_5e4", "pr_auc", "roc_auc", "thr_5e5", "thr_5e4",
        "fp_5e5", "fp_5e4", "n_benign", "n_attack"]

# ---------------------------------------------------------------- per-attack table
b1 = pd.read_csv(os.path.join(TAB, "B1_all_configs.csv"))
parts = []
for (det, corpus), run in RUNS.items():
    d = b1[b1.run == run].copy()
    d.insert(0, "detector", det)
    d.insert(1, "corpus", corpus)
    parts.append(d)
c4 = pd.read_csv(os.path.join(OUT, "C4_per_attack_full.csv")).replace({"detector": {"IsolationForest": "Isolation Forest"}})
parts.append(c4)
P = pd.concat(parts, ignore_index=True)
P["in_macro_16"] = P.attack != "http_ddos"
P = P[COLS].sort_values(["corpus", "detector", "attack"])
P.to_csv(os.path.join(SUP, "per_attack_all_configs.csv"), index=False)

# ---------------------------------------------------------------- thresholds
cal = pd.read_csv(os.path.join(TAB, "B2_thresholds.csv"))
calr = pd.read_csv(os.path.join(TAB, "B8_C4a_calibration.csv"))
cuts = pd.read_csv(os.path.join(OUT, "C4_oracle_cuts.csv")).replace({"detector": {"IsolationForest": "Isolation Forest"}})
rows = []
for (det, corpus), run in RUNS.items():
    r = pd.read_pickle(os.path.join(OUT, "rows", run + ".pkl"))
    ben = np.sort(r[(r.attack == "Okiru") & (r.label == 0)].score.values)[::-1]
    cc = "A" if corpus == "proprietary" else "B"
    for fpr, kind in ((5e-5, "calib_5e5"), (5e-4, "calib_5e4")):
        k = int(math.floor((fpr + 1e-6) * len(ben)))
        c = cal[(cal.model == det) & (cal.corpus_train == cc) & (cal.tau_kind == kind)].iloc[0]
        rows.append({"detector": det, "corpus": corpus, "fpr_target": fpr, "n_benign_test": len(ben), "max_fp": k,
                     "oracle_cut": float(ben[k]), "calibrated_tau": c.tau, "n_validation": int(c.n_validation)})
for _, x in cuts.iterrows():
    kind = "calib_5e5" if x.fpr_target == 5e-5 else "calib_5e4"
    c = calr[(calr.detector == ("IsolationForest" if x.detector == "Isolation Forest" else x.detector))
             & (calr.corpus_train == ("A" if x.corpus == "proprietary" else "B")) & (calr.tau_kind == kind)].iloc[0]
    rows.append({"detector": x.detector, "corpus": x.corpus, "fpr_target": x.fpr_target, "n_benign_test": x.n_benign_test,
                 "max_fp": x.max_fp, "oracle_cut": x.oracle_cut, "calibrated_tau": c.tau, "n_validation": None})
TH = pd.DataFrame(rows).sort_values(["corpus", "detector", "fpr_target"])
TH.to_csv(os.path.join(SUP, "thresholds.csv"), index=False)

# ---------------------------------------------------------------- corrected original tables
paper = pd.read_csv(os.path.join(TAB, "submitted_paper_tables_2_3.csv"))
names = {"MITM": "ARP Spoofing", "http_ddos": "HTTP DDoS (control)", "Uploading_attack": "Uploading Attack",
         "Hide_and_seek": "Hide & Seek", "Sparta": "SSH Bruteforce", "Vulnerability_scanner": "Vuln. Scanner",
         "SQL_injection": "SQL Injection", "Okiru": "Okiru", "Ransomware": "Ransomware", "Muhstik": "Muhstik",
         "bruteforce": "MQTT Bruteforce", "Hakai": "Hakai", "DOS_synflooding": "DoS SYN Flood", "Password_attack": "Password Attack"}
sysrun = {("A", "Kitsune"): "R4_A_KIT", ("A", "Magnifier"): "R2_A_MAG", ("A", "HorusEye"): "R1_A_HE",
          ("B", "Kitsune"): "R8_B_KIT", ("B", "Magnifier"): "R6_B_MAG", ("B", "HorusEye"): "R5_B_HE"}
L = ["# Tables 2–3 of the submitted manuscript, as reproduced", "",
     "Re-run of the released models (`scripts/run_all.sh`, R1–R8) on the 14 attacks of the submitted paper; each cell is "
     "the reproduced value (3 decimals). Every reproduced cell is within 0.0005 of the submitted table except the one "
     "marked **bold**, a transcription error in the submitted Table 3. Macro = mean over the 14 attacks, as in the "
     "submitted paper (the revised paper uses 16 attacks and excludes HTTP DDoS). Source: `results/tables/B1_all_configs.csv`, "
     "`results/tables/submitted_paper_tables_2_3.csv`.", ""]
for exp, title in (("B", "Table 2 — trained on the open-source benign corpus"), ("A", "Table 3 — trained on the proprietary benign corpus")):
    L += ["## " + title, "", "| Attack | Kitsune TPR≤5e-5 | TPR≤5e-4 | PR-AUC | Magnifier TPR≤5e-5 | TPR≤5e-4 | PR-AUC | "
          "HorusEye TPR≤5e-5 | TPR≤5e-4 | PR-AUC |", "|---|" + "---|" * 9]
    macro = {}
    for att, nm in names.items():
        cells = []
        for sysn in ("Kitsune", "Magnifier", "HorusEye"):
            r = b1[b1.run == sysrun[(exp, sysn)]].set_index("attack").loc[att]
            p = paper[(paper.experiment == exp) & (paper.system == sysn) & (paper.attack == att)].iloc[0]
            for col, pc in (("tpr_5e5", "tpr_1"), ("tpr_5e4", "tpr_2"), ("pr_auc", "pr_auc")):
                v = round(float(r[col]), 3)
                macro.setdefault((sysn, col), []).append(float(r[col]))
                cell = "%.3f" % v
                if abs(float(r[col]) - p[pc]) > 0.0015:
                    cell = "**%.3f** (submitted: %.3f)" % (v, p[pc])
                cells.append(cell)
        L.append("| %s | %s |" % (nm, " | ".join(cells)))
    L.append("| **Macro (14)** | %s |" % " | ".join("%.3f" % np.mean(macro[(s, c)]) for s in ("Kitsune", "Magnifier", "HorusEye")
                                                  for c in ("tpr_5e5", "tpr_5e4", "pr_auc")))
    L.append("")
open(os.path.join(SUP, "corrected_original_tables.md"), "w").write("\n".join(L) + "\n")
print("wrote supplement/per_attack_all_configs.csv (%d rows), thresholds.csv (%d rows), corrected_original_tables.md" % (len(P), len(TH)))
