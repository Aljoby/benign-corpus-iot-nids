"""Builds outputs/RETRAINING_SUMMARY.md from the existing result files only (no runs)."""
import json
import os

import pandas as pd

T = os.path.join(os.path.dirname(os.path.abspath(__file__)), "..", "..", "outputs")
R = lambda f: pd.read_csv(os.path.join(T, f))  # noqa: E731
NEW16 = lambda d: d[d.attack != "http_ddos"]  # noqa: E731

b1 = R("B1_repro.csv")
val = R("B1_fasteval_validation.csv")
b1x = R("B1x_cascade.csv")
b4 = R("B4_gulliver.csv")
b5 = R("B5_ablation.csv")
g3, g4, g5 = R("B8_G3.csv"), R("B8_G4.csv"), R("B8_G5.csv")
c3 = R("B8_C3.csv")
c4a, c4b, c5 = R("B8_C4a.csv"), R("B8_C4b.csv"), R("B8_C5.csv")
he5 = b5[b5.model == "HorusEye"].drop_duplicates("subset", keep="first").set_index("subset")
m16 = {r: NEW16(b1[b1.run == r]) for r in b1.run.unique()}
mac = lambda r, c: m16[r][c].mean()  # noqa: E731

L = ["# RETRAINING_SUMMARY — models re-run or retrained for the revision", "",
     "All numbers come from the result files in `results/tables/` (paper comparison: "
     "`submitted_paper_tables_2_3.csv`). Macro = mean over the 16 new attacks (HTTP DDoS excluded); values are macro TPR at FPR≤5×10⁻⁵ / "
     "macro ROC-AUC. \"Max FP\" = false positives allowed at that FPR for the benign test set used.", ""]

# ---------------------------------------------------------------- (1)
L += ["## 1. Released models re-evaluated (no training)", "",
      "| Models | Configurations | Checked | Outcome |", "|---|---|---|---|",
      "| 2 Magnifier + 1 Gulliver rule set (HorusEye), 2 Kitsune — the artifact's released models | 8 runs R1–R8 "
      "(HorusEye, Magnifier alone, Kitsune with / without Gulliver × 2 corpora) | Tables 2–3 of the submitted paper and "
      "the student's saved results | All paper cells within 0.0005 except one typo (Table 3 MQTT Magnifier PR-AUC "
      "0.088 → 0.604); saved results reproduced exactly (Δ = 0.0); paper's Kitsune = standalone Kitsune (R4/R8) |",
      "| same | fast re-evaluation of R1–R8 (scores cached, MPS) | metrics vs. the CPU artifact runs | max \\|Δ\\| TPR %.0e, "
      "ROC-AUC %.0e |" % (round(val.d_tpr_1.max(), 12), val.d_roc_auc.max()),
      "| same | 2 runs (B1x): HorusEye with Gulliver-passed packets scored by Magnifier | cascade explanation (R2.3) | "
      "identical to Magnifier alone: %.3f / %.3f (prop. / open) vs. HorusEye %.3f / %.3f |" % (
          mac("R2_A_MAG", "tpr_5e5"), mac("R6_B_MAG", "tpr_5e5"), mac("R1_A_HE", "tpr_5e5"), mac("R5_B_HE", "tpr_5e5")),
      "", "Analyses on these scores (no new models): benign-only calibration and transfer (B2), cluster bootstrap (B3), "
      "TPR-vs-FPR curves (C1), tail attribution (G2), score figures.", ""]

# ---------------------------------------------------------------- (2)
kit_all14 = c3[c3.condition == "all14"].iloc[0]
kit_os5 = c3[c3.condition == "os_days5"]
b4p, b4o = b4[(b4.corpus == "A") & (b4.seed != 114514)], b4[(b4.corpus == "B") & (b4.seed != 114514)]
art = b4[(b4.corpus == "A") & (b4.seed == 114514)].iloc[0]
open_ret = b4[(b4.corpus == "B") & (b4.seed == 114514)].iloc[0]
seeds = he5.loc[[s for s in ["all14", "all14_seed1", "all14_seed2"] if s in he5.index]]
L += ["## 2. Retrained models used to verify reproducibility", "",
      "| Check | Models | What was checked | Outcome |", "|---|---|---|---|",
      "| Kitsune retraining | %d | KitNET retrained (original hyper-parameters, CPU) vs. the released models | "
      "all 14 devices: %.4f / %.4f = released R4 (%.4f / %.4f)%s |" % (
          1 + len(kit_os5), kit_all14.macro_tpr_5e5, kit_all14.macro_roc_auc, mac("R4_A_KIT", "tpr_5e5"),
          mac("R4_A_KIT", "roc_auc"),
          ("; open-source 5 days: %.4f / %.4f vs. released R8 (%.4f / %.4f)" % (
              kit_os5.macro_tpr_5e5.iloc[0], kit_os5.macro_roc_auc.iloc[0], mac("R8_B_KIT", "tpr_5e5"),
              mac("R8_B_KIT", "roc_auc"))) if len(kit_os5) else ""),
      "| Gulliver retraining and seeds | %d | iForest retrained with the original hyper-parameters; seed 114514 "
      "(original) + seeds 0–4 per corpus | original seed reproduces the released rules byte-for-byte "
      "(rules identical: %s); seed sd %.4f (prop.) / %.4f (open) macro TPR; Gulliver retrained on open-source: "
      "%.3f vs. %.3f with the released rules |" % (len(b4), bool(art.rules_identical_to_artifact),
                                                    b4p.macro_tpr_5e5.std(ddof=1), b4o.macro_tpr_5e5.std(ddof=1),
                                                    open_ret.macro_tpr_5e5, mac("R5_B_HE", "tpr_5e5")),
      "| Magnifier seeds (HorusEye, all 14 devices) | %d | retraining spread (seeds %s; 18 epochs) | macro TPR %s "
      "(sd %.3f); ROC-AUC sd %.3f; released model %.3f |" % (
          len(seeds), "/".join(str(int(x)) for x in seeds.seed), " / ".join("%.3f" % x for x in seeds.macro_tpr_5e5),
          seeds.macro_tpr_5e5.std(ddof=1), seeds.macro_roc_auc.std(ddof=1), mac("R1_A_HE", "tpr_5e5")),
      "| 18 vs. 20 epochs | %d | original 20 epochs + original checkpoint rule vs. the 18-epoch ablation models | "
      "identical for all %d (%s); selected epochs %s |" % (
          len(g4[g4.detector == "HorusEye"]), len(g4[g4.detector == "HorusEye"]),
          ", ".join("%s %.3f" % (r.condition, r.macro_tpr_5e5) for _, r in g4[g4.detector == "HorusEye"].iterrows()),
          "/".join(str(int(x)) for x in g4[g4.detector == "HorusEye"].best_epoch)),
      "| Benign-only checkpoint selection | %d | 20 epochs, checkpoint = lowest benign validation loss (no attack "
      "packets), Gulliver retrained | proprietary %.3f / %.3f, open-source %.3f / %.3f; corpus effect %.3f "
      "(released %.3f) |" % (
          len(g3[g3.detector == "HorusEye"]),
          g3[(g3.detector == "HorusEye") & (g3.condition == "all14")].macro_tpr_5e5.iloc[0],
          g3[(g3.detector == "HorusEye") & (g3.condition == "all14")].macro_roc_auc.iloc[0],
          g3[(g3.detector == "HorusEye") & (g3.condition == "open_full")].macro_tpr_5e5.iloc[0],
          g3[(g3.detector == "HorusEye") & (g3.condition == "open_full")].macro_roc_auc.iloc[0],
          g3[(g3.detector == "HorusEye") & (g3.condition == "open_full")].macro_tpr_5e5.iloc[0]
          - g3[(g3.detector == "HorusEye") & (g3.condition == "all14")].macro_tpr_5e5.iloc[0],
          mac("R5_B_HE", "tpr_5e5") - mac("R1_A_HE", "tpr_5e5")), ""]

# ---------------------------------------------------------------- (3)
he_sets = [s for s in ["all14", "vol_match", "cam8", "gw6", "rand5_a", "rand5_b", "os_days1", "os_days2", "os_days3", "os_days5"]
           if s in he5.index]
he_rows = [(s, he5.loc[s, "macro_tpr_5e5"], he5.loc[s, "macro_roc_auc"], he5.loc[s, "n_benign_test"]) for s in he_sets]
he_rows += [(r.condition, r.macro_tpr_5e5, r.macro_roc_auc, r.n_benign_test) for _, r in g5[g5.detector == "HorusEye"].iterrows()]
kit = c3[~c3.condition.str.startswith("train=")]
ref = pd.concat([c4a.assign(condition=c4a.condition.map({"full_proprietary": "all14", "full_open-source": "os_days5"})),
                 c4b[~c4b.condition.isin(["all14", "os_days5"]) & ~c4b.condition.str.startswith("train=")],
                 c5])
def fmt(rows):
    """Compact outcome: ranges for proprietary subsets (without gateways), the gateway subset, open-source setups."""
    P = [r for r in rows if not r[0].startswith(("os_", "open")) and r[0] != "gw6"]
    G = [r for r in rows if r[0] == "gw6"]
    O = [r for r in rows if r[0].startswith(("os_", "open"))]
    rng = lambda xs, i: "%.3f–%.3f" % (min(x[i] for x in xs), max(x[i] for x in xs)) if xs else "–"  # noqa: E731
    out = ["proprietary subsets (n=%d) TPR %s, AUC %s" % (len(P), rng(P, 1), rng(P, 2))]
    if G:
        out.append("gateways+router %.3f / %.3f (≤1 FP)" % (G[0][1], G[0][2]))
    if O:
        out.append("open-source setups (n=%d) TPR %s, AUC %s" % (len(O), rng(O, 1), rng(O, 2)))
    return "; ".join(out)
L += ["## 3. Ablation models (one training run each unless stated)", "",
      "| Detector | Models | Setups | Outcome |", "|---|---|---|---|",
      "| HorusEye (Magnifier 18 epochs, original checkpoint rule; Gulliver retrained on proprietary subsets, released "
      "rules on open-source subsets) | %d | %s | %s |" % (len(he_rows), ", ".join(s for s, *_ in he_rows), fmt(he_rows)),
      "| Kitsune (KitNET, original hyper-parameters, CPU) | %d | %s | %s |" % (
          len(kit), ", ".join(kit.condition), fmt([(r.condition, r.macro_tpr_5e5, r.macro_roc_auc, r.n_benign_test)
                                                   for _, r in kit.iterrows()])),
      ]
for det in ("kNN", "IsolationForest"):
    d = ref[ref.detector == det].drop_duplicates("condition")
    L.append("| %s | %d | %s | %s |" % (
        "Isolation Forest (training-free reference; 100 trees, 256 samples)" if det == "IsolationForest"
        else "kNN (training-free reference; k = 5, 100,000 benign reference packets)", len(d), ", ".join(d.condition),
        fmt([(r.condition, r.macro_tpr_5e5, r.macro_roc_auc, r.n_benign_test) for _, r in d.iterrows()])))
cross = sum(len(x[x.condition.str.startswith("train=")]) for x in (c3, c4b)) + len(R("B8_G1.csv"))
L += ["", "Gateway cross-tests (G1, C3, C4b: %d evaluations) re-use the all-14 and gateway models above; no extra "
      "training. Each setup is tested on the benign test traffic of the same devices / days plus the same attacks." % cross,
      "", "**Totals:** released models re-evaluated: 5 model files (2 Magnifier, 2 Kitsune, 1 Gulliver rule set) in "
      "10 configurations; reproducibility retrains: %d; ablation models: %d (HorusEye %d, Kitsune %d, kNN %d, "
      "Isolation Forest %d)." % (
          1 + len(kit_os5) + len(b4) + (len(seeds) - 1) + len(g4[g4.detector == "HorusEye"]) + len(g3[g3.detector == "HorusEye"]),
          len(he_rows) + len(kit) + len(ref[ref.detector == "kNN"].drop_duplicates("condition"))
          + len(ref[ref.detector == "IsolationForest"].drop_duplicates("condition")),
          len(he_rows), len(kit), len(ref[ref.detector == "kNN"].drop_duplicates("condition")),
          len(ref[ref.detector == "IsolationForest"].drop_duplicates("condition")))]
open(os.path.join(T, "RETRAINING_SUMMARY.md"), "w").write("\n".join(L) + "\n")
print("\n".join(L))
