# RETRAINING_SUMMARY — models re-run or retrained for the revision

All numbers come from the result files in `results/tables/` (paper comparison: `submitted_paper_tables_2_3.csv`). Macro = mean over the 16 new attacks (HTTP DDoS excluded); values are macro TPR at FPR≤5×10⁻⁵ / macro ROC-AUC. "Max FP" = false positives allowed at that FPR for the benign test set used.

## 1. Released models re-evaluated (no training)

| Models | Configurations | Checked | Outcome |
|---|---|---|---|
| 2 Magnifier + 1 Gulliver rule set (HorusEye), 2 Kitsune — the artifact's released models | 8 runs R1–R8 (HorusEye, Magnifier alone, Kitsune with / without Gulliver × 2 corpora) | Tables 2–3 of the submitted paper and the student's saved results | All paper cells within 0.0005 except one typo (Table 3 MQTT Magnifier PR-AUC 0.088 → 0.604); saved results reproduced exactly (Δ = 0.0); paper's Kitsune = standalone Kitsune (R4/R8) |
| same | fast re-evaluation of R1–R8 (scores cached, MPS) | metrics vs. the CPU artifact runs | max \|Δ\| TPR 0e+00, ROC-AUC 3e-06 |
| same | 2 runs (B1x): HorusEye with Gulliver-passed packets scored by Magnifier | cascade explanation (R2.3) | identical to Magnifier alone: 0.128 / 0.418 (prop. / open) vs. HorusEye 0.149 / 0.425 |

Analyses on these scores (no new models): benign-only calibration and transfer (B2), cluster bootstrap (B3), TPR-vs-FPR curves (C1), tail attribution (G2), score figures.

## 2. Retrained models used to verify reproducibility

| Check | Models | What was checked | Outcome |
|---|---|---|---|
| Kitsune retraining | 2 | KitNET retrained (original hyper-parameters, CPU) vs. the released models | all 14 devices: 0.0921 / 0.7060 = released R4 (0.0921 / 0.7060); open-source 5 days: 0.3924 / 0.8534 vs. released R8 (0.3924 / 0.8534) |
| Gulliver retraining and seeds | 12 | iForest retrained with the original hyper-parameters; seed 114514 (original) + seeds 0–4 per corpus | original seed reproduces the released rules byte-for-byte (rules identical: True); seed sd 0.0008 (prop.) / 0.0010 (open) macro TPR; Gulliver retrained on open-source: 0.422 vs. 0.425 with the released rules |
| Magnifier seeds (HorusEye, all 14 devices) | 3 | retraining spread (seeds 20/1/2; 18 epochs) | macro TPR 0.147 / 0.132 / 0.148 (sd 0.009); ROC-AUC sd 0.017; released model 0.149 |
| 18 vs. 20 epochs | 3 | original 20 epochs + original checkpoint rule vs. the 18-epoch ablation models | identical for all 3 (gw6 0.639, cam8 0.214, rand5_a 0.080); selected epochs 0/1/2 |
| Benign-only checkpoint selection | 2 | 20 epochs, checkpoint = lowest benign validation loss (no attack packets), Gulliver retrained | proprietary 0.148 / 0.824, open-source 0.409 / 0.941; corpus effect 0.260 (released 0.276) |

## 3. Ablation models (one training run each unless stated)

| Detector | Models | Setups | Outcome |
|---|---|---|---|
| HorusEye (Magnifier 18 epochs, original checkpoint rule; Gulliver retrained on proprietary subsets, released rules on open-source subsets) | 14 | all14, vol_match, cam8, gw6, rand5_a, rand5_b, os_days1, os_days2, os_days3, os_days5, prop_files1, open_25pct, prop_files2, open_50pct | proprietary subsets (n=7) TPR 0.080–0.214, AUC 0.701–0.860; gateways+router 0.639 / 0.969 (≤1 FP); open-source setups (n=6) TPR 0.376–0.454, AUC 0.876–0.925 |
| Kitsune (KitNET, original hyper-parameters, CPU) | 10 | all14, gw6, cam8, vol_match, rand5_a, rand5_b, os_days1, os_days2, os_days3, os_days5 | proprietary subsets (n=5) TPR 0.087–0.158, AUC 0.671–0.776; gateways+router 0.656 / 0.917 (≤1 FP); open-source setups (n=4) TPR 0.392–0.428, AUC 0.813–0.864 |
| kNN (training-free reference; k = 5, 100,000 benign reference packets) | 22 | all14, os_days5, vol_match, cam8, gw6, rand5_a, rand5_b, os_days1, os_days2, os_days3, prop_files1, prop_files2, prop_files3, open_25pct, open_50pct, open_devhalf_A, open_devhalf_B, rand5_seed2, rand5_seed3, rand5_seed4, rand5_seed5, rand5_seed6 | proprietary subsets (n=13) TPR 0.142–0.275, AUC 0.823–0.914; gateways+router 0.649 / 0.993 (≤1 FP); open-source setups (n=8) TPR 0.459–0.494, AUC 0.894–0.981 |
| Isolation Forest (training-free reference; 100 trees, 256 samples) | 22 | all14, os_days5, vol_match, cam8, gw6, rand5_a, rand5_b, os_days1, os_days2, os_days3, prop_files1, prop_files2, prop_files3, open_25pct, open_50pct, open_devhalf_A, open_devhalf_B, rand5_seed2, rand5_seed3, rand5_seed4, rand5_seed5, rand5_seed6 | proprietary subsets (n=13) TPR 0.000–0.000, AUC 0.632–0.728; gateways+router 0.000 / 0.867 (≤1 FP); open-source setups (n=8) TPR 0.000–0.004, AUC 0.816–0.958 |

Gateway cross-tests (G1, C3, C4b: 14 evaluations) re-use the all-14 and gateway models above; no extra training. Each setup is tested on the benign test traffic of the same devices / days plus the same attacks.

**Totals:** released models re-evaluated: 5 model files (2 Magnifier, 2 Kitsune, 1 Gulliver rule set) in 10 configurations; reproducibility retrains: 21; ablation models: 68 (HorusEye 14, Kitsune 10, kNN 22, Isolation Forest 22).
