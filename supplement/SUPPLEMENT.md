# Online supplement — index

Everything here is produced by scripts in `scripts/` from the released models and the datasets listed in
`data/DATA.md`. Macro averages are over the 16 new attacks (HTTP DDoS shown but excluded); FPR targets 5×10⁻⁵ and
5×10⁻⁴; "max FP" is the number of false positives allowed for the benign test set used.

| File | Content | Maps to the paper | Produced by |
|---|---|---|---|
| `per_attack_all_configs.csv` | 17 attacks (16 new + HTTP DDoS) × {HorusEye, Magnifier, Kitsune, kNN, Isolation Forest} × {proprietary, open-source}: TPR at FPR ≤ 5×10⁻⁵ and ≤ 5×10⁻⁴, PR-AUC, ROC-AUC, the threshold recorded at each operating point, false-positive counts, benign and attack row counts (170 rows) | Table 2 (per-attack TPR / ROC-AUC), §4.1, §4.2, reference detectors in §4.1 | `scripts/analysis/build_supplement.py` from `results/tables/B1_all_configs.csv` (released HorusEye / Magnifier / Kitsune, runs R1, R2, R4, R5, R6, R8) and `scripts/analysis/c4_full_metrics.py` (kNN, Isolation Forest; reproduces `B8_C4a.csv` exactly) |
| `thresholds.csv` | per detector, corpus and FPR target: the oracle cut (the (k+1)-th highest benign test score, k = max FP), the benign-calibrated threshold τ (quantile of the benign validation scores), benign test size (20 rows) | §4.2 (calibration), Fig. 3 (dashed and dotted lines) | `scripts/analysis/build_supplement.py` from the raw scores (`outputs/rows/`), `results/tables/B2_thresholds.csv`, `results/tables/B8_C4a_calibration.csv`, `outputs/C4_oracle_cuts.csv` |
| `fig_scores_all_horuseye.pdf` | HorusEye score distributions, benign vs. attack, all 16 attacks × 2 corpora; oracle cut, calibrated τ, TPR / AUC per panel; same style and x axis (from 10⁻⁴) as Fig. 3 | extends Fig. 3 to all attacks (§4.2, §5.1) | `scripts/figures/fig_scores_style.py` |
| `fig_scores_all_kitsune.pdf` | the same for Kitsune | extends Fig. 3 to all attacks | `scripts/figures/fig_scores_style.py` |
| `corrected_original_tables.md` | Tables 2–3 of the submitted manuscript as reproduced from the released models, including the corrected Magnifier PR-AUC for MQTT brute force (0.604; 0.088 was printed) | response to the reviewers (reproduction) | `scripts/analysis/build_supplement.py` from `results/tables/B1_all_configs.csv` and `results/tables/submitted_paper_tables_2_3.csv` |

Further result tables used by the paper are in `results/tables/` (see `results/tables/RETRAINING_SUMMARY.md` for
every re-run or retrained model):
- calibration and transfer: `B2_calibration.csv`;
- bootstrap confidence intervals: `B3_ci.csv`, `B3_differences.csv`;
- Gulliver seeds: `B4_gulliver.csv`;
- ablations: `B5_ablation.csv`, `B8_C3.csv`, `B8_C4b.csv`, `B8_C5.csv`, `B8_G4.csv`, `B8_G5.csv`, `B8_summary_table.csv`;
- gateway cross-tests: `B8_G1.csv`;
- tail attribution: `B8_G2_*`;
- benign-only checkpoint selection: `B8_G3.csv`;
- feature overlap: `B2x_overlap.csv`;
- corpus distance: `B6_corpus_distance.csv`;
- TPR vs FPR: `B8_C1_points.csv`, `B8_C1_curves.csv`.

**Notes.**
- **Recorded thresholds** (`thr_5e5`, `thr_5e4`) are those of the last ROC point within the FPR target, as recorded by the artifact. When TPR = 0, `roc_curve` drops collinear points, so the recorded threshold can lie well above the actual cut. Use `thresholds.csv` (`oracle_cut`) for the cut.
- **`n_validation`** is given for the learned detectors (HorusEye: packets scored after Gulliver filtering). For kNN and the Isolation Forest the calibration used the full 20 % validation split.
- **Labels** are capture-level: every packet of an attack capture counts as malicious.
