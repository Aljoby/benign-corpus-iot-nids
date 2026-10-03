# Benign Data is the Bottleneck: How the Benign Corpus Shapes Low-False-Positive Detection in Unsupervised IoT Anomaly Detectors

**Walid Aljoby, Muhannad Alshareef, Mohammad Hammoudeh** (King Fahd University of Petroleum and Minerals) and
**Bouziane Brik** (University of Sharjah)

*IEEE Internet of Things Magazine (under review, IOTMAG-26-00248)*

Code, result tables, figures and supplement for the revision of the paper. No datasets are included; see
[`data/DATA.md`](data/DATA.md).

## Summary

Unsupervised IoT intrusion detectors learn "normal" from benign traffic only, so their reported performance depends
on which benign corpus is used. We evaluate two detectors at opposite deployment tiers, Kitsune (software) and
HorusEye (programmable switch), on the same 16 IoT attacks, trained on two benign corpora: the HorusEye authors'
proprietary testbed and the public UNSW IoT traces.

At the strict operating point used in prior work (FPR ≤ 5×10⁻⁵):
- **Corpus effect:** changing only the benign corpus moves the macro true positive rate (TPR) from 0.149 to 0.425 for HorusEye and from 0.092 to 0.392 for Kitsune.
- **Architecture gap:** the difference between the two detectors is 3–6 points under either corpus.
- **Wider range:** the corpus effect holds across the whole low-false-positive range. A training-free nearest-neighbour detector shows the same effect.
- **What drives it:** ablations attribute it to the corpus itself (in particular the device types in the training and test traffic), not to its size, duration or number of devices.

### Takeaways (Lessons L1–L4 of the paper, verbatim)

**L1: Report the operating point, not only the TPR.** At FPR ≤ 5×10⁻⁵ a few benign packets decide the result. Report the benign test size, false-positive counts, ROC-AUC and confidence intervals, and set thresholds on held-out benign data rather than on the labeled test set.

**L2: Evaluate on more than one benign corpus, and match it to the deployment.** The same attacks and detectors yielded macro TPRs from 0.09 to 0.48 depending on the corpus, and models trained on one corpus over-alarmed on the other. A single-corpus result describes the pair (detector, corpus), not the detector; comparing training and deployment distributions [Thirumuruganathan et al., USENIX Security 2024] is a practical safeguard.

**L3: Include simple references and document provenance.** A training-free kNN was as good as either learned detector, and corpus descriptions, attack sources and label granularity changed our interpretation of several results.

**L4: Re-validate the corpus when changing the detector.** The architecture gain we measured (3–6 points) is smaller than the effect of the corpus, so upgrading from a commodity to a switch-based detector does not remove the need to re-validate the benign corpus for the new site.

## Key results (reproducible from `results/tables/`)

| Quantity | Value |
|---|---|
| Macro TPR at FPR ≤ 5×10⁻⁵ (16 attacks), HorusEye proprietary / open-source | 0.149 / 0.425 |
| Same, Kitsune | 0.092 / 0.392 |
| Macro ROC-AUC, HorusEye / Kitsune (proprietary → open-source) | 0.800 → 0.879 / 0.706 → 0.853 |
| Corpus effect (open − proprietary), 95 % cluster-bootstrap CI | HorusEye 0.276 [0.231, 0.308]; Kitsune 0.300 [0.212, 0.331] |
| Architecture gap (HorusEye − Kitsune), 95 % CI | proprietary 0.057 [0.021, 0.074]; open-source 0.033 [0.004, 0.100] |
| Benign test packets entering each ROC (false positives allowed at 5×10⁻⁵) | 156,505 (≤7) / 124,792 (≤6) |
| Training-free kNN, macro TPR proprietary / open-source | 0.142 / 0.482 |
| Cross-corpus transfer: realized FPR of open-source-trained models on proprietary benign traffic (calibrated 5×10⁻⁵ threshold) | HorusEye 22.8 %, Kitsune 26.6 % |
| Corpus distance (gradient boosting, 5-fold CV AUC, packet features) | 1.000 |
| Gateway subset, HorusEye trained and tested on gateways / tested on all devices | 0.639 / 0.002 |

## Repository map

| Folder | Content | Paper |
|---|---|---|
| `horuseye_artifact/` | HorusEye evaluation code and released models (third-party; see its `LICENSE_NOTICE.md`), with our patched `control_plane.py`, `patch_control_plane.diff` listing every change and `REDACTIONS.md` (two privacy redactions in the pre-processing code) | §2, §3 (protocol) |
| `scripts/setup_datasets.sh` | builds `horuseye_artifact/DataSets/` from the downloads (relative symlinks) | — |
| `scripts/run_eval.py`, `scripts/run_all.sh`, `scripts/compare_paper.py` | reproduction of the eight configurations R1–R8 with the released models and comparison with the submitted tables | Table 2, §4.1 |
| `scripts/audit/` | data audit (`audit_stage1.py`) and pcap profiler (`profile_datasets.py`) | Table 1, §3 |
| `scripts/analysis/` | all analyses: fast re-evaluation and raw scores (`b1_fasteval.py`, `hekit.py`), calibration and transfer (`b2_calibration.py`), feature overlap (B2x, same file), bootstrap CIs (`b3_bootstrap.py`), Gulliver retraining and seeds (`b4_gulliver.py`), composition / volume / duration ablation (`b5_ablation.py`, `glane.py`, `g1`–`g5`, `c3`, `c3b`, `c4`, `c5`), corpus distance (`b6_distance.py`), TPR vs FPR (`c1.py`), tail attribution (`g2.py`), full reference-detector metrics (`c4_full_metrics.py`), summary tables (`b8_table.py`, `retraining_summary.py`, `build_supplement.py`) | §4.1–§4.3, §5.1 |
| `scripts/figures/` | figure scripts sharing `figstyle.py` | Figs. 2–4 and supplement |
| `results/tables/` | result tables (CSV/MD); `RETRAINING_SUMMARY.md` lists every re-run or retrained model | all results |
| `results/figures/` | `fig_tpr_fpr.pdf` (Fig. 2), `fig_scores_both_v1n.pdf` (Fig. 3), `fig_ablation_v2.pdf` (Fig. 4) | Figs. 2–4 |
| `supplement/` | online supplement (index: `supplement/SUPPLEMENT.md`) | supplement |

Fig. 1 (architecture) is a diagram without data and is not generated here.

## Data

See [`data/DATA.md`](data/DATA.md). In brief:
- **HorusEye extracted features** (both benign corpora and the original attacks): [Google Drive](https://drive.google.com/u/0/uc?id=1k-oTsxVD3fkZnjwj-4XclVhQdAC36nLd&export=download).
- **HorusEye original pcaps** (optional): [Google Drive](https://drive.google.com/u/0/uc?id=191CmJYWszlSmIitfid2J53UMYtiaqhhe&export=download).
- **New-attack dataset** (16 attacks + HTTP DDoS): [Google Drive](https://drive.google.com/file/d/1cmBi8CsCUiSBfJw6zDzF2ueNpdqR9OZb/view?usp=sharing).
- **Public sources of the attacks:**
  - IoT-23: https://www.stratosphereips.org/datasets-iot23
  - Kang et al. IoT Network Intrusion Dataset: https://doi.org/10.21227/q70p-q449
  - MQTT-IoT-IDS2020: https://doi.org/10.21227/bhxy-ep04
  - Edge-IIoTset: https://doi.org/10.21227/mbc1-1h68
- **Public source of the open-source benign corpus:** UNSW IoT traces, https://iotanalytics.unsw.edu.au/iottraces.html.

The **proprietary benign features come from the HorusEye release; their raw captures are not public.**

## Reproduction

Hardware used: Apple M4 Max (16 cores, 64 GB RAM). Evaluation runs on CPU; Magnifier retraining and fast scoring used
Apple MPS. CUDA works as well, because the patch only adds a CPU/MPS fallback.

```bash
# 1. environment (Python 3.8)
python3.8 -m venv .venv && source .venv/bin/activate
pip install -r requirements.txt

# 2. data (see data/DATA.md for the downloads and the macOS case warning)
scripts/setup_datasets.sh data/horuseye_features/DataSets data/new_attacks/Datasets

# 3. reproduction with the released models: R1–R8 (CPU), then comparison with the submitted tables
PYTHON=python scripts/run_all.sh
python scripts/compare_paper.py

# 4. analyses (outputs in outputs/; raw scores in outputs/rows/)
python scripts/analysis/b1_fasteval.py          # B1/B1x + raw scores used by B2, B3, C1, G2 and the score figures
python scripts/analysis/b2_calibration.py       # B2 calibration/transfer, B2x feature overlap
python scripts/analysis/b3_bootstrap.py         # B3 confidence intervals
python scripts/analysis/b4_gulliver.py          # B4 Gulliver retraining and seeds
python scripts/analysis/b5_ablation.py auto all14 rand5_a rand5_b cam8 gw6 vol_match os_days1 os_days2 os_days3 os_days5
python scripts/analysis/b6_distance.py          # corpus distance
python scripts/analysis/c1.py                   # TPR vs FPR
PYTHON=python scripts/analysis/lane.sh "g1:30 g2:20 g3:120 g4:90 g5:120"   # GPU/MPS tasks
PYTHON=python scripts/analysis/lane.sh "c3:150 c4:90 c5:60"                 # CPU tasks
python scripts/analysis/c3b.py                  # Kitsune on the remaining ablation setups
python scripts/analysis/c4_full_metrics.py      # full reference-detector metrics (supplement)

# 5. figures (Figs. 2 and 4 need only results/tables/; Fig. 3 and the supplement figures need outputs/rows/)
python scripts/figures/fig_tpr_fpr.py
python scripts/figures/fig_ablation_v2.py
python scripts/figures/fig_scores_style.py
```

**Expected key numbers** (macro over the 16 new attacks, TPR at FPR ≤ 5×10⁻⁵): HorusEye **0.149** (proprietary) / **0.425** (open-source), Kitsune **0.092** / **0.392**. `compare_paper.py` should report:
- differences from the submitted tables of at most 0.0005;
- one exception, the MQTT brute-force Magnifier PR-AUC (0.088 printed, 0.604 reproduced);
- 0.0 against the student's saved results.

**Runtimes we measured** (`results/tables/runtimes.csv`):
- R1–R8 together: 131.8 min on CPU, peak 11.2 GB RAM.
- HorusEye retraining and evaluation on all 14 devices: 27.2 min (MPS, 18 epochs).
- Kitsune training on all 14 devices: 9.5 min (CPU).

## Acknowledgement and attribution

- **HorusEye:** Y. Dong et al., "HorusEye: A Realtime IoT Malicious Traffic Detection Framework using Programmable Switches", USENIX Security 2023. Code: https://github.com/vicTorKd/HorusEye. The upstream repository states no license; its code in `horuseye_artifact/` remains under its authors' terms.
- **Kitsune:** Y. Mirsky et al., "Kitsune: An Ensemble of Autoencoders for Online Network Intrusion Detection", NDSS 2018. Code: https://github.com/ymirsky/Kitsune-py (MIT; notices kept in the files).
- **Student replication with new attacks:** M. Alshareef, https://github.com/Muhannad-Alshareef/HorusEye-replication-with-different-attacks.

## License

Our scripts, tables, figures and documentation are released under the MIT license ([`LICENSE`](LICENSE)). This
**excludes** `horuseye_artifact/`; see [`horuseye_artifact/LICENSE_NOTICE.md`](horuseye_artifact/LICENSE_NOTICE.md).
Please cite the paper ([`CITATION.cff`](CITATION.cff)).

## Sources of the numbers in this README

| Number(s) | Source file (in `results/tables/`) |
|---|---|
| 0.149 / 0.425, 0.092 / 0.392, ROC-AUC 0.800 / 0.879 / 0.706 / 0.853, 156,505 / 124,792 | `B1_repro.csv` (mean over the 16 attacks; `n_benign`) |
| 0.276 [0.231, 0.308], 0.300 [0.212, 0.331], 0.057 [0.021, 0.074], 0.033 [0.004, 0.100] | `B3_differences.csv` |
| kNN 0.142 / 0.482 | `B8_C4a.csv` |
| 22.8 %, 26.6 % | `B2_calibration.csv` (rows `attack = benign`, `corpus_eval ≠ corpus_train`, `calib_5e5`) |
| 1.000 | `B6_corpus_distance.csv` |
| 0.639 / 0.002 | `B8_G1.csv` |
| 3–6 points, 0.09–0.48 (L2, L4) | paper text; computed from `B3_differences.csv` (0.033, 0.057) and `B8_summary_table.csv` |
| 0.0005, 0.088 → 0.604 | `submitted_paper_tables_2_3.csv` vs. `B1_all_configs.csv` (`supplement/corrected_original_tables.md`) |
| 131.8 min, 11.2 GB, 27.2 min, 9.5 min | `runtimes.csv` |
