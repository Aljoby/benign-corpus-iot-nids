# B3 — cluster-bootstrap confidence intervals

1,000 resamples of flow keys (benign and attack separately; benign keys shared across attacks and detectors of a corpus, attack keys shared across detectors). Macro = mean over the 16 new attacks (HTTP DDoS excluded). 95 % percentile intervals. Weighted metrics reproduce B1 exactly (max diff 2.2e-16).

## Macro point estimates and 95 % CIs

| Corpus | Detector | Macro TPR@5e-5 | Macro ROC-AUC |
|---|---|---|---|
| proprietary | HorusEye | 0.149 [0.125, 0.160] | 0.800 [0.727, 0.858] |
| proprietary | Kitsune | 0.092 [0.070, 0.116] | 0.706 [0.653, 0.744] |
| proprietary | Magnifier | 0.128 [0.091, 0.152] | 0.670 [0.607, 0.709] |
| open-source | HorusEye | 0.425 [0.380, 0.441] | 0.879 [0.829, 0.906] |
| open-source | Kitsune | 0.392 [0.307, 0.424] | 0.853 [0.800, 0.880] |
| open-source | Magnifier | 0.418 [0.378, 0.434] | 0.871 [0.825, 0.897] |

## Corpus effect (open-source − proprietary) and architecture gap (HorusEye − Kitsune)

| Quantity | Metric | Point | 95 % CI |
|---|---|---|---|
| corpus effect, HorusEye | tpr_5e5 | 0.276 | [0.231, 0.308] |
| corpus effect, Kitsune | tpr_5e5 | 0.300 | [0.212, 0.331] |
| corpus effect, Magnifier | tpr_5e5 | 0.291 | [0.238, 0.330] |
| architecture gap, proprietary | tpr_5e5 | 0.057 | [0.021, 0.074] |
| architecture gap, open-source | tpr_5e5 | 0.033 | [0.004, 0.100] |
| corpus effect, HorusEye | roc_auc | 0.079 | [0.002, 0.155] |
| corpus effect, Kitsune | roc_auc | 0.147 | [0.084, 0.203] |
| corpus effect, Magnifier | roc_auc | 0.201 | [0.145, 0.267] |
| architecture gap, proprietary | roc_auc | 0.094 | [0.034, 0.148] |
| architecture gap, open-source | roc_auc | 0.026 | [0.005, 0.051] |

Benign rows at or above the FPR<=5e-5 threshold (point estimate, from B1): max 7 (proprietary limit 7, open-source limit 6); per run: {'R1_A_HE': 7, 'R4_A_KIT': 7, 'R5_B_HE': 6, 'R8_B_KIT': 6}.
