# B4 — Gulliver retrained and seed spread

Magnifier fixed to the artifact model of each corpus; Gulliver retrained with the original hyper-parameters (iForest 200 trees, max_samples 5000, contamination 0.15 / 0.05 ports) on that corpus's burst training rows. HTTP DDoS is the Gulliver validation attack in the original code and was kept. Macro over the 16 new attacks.

Artifact reference (proprietary-trained rules, both corpora): proprietary macro TPR 0.1492 / ROC-AUC 0.7998; open-source 0.4251 / 0.8792.

| Corpus | seed | rules = artifact? | passed benign | macro TPR@5e-5 | macro ROC-AUC |
|---|---|---|---|---|---|
| proprietary | 114514 | True | 72528 / 156505 | 0.1492 | 0.7998 |
| proprietary | 0 | False | 76420 / 156505 | 0.1492 | 0.8138 |
| proprietary | 1 | False | 76545 / 156505 | 0.1492 | 0.8139 |
| proprietary | 2 | False | 76646 / 156505 | 0.1510 | 0.8142 |
| proprietary | 3 | False | 76628 / 156505 | 0.1492 | 0.8144 |
| proprietary | 4 | False | 72609 / 156505 | 0.1492 | 0.8000 |
| open-source | 114514 | False | 99137 / 124792 | 0.4222 | 0.9505 |
| open-source | 0 | False | 96825 / 124792 | 0.4236 | 0.9550 |
| open-source | 1 | False | 99052 / 124792 | 0.4222 | 0.9576 |
| open-source | 2 | False | 98915 / 124792 | 0.4217 | 0.9497 |
| open-source | 3 | False | 88235 / 124792 | 0.4236 | 0.9437 |
| open-source | 4 | False | 98489 / 124792 | 0.4216 | 0.9560 |

proprietary, seeds 0-4 (n=5): macro TPR@5e-5 0.1496 ± 0.0008 (sd), range 0.1492–0.1510; macro ROC-AUC 0.8113 ± 0.0063.
open-source, seeds 0-4 (n=5): macro TPR@5e-5 0.4225 ± 0.0010 (sd), range 0.4216–0.4236; macro ROC-AUC 0.9524 ± 0.0057.
