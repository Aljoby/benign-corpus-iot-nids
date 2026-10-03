# License notice for `horuseye_artifact/`

This folder contains third-party code that is **not** covered by the MIT license of this repository.

| Part | Origin | License found |
|---|---|---|
| HorusEye code (`control_plane.py`, `iForest_detect.py`, `load_data.py`, `FE.py`, `AfterImage.py`, `convert_model.py`, `model/`, `pcap_process/`, `iot_dect_waterflow8.p4`, `iot*.y*ml`, `params/`, `result/*_rule_all.csv`) | Dong et al., "HorusEye", USENIX Security 2023 — https://github.com/vicTorKd/HorusEye | **No license file or license statement** in the upstream repository (checked 2026-10-03). The code therefore remains under the copyright of its authors; no license is granted by this repository. |
| Student replication changes (`control_plane_annotated.py`, `model/AE_annotated.py`, `CHANGELOG_student.txt`, `new_attacks_results/`) | M. Alshareef — https://github.com/Muhannad-Alshareef/HorusEye-replication-with-different-attacks | **No license file** in the upstream repository. |
| `Kitsune/KitNET.py`, `Kitsune/corClust.py`, `netStat.py` | Y. Mirsky, Kitsune (NDSS 2018), https://github.com/ymirsky/Kitsune-py | **MIT** (copyright notice inside each file, kept unchanged) |
| `Kitsune/dA.py` | Y. Sugomori (adapted by Y. Mirsky) | **MIT** (copyright notice inside the file, kept unchanged) |
| `control_plane.py` changes for this study | this study | listed line by line in `patch_control_plane.diff` (CPU/MPS fallback, throughput off, Kitsune switch, saving of experiment-A Magnifier records, logging of ROC row counts; no change to models, data loading, seeds or metrics) |

Two privacy redactions in the pre-processing code (device MAC lists, an absolute author path) are described in `REDACTIONS.md`. Original file headers are kept unchanged. If you redistribute this folder, check the upstream repositories for a
license first, or obtain the HorusEye code from upstream and apply `patch_control_plane.diff`.
