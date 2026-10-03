# Data

No data is included in this repository. Download the archives below, extract them **outside** `horuseye_artifact/`,
then run `scripts/setup_datasets.sh`, which builds `horuseye_artifact/DataSets/` from relative symlinks.

## Downloads used by the experiments

| What | Source | Used for |
|---|---|---|
| HorusEye extracted features (`DataSets`) — benign feature files of both corpora (proprietary testbed and UNSW open-source) and the original 15 attacks | HorusEye authors, Google Drive: https://drive.google.com/u/0/uc?id=1k-oTsxVD3fkZnjwj-4XclVhQdAC36nLd&export=download (linked from https://github.com/vicTorKd/HorusEye) | all experiments (benign training and test data) |
| New-attack dataset (`Datasets`) — 16 new attacks + HTTP DDoS, as pcaps and as extracted features | Student replication, Google Drive: https://drive.google.com/file/d/1cmBi8CsCUiSBfJw6zDzF2ueNpdqR9OZb/view?usp=sharing (linked from https://github.com/Muhannad-Alshareef/HorusEye-replication-with-different-attacks) | attack test data |
| HorusEye original pcaps (`Pcap`) — optional | HorusEye authors, Google Drive: https://drive.google.com/u/0/uc?id=191CmJYWszlSmIitfid2J53UMYtiaqhhe&export=download | data audit / pcap profiling only (`scripts/audit/`) |

**Proprietary benign corpus.** Its features come from the HorusEye release. The raw captures behind these features
are **not public**: the released pcaps match the open-source corpus and one proprietary device (linksys router),
but not the other 13 proprietary devices (see `scripts/audit/audit_stage1.py`). The proprietary corpus can therefore
only be varied at the level of feature files, not capture days.

## Public sources of the attack captures and of the open-source benign corpus

| Dataset | Used for | Link |
|---|---|---|
| IoT-23 (Garcia et al., 2020) | Okiru, Hakai, Muhstik, Hide & Seek, Torii | https://www.stratosphereips.org/datasets-iot23 (Zenodo: https://doi.org/10.5281/zenodo.4743746) |
| IoT Network Intrusion Dataset (Kang et al., 2019) | ARP spoofing (MITM), SYN flood | https://doi.org/10.21227/q70p-q449 (IEEE Dataport) |
| MQTT-IoT-IDS2020 (Hindy et al., 2020) | SSH brute force, MQTT brute force, UDP scan | https://doi.org/10.21227/bhxy-ep04 (IEEE Dataport) |
| Edge-IIoTset (Ferrag et al., 2022) | SQL injection, XSS, uploading, password, vulnerability scanner, ransomware | https://doi.org/10.21227/mbc1-1h68 (IEEE Dataport) |
| UNSW IoT traces (Sivanathan et al., 2019) | open-source benign corpus (as released in the HorusEye features) | https://iotanalytics.unsw.edu.au/iottraces.html |

The attack captures are contiguous prefixes of the public traces; labels are capture-level (every packet of an
attack capture counts as malicious).

## Expected layout (suggested)

```
data/                                    (git-ignored except this file)
├── horuseye_features/DataSets/          extracted HorusEye features (from the "DataSets" archive)
│   ├── normal-flow-level-device_1_dou_burst_14_add_pk/<14 devices>/   burst features, 6 files per device
│   ├── normal-kitsune_test/<14 devices>/                             packet features, 6 files per device
│   ├── Open-Source/normal-flow-level-device_1_dou_burst_14_add_pk/   13 files
│   ├── Open-Source/normal_kitsune/                                   13 files
│   └── Anomaly/{attack_kitsune, attack-flow-level-device_1_dou_burst_14_add_pk}/<15 original attacks>/
├── new_attacks/Datasets/                extracted new-attack dataset (from "Datasets.rar")
│   └── Anomaly/{attack_kitsune, attack-flow-level-device_1_dou_burst_14_add_pk}/<17 attacks>/
└── horuseye_pcap/Pcap/                  optional, original pcaps
```

> **macOS:** the default file system is case-insensitive, so `DataSets` and `Datasets` are the **same name**.
> Keep the two archives in separate parent folders, as above. The HorusEye "DataSets" archive is a
> gzip-compressed tar (`tar -xf` handles it).

Then:

```bash
scripts/setup_datasets.sh data/horuseye_features/DataSets data/new_attacks/Datasets
# -> horuseye_artifact/DataSets/ with 37 relative links: the benign folders of the feature release and
#    the 17 attack folders of the new-attack dataset (use --original-attacks for the 15 original attacks)
```
