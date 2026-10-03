# Tables 2–3 of the submitted manuscript, as reproduced

Re-run of the released models (`scripts/run_all.sh`, R1–R8) on the 14 attacks of the submitted paper; each cell is the reproduced value (3 decimals). Every reproduced cell is within 0.0005 of the submitted table except the one marked **bold**, a transcription error in the submitted Table 3. Macro = mean over the 14 attacks, as in the submitted paper (the revised paper uses 16 attacks and excludes HTTP DDoS). Source: `results/tables/B1_all_configs.csv`, `results/tables/submitted_paper_tables_2_3.csv`.

## Table 2 — trained on the open-source benign corpus

| Attack | Kitsune TPR≤5e-5 | TPR≤5e-4 | PR-AUC | Magnifier TPR≤5e-5 | TPR≤5e-4 | PR-AUC | HorusEye TPR≤5e-5 | TPR≤5e-4 | PR-AUC |
|---|---|---|---|---|---|---|---|---|---|
| ARP Spoofing | 0.616 | 0.745 | 0.979 | 0.714 | 0.835 | 0.987 | 0.730 | 0.841 | 0.985 |
| HTTP DDoS (control) | 0.674 | 0.744 | 0.984 | 0.728 | 0.851 | 0.994 | 0.743 | 0.858 | 0.994 |
| Uploading Attack | 0.793 | 0.839 | 0.994 | 0.748 | 0.877 | 0.997 | 0.756 | 0.887 | 0.997 |
| Hide & Seek | 0.000 | 0.000 | 0.764 | 0.000 | 0.000 | 0.697 | 0.000 | 0.000 | 0.705 |
| SSH Bruteforce | 0.945 | 0.947 | 0.985 | 0.946 | 0.950 | 0.987 | 0.946 | 0.950 | 0.988 |
| Vuln. Scanner | 0.812 | 0.849 | 0.995 | 0.870 | 0.948 | 0.998 | 0.882 | 0.951 | 0.998 |
| SQL Injection | 0.877 | 0.902 | 0.992 | 0.897 | 0.937 | 0.997 | 0.901 | 0.940 | 0.997 |
| Okiru | 0.945 | 0.958 | 0.998 | 0.985 | 0.994 | 0.999 | 0.986 | 0.994 | 1.000 |
| Ransomware | 0.005 | 0.009 | 0.175 | 0.005 | 0.007 | 0.141 | 0.005 | 0.007 | 0.148 |
| Muhstik | 0.000 | 0.000 | 0.733 | 0.000 | 0.000 | 0.711 | 0.000 | 0.000 | 0.720 |
| MQTT Bruteforce | 0.137 | 0.603 | 0.758 | 0.120 | 0.376 | 0.686 | 0.158 | 0.394 | 0.692 |
| Hakai | 0.000 | 0.000 | 0.149 | 0.000 | 0.000 | 0.221 | 0.000 | 0.000 | 0.231 |
| DoS SYN Flood | 0.467 | 0.470 | 0.585 | 0.472 | 0.478 | 0.691 | 0.472 | 0.479 | 0.696 |
| Password Attack | 0.681 | 0.748 | 0.976 | 0.768 | 0.849 | 0.991 | 0.778 | 0.854 | 0.991 |
| **Macro (14)** | 0.497 | 0.558 | 0.791 | 0.518 | 0.579 | 0.793 | 0.525 | 0.582 | 0.796 |

## Table 3 — trained on the proprietary benign corpus

| Attack | Kitsune TPR≤5e-5 | TPR≤5e-4 | PR-AUC | Magnifier TPR≤5e-5 | TPR≤5e-4 | PR-AUC | HorusEye TPR≤5e-5 | TPR≤5e-4 | PR-AUC |
|---|---|---|---|---|---|---|---|---|---|
| ARP Spoofing | 0.000 | 0.004 | 0.353 | 0.001 | 0.007 | 0.585 | 0.003 | 0.009 | 0.652 |
| HTTP DDoS (control) | 0.055 | 0.211 | 0.779 | 0.235 | 0.382 | 0.927 | 0.285 | 0.408 | 0.942 |
| Uploading Attack | 0.153 | 0.265 | 0.865 | 0.199 | 0.402 | 0.964 | 0.277 | 0.442 | 0.972 |
| Hide & Seek | 0.000 | 0.000 | 0.207 | 0.000 | 0.000 | 0.090 | 0.000 | 0.000 | 0.142 |
| SSH Bruteforce | 0.881 | 0.919 | 0.975 | 0.931 | 0.941 | 0.971 | 0.936 | 0.942 | 0.975 |
| Vuln. Scanner | 0.000 | 0.004 | 0.417 | 0.000 | 0.012 | 0.741 | 0.002 | 0.018 | 0.789 |
| SQL Injection | 0.000 | 0.000 | 0.565 | 0.000 | 0.000 | 0.783 | 0.000 | 0.000 | 0.824 |
| Okiru | 0.085 | 0.808 | 0.981 | 0.446 | 0.877 | 0.994 | 0.696 | 0.902 | 0.996 |
| Ransomware | 0.007 | 0.011 | 0.112 | 0.005 | 0.007 | 0.086 | 0.005 | 0.007 | 0.121 |
| Muhstik | 0.000 | 0.000 | 0.179 | 0.000 | 0.000 | 0.091 | 0.000 | 0.000 | 0.144 |
| MQTT Bruteforce | 0.000 | 0.000 | 0.378 | 0.000 | 0.555 | **0.604** (submitted: 0.088) | 0.000 | 0.596 | 0.621 |
| Hakai | 0.000 | 0.000 | 0.075 | 0.000 | 0.000 | 0.080 | 0.000 | 0.000 | 0.126 |
| DoS SYN Flood | 0.347 | 0.414 | 0.556 | 0.461 | 0.470 | 0.567 | 0.466 | 0.472 | 0.602 |
| Password Attack | 0.000 | 0.000 | 0.180 | 0.000 | 0.000 | 0.603 | 0.000 | 0.000 | 0.669 |
| **Macro (14)** | 0.109 | 0.188 | 0.473 | 0.163 | 0.261 | 0.578 | 0.191 | 0.271 | 0.612 |

