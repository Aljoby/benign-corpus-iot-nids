# B5 / B5x — composition, volume and duration ablation

Status: COMPLETE. Epochs per model: 18 (original 20; first-epoch time 89.9s on mps; cap rule: ≤45 min/model and B5+B5x ≤ 3 h, same epochs for every model incl. the all14 reference). Planned (priority order): ['all14_seed1', 'all14_seed2'].

Gulliver is retrained on each proprietary subset; the open-source day sweep keeps the artifact rules (as in the paper's open-source configuration). Test: benign test files of the same devices (proprietary) / standard open-source test days, all 17 attacks; macro over the 16 new attacks.

| Subset | corpus | devices | train rows (packets) | n benign test | HorusEye macro TPR@5e-5 | HorusEye macro ROC-AUC | Magnifier macro TPR@5e-5 | Magnifier macro ROC-AUC | best epoch |
|---|---|---|---|---|---|---|---|---|---|
| all14 | prop. | philips_camera;360_camera;ezviz_camera;hichip_battery_camera;mercury_wirecamera;skyworth_camera;tplink_camera;xiaomi_camera;aqara_gateway;gree_gateway;ihorn_gateway;tcl_gateway;xiaomi_gateway;linksys_router | 3629498 | 156505 | 0.1469 | 0.8220 | 0.1397 | 0.7302 | 11 |
| all14_seed1 | prop. | philips_camera;360_camera;ezviz_camera;hichip_battery_camera;mercury_wirecamera;skyworth_camera;tplink_camera;xiaomi_camera;aqara_gateway;gree_gateway;ihorn_gateway;tcl_gateway;xiaomi_gateway;linksys_router | 3629498 | 156505 | 0.1322 | 0.8131 | 0.1225 | 0.6955 | 7 |
| all14_seed2 | prop. | philips_camera;360_camera;ezviz_camera;hichip_battery_camera;mercury_wirecamera;skyworth_camera;tplink_camera;xiaomi_camera;aqara_gateway;gree_gateway;ihorn_gateway;tcl_gateway;xiaomi_gateway;linksys_router | 3629498 | 156505 | 0.1476 | 0.7900 | 0.1381 | 0.6782 | 17 |
| vol_match | prop. | philips_camera;360_camera;ezviz_camera;hichip_battery_camera;mercury_wirecamera;skyworth_camera;tplink_camera;xiaomi_camera;aqara_gateway;gree_gateway;ihorn_gateway;tcl_gateway;xiaomi_gateway;linksys_router | 2011148 | 156505 | 0.1236 | 0.8596 | 0.1148 | 0.7046 | 6 |
| cam8 | prop. | philips_camera;360_camera;ezviz_camera;hichip_battery_camera;mercury_wirecamera;skyworth_camera;tplink_camera;xiaomi_camera | 2987894 | 124124 | 0.2139 | 0.8132 | 0.2018 | 0.7065 | 1 |
| gw6 | prop. | aqara_gateway;gree_gateway;ihorn_gateway;tcl_gateway;xiaomi_gateway;linksys_router | 641604 | 32318 | 0.6395 | 0.9693 | 0.6395 | 0.9322 | 0 |
| rand5_a | prop. | ezviz_camera;mercury_wirecamera;tplink_camera;aqara_gateway;tcl_gateway | 1171120 | 48578 | 0.0797 | 0.7480 | 0.0797 | 0.7254 | 2 |
| rand5_b | prop. | ezviz_camera;hichip_battery_camera;tplink_camera;xiaomi_camera;ihorn_gateway | 1192793 | 44583 | 0.0846 | 0.7009 | 0.0841 | 0.6452 | 9 |
| os_days1 | open | files 0 | 402162 | 124792 | 0.3904 | 0.9066 | 0.3905 | 0.9050 | 11 |
| os_days2 | open | files 0,2 | 772390 | 124792 | 0.4541 | 0.8915 | 0.4542 | 0.8749 | 4 |
| os_days3 | open | files 0,2,4 | 1138497 | 124792 | 0.4017 | 0.9096 | 0.4018 | 0.9061 | 8 |
| os_days5 | open | files 0,2,4,6,7 | 2011147 | 124792 | 0.3764 | 0.8755 | 0.3765 | 0.8689 | 8 |

Reference (artifact models, 16 attacks): proprietary macro TPR 0.1492 / ROC-AUC 0.7998; open-source 0.4251 / 0.8792.
Magnifier/HorusEye retraining spread, all14 (n=3 seeds): macro TPR 0.1422 ± 0.0087 (sd), ROC-AUC 0.8084 ± 0.0165.
