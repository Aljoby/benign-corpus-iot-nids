# B6 (part 3 only) — corpus distance between the two benign training corpora

Extra block (not in the requested order) run because two \TBD keys need it. Balanced 200000 rows per corpus (burst: all available if fewer), 5-fold stratified CV ROC-AUC (1 = perfectly separable).

## packet (100 stats)

- CV ROC-AUC: logistic 0.8452 ± 0.0016; gradient boosting 1.0000 ± 0.0000
- Top-10 (logistic, sign = corpus with larger values): HpHp_l0.01_w(+61.91, open-source); MI_l0.01_w(-24.45, proprietary); HH_l0.01_w(-24.38, proprietary); HHjit_l0.01_w(-18.64, proprietary); HHjit_l5_w(-17.66, proprietary); HHjit_l3_w(+15.27, open-source); HpHp_l0.1_w(-14.49, proprietary); HpHp_l3_w(-13.32, proprietary); HpHp_l5_w(+11.39, open-source); HHjit_l1_w(+9.02, open-source)
- Top-10 (boosting, permutation importance in ROC-AUC): HHjit_l0.01_std(0.002); HH_l0.01_mag(0.001); MI_l0.01_w(0.001); HHjit_l0.01_mean(0.000); HpHp_l3_mean(0.000); HpHp_l5_mean(0.000); HpHp_l0.01_w(0.000); HpHp_l0.01_rad(0.000); HpHp_l1_mean(0.000); HH_l0.1_mag(0.000)

## burst (pk_num, sum_len, proto, ports)

- CV ROC-AUC: logistic 0.9025 ± 0.0011; gradient boosting 0.9991 ± 0.0001
- Top-10 (logistic, sign = corpus with larger values): port_11(-1.72, proprietary); port_2(+1.24, open-source); pk_num(+1.17, open-source); port_1(-1.07, proprietary); port_3(+1.07, open-source); port_10(+0.96, open-source); port_5(-0.87, proprietary); port_9(-0.79, proprietary); udp_tcp(+0.74, open-source); port_15(-0.70, proprietary)
- Top-10 (boosting, permutation importance in ROC-AUC): sum_len(0.119); pk_num(0.053); port_11(0.053); port_2(0.008); port_12(0.006); udp_tcp(0.004); port_13(0.002); port_3(0.001); port_15(0.001); port_8(0.000)

