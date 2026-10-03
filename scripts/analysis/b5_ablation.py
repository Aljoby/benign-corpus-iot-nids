"""B5 + B5x: retrain HorusEye (Gulliver + Magnifier) on proprietary device subsets, volume-matched data,
and open-source day subsets. Training replicates control_plane.py TRAIN mode:
- Gulliver: iForest_detect.train('all', ['pk_num','sum_len'], 80 % burst train, 20 % burst eval, HTTP-DDoS burst)
  (original hyper-parameters, random_state=114514, rules written to the work dir's result/).
- Magnifier: train_test_split(0.2, random_state=20); MinMaxScaler; Adam lr 1e-2, wd 0.01, batch 256, lr x0.1 at
  epochs*0.5; best epoch by validation ROC-AUC on (20 % benign + HTTP-DDoS rows selected by
  iForest_detect.filter(http_ddos burst, all attack packets)), as in the original.
- Device: MPS (timed vs CPU, see REVISION_STATE.md). DataLoader workers 0 (same sampler RNG). The per-epoch
  batch-16 "eval loss" loops of the original only write a log file and are skipped.
Evaluation: hekit.evaluate (benign test files of the same devices / standard open-source test days).

usage: b5_ablation.py <epochs|auto> <subset> [<subset> ...]   (subsets in priority order)
Results are appended to outputs/B5_ablation.csv after every model.
"""
import json
import os
import sys
import time

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
import hekit as hk  # noqa: E402
import numpy as np  # noqa: E402
import pandas as pd  # noqa: E402
import torch  # noqa: E402
import torch.nn as nn  # noqa: E402
import torch.optim as optim  # noqa: E402
import torch.utils.data as Data  # noqa: E402
from sklearn import preprocessing  # noqa: E402

T = os.path.abspath(hk.OUTPUTS)
OUT = os.path.join(T, "B5_ablation.csv")
STATE = os.path.join(T, "B5_state.json")
ALL14 = hk.CAM + hk.GW
OS_TRAIN_ROWS = 2011147
BUDGET_MIN_PER_MODEL = 45


def rand5(seed):
    rs = np.random.RandomState(seed)
    return sorted(rs.choice(ALL14, 5, replace=False).tolist())


SUBSETS = {  # name: (corpus, devices or os_files, vol_match, seed)
    "all14": ("A", ALL14, False, 20),
    "rand5_a": ("A", rand5(0), False, 20),
    "rand5_b": ("A", rand5(1), False, 20),
    "cam8": ("A", hk.CAM, False, 20),
    "gw6": ("A", hk.GW, False, 20),
    "vol_match": ("A", ALL14, True, 20),
    "os_days1": ("B", (0,), False, 20),
    "os_days2": ("B", (0, 2), False, 20),
    "os_days3": ("B", (0, 2, 4), False, 20),
    "os_days5": ("B", (0, 2, 4, 6, 7), False, 20),
    "all14_seed1": ("A", ALL14, False, 1),
    "all14_seed2": ("A", ALL14, False, 2),
    "rand5_a_seed1": ("A", rand5(0), False, 1),
}

_A_CACHE = {}


def proprietary_train(devices):
    """Per-device training rows (cached), concatenated in the original camera-then-gateway order."""
    for d in devices:
        if d not in _A_CACHE:
            _A_CACHE[d] = hk.load_benign_train("A", devices=[d])
    order = [d for d in hk.CAM + hk.GW if d in devices]
    con = pd.concat([_A_CACHE[d][0] for d in order], ignore_index=True)
    data = pd.concat([_A_CACHE[d][1] for d in order], ignore_index=True)
    return con, data, order


def vol_match(seed=20):
    rs = np.random.RandomState(seed)
    con_all, data_all, order = proprietary_train(ALL14)
    frac = OS_TRAIN_ROWS / len(con_all)
    cons, datas = [], []
    for d in order:
        c, b = _A_CACHE[d]
        cons.append(c.iloc[np.sort(rs.choice(len(c), int(round(len(c) * frac)), replace=False))])
        datas.append(b.iloc[np.sort(rs.choice(len(b), int(round(len(b) * frac)), replace=False))])
    return pd.concat(cons, ignore_index=True), pd.concat(datas, ignore_index=True), order, frac


def train_magnifier(df_normal_train, df_attack_eval, corpus, epochs, seed, epoch_cb=None):
    hk.setup_seed(seed)
    scaler = preprocessing.MinMaxScaler()
    tr, ev = hk.train_test_split(df_normal_train, test_size=0.2, random_state=20)
    df_eval = pd.concat([ev, df_attack_eval], axis=0)
    X_train = scaler.fit_transform(hk.features(tr))
    sub = os.path.join("params", "Open-Source") if corpus == "B" else "params"
    import pickle
    pickle.dump(scaler, open(os.path.join(sub, "scaler.pkl"), "wb"))
    X_valid = scaler.transform(hk.features(df_eval))
    y_train = torch.tensor(tr["class"].values)
    y_valid = torch.tensor(df_eval["class"].values.astype(float).reshape(-1))
    X_train, X_valid = hk.to_tensor_2d(X_train), hk.to_tensor_2d(X_valid)
    loader = Data.DataLoader(Data.TensorDataset(X_train, y_train), batch_size=256, shuffle=True, num_workers=0)
    model = hk.Magnifier(input_size=105).to(hk.DEVICE)
    crit = nn.MSELoss()
    opt = optim.Adam(model.parameters(), lr=1e-2, weight_decay=0.01)
    best, best_ep, path = 0, -1, os.path.join(sub, "CNN_DW_dilation_channel_port.pkl")
    hist = []
    ep = 0
    while ep < epochs:
        t0 = time.time()
        if ep in [epochs * 0.5, epochs * 1.0]:
            for g in opt.param_groups:
                g["lr"] *= 0.1
        model.train()
        for b_x, _ in loader:
            b_x = b_x.to(hk.DEVICE)
            loss = torch.sqrt(crit(model(b_x), b_x))
            opt.zero_grad()
            loss.backward()
            opt.step()
        model.eval()
        with torch.no_grad():
            r = np.concatenate([model.excute_RMSE(model(X_valid[i:i + 60000].to(hk.DEVICE)), X_valid[i:i + 60000].to(hk.DEVICE))
                                for i in range(0, len(X_valid), 60000)])
        fpr, tpr, _ = hk.roc_curve(y_valid.numpy(), r)
        a = hk.auc(fpr, tpr)
        if best < a:
            best, best_ep = a, ep
            torch.save(model.state_dict(), path)
        dt = time.time() - t0
        hist.append({"epoch": ep, "val_auc": a, "sec": round(dt, 1)})
        hk.log("  epoch %d val_auc %.4f (%.0fs)" % (ep, a, dt))
        if epoch_cb:
            epochs = epoch_cb(ep, dt, epochs) or epochs
        ep += 1
    return best_ep, best, hist, len(tr)


def run_subset(name, epochs_req, attacks_eval, df_attack_eval, df_attack_eval_data, state):
    corpus, spec, vm, seed = SUBSETS[name]
    t_start = time.time()
    hk.workdir("b5_" + name, rules_from=None if corpus == "A" else "repro")
    hk.log("=== B5", name, "corpus", corpus, "seed", seed)
    if corpus == "A":
        if vm:
            con, data, order, frac = vol_match(seed)
        else:
            con, data, order = proprietary_train(spec)
            frac = 1.0
        devices = order
    else:
        con, data = hk.load_benign_train("B", os_files=spec)
        devices, frac = ["os_files_%s" % ",".join(map(str, spec))], 1.0
    # Gulliver retrained for proprietary subsets; open-source day sweep keeps the artifact rules (as in Table 2)
    if corpus == "A":
        tr_b, ev_b = hk.train_test_split(data, test_size=0.2, random_state=20)
        iforest_t = time.time()
        hk.iForest_detect.train('all', hk.FEATURE_SET, tr_b, ev_b, df_attack_eval_data)
        hk.log("  gulliver trained in %.0fs" % (time.time() - iforest_t))
    epochs = state.get("epochs") or epochs_req

    def cb(ep, dt, cur):  # first epoch of the first model decides the cap (rule 2/8)
        if state.get("epochs"):
            return cur
        rows_all14 = 0.8 * 3629498
        est = dt * 20 / 60.0
        cap = 20 if est <= BUDGET_MIN_PER_MODEL else int(BUDGET_MIN_PER_MODEL * 60 // dt)
        # whole B5+B5x must fit 3 h: estimate the training rows of the planned priority list
        planned = state["planned_rows"]
        tot_min = sum(planned) / rows_all14 * dt * cap / 60.0 + 4 * len(planned)
        while tot_min > state["budget_min"] and cap > 1:
            cap -= 1
            tot_min = sum(planned) / rows_all14 * dt * cap / 60.0 + 4 * len(planned)
        state.update(epochs=cap, first_epoch_sec=round(dt, 1), est_total_min=round(tot_min, 1))
        json.dump(state, open(STATE, "w"), indent=1)
        hk.log("  CAP DECISION: epoch %.0fs -> epochs=%d (est. total %.0f min)" % (dt, cap, tot_min))
        return cap

    best_ep, best_auc, hist, n_tr = train_magnifier(con, df_attack_eval, corpus, epochs, seed, epoch_cb=cb)
    # evaluate
    con_b, data_b = hk.load_benign_test(corpus, devices=None if corpus == "B" else devices)
    sub = os.path.join("params", "Open-Source") if corpus == "B" else "params"
    sc = hk.MagScorer(os.path.join(sub, "CNN_DW_dilation_channel_port.pkl"), os.path.join(sub, "scaler.pkl"))
    rows = []
    for det, g in (("HorusEye", True), ("Magnifier", False)):
        m, _ = hk.evaluate(con_b, data_b, attacks_eval, sc, g, tag=name + "/" + det)
        rec = {"subset": name, "corpus": corpus, "devices": ";".join(devices), "n_devices": len(devices) if corpus == "A" else None,
               "n_train_rows": len(con), "n_train_rows_magnifier_80pct": n_tr, "n_train_burst_rows": len(data),
               "volume_fraction": round(frac, 4), "model": det, "seed": seed, "epochs": state.get("epochs") or epochs,
               "best_epoch": best_ep, "best_val_auc": round(best_auc, 4), "n_benign_test": int(m.n_benign.iloc[0]),
               "gulliver_rules": "retrained" if corpus == "A" else "artifact (proprietary-trained)",
               "macro_tpr_5e5": hk.macro(m, "tpr_5e5"), "macro_tpr_5e4": hk.macro(m, "tpr_5e4"),
               "macro_roc_auc": hk.macro(m, "roc_auc"), "macro_pr_auc": hk.macro(m, "pr_auc"),
               "minutes": round((time.time() - t_start) / 60, 1)}
        for _, x in m.iterrows():
            rec["tpr_5e5:" + x.attack] = x.tpr_5e5
            rec["roc_auc:" + x.attack] = x.roc_auc
        rows.append(rec)
    df = pd.DataFrame(rows)
    df.to_csv(OUT, mode="a", header=not os.path.exists(OUT), index=False)
    pd.DataFrame(hist).to_csv(os.path.join(T, "logs", "B5_epochs_%s.csv" % name), index=False)
    hk.log("=== B5 done", name, "HE macro tpr %.4f roc %.4f | %.1f min" % (rows[0]["macro_tpr_5e5"], rows[0]["macro_roc_auc"], rows[0]["minutes"]))


def main():
    epochs_req = sys.argv[1]
    names = sys.argv[2:]
    state = json.load(open(STATE)) if os.path.exists(STATE) else {}
    if epochs_req != "auto":
        state["epochs"] = int(epochs_req)
    state.setdefault("budget_min", 165)  # 3 h box minus data loading / margin
    hk.workdir("b5_common")
    df_attack = hk.load_iot_attack_seq('all')            # as control_plane TRAIN mode (all 17 student attacks)
    df_attack_eval_data = hk.load_iot_attack(attack_name='http_ddos', thr_time=1)
    df_attack_eval = hk.iForest_detect.filter(df_attack_eval_data, df_attack)
    hk.log("attack eval rows (http_ddos-filtered packets):", len(df_attack_eval))
    attacks_eval = hk.load_attacks()
    # planned training rows (80 %) for the cap estimate, in priority order
    sizes = {}
    for n in names:
        c, spec, vm, _ = SUBSETS[n]
        if c == "A":
            con, _, _ = proprietary_train(spec)
            sizes[n] = 0.8 * (OS_TRAIN_ROWS if vm else len(con))
        else:
            os_rows = {0: 402162, 2: 370228, 4: 366107, 6: 359531, 7: 513119}  # DATA_AUDIT.md
            sizes[n] = 0.8 * sum(os_rows[i] for i in spec)
    state["planned_rows"] = [sizes[n] for n in names]
    state["planned"] = names
    state["subset_devices"] = {n: SUBSETS[n][1] for n in names if SUBSETS[n][0] == "A"}
    json.dump(state, open(STATE, "w"), indent=1, default=list)
    for n in names:
        try:
            run_subset(n, int(epochs_req) if epochs_req != "auto" else 20, attacks_eval, df_attack_eval,
                       df_attack_eval_data, state)
        except Exception as e:  # rule 7: log, skip, continue
            import traceback
            hk.log("ERROR in", n, repr(e))
            traceback.print_exc()
        json.dump(state, open(STATE, "w"), indent=1, default=list)


if __name__ == "__main__":
    main()
