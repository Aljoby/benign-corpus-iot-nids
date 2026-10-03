"""GPU-lane training helper (G3-G5): retrain HorusEye (Gulliver + Magnifier) like B5, with a choice of checkpoint rule.
select='auc'          : original rule (best validation ROC-AUC on 20 % benign + HTTP-DDoS-filtered attack packets)
select='benign_loss'  : lowest mean reconstruction RMSE on the 20 % benign validation split only (no attack packets)
Gulliver: retrained with the original hyper-parameters when retrain_gulliver=True (its HTTP-DDoS 'eval' only prints a
report; there is a single configuration, so nothing is selected with attack data). Otherwise artifact rules.
"""
import os
import pickle
import sys
import time

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
import b8common as c  # noqa: E402
import hekit as hk  # noqa: E402
import numpy as np  # noqa: E402
import pandas as pd  # noqa: E402
import torch  # noqa: E402
import torch.nn as nn  # noqa: E402
import torch.optim as optim  # noqa: E402
import torch.utils.data as Data  # noqa: E402
from sklearn import preprocessing  # noqa: E402

_ATT = {}


def attack_eval():
    if not _ATT:
        df_attack = hk.load_iot_attack_seq('all')
        _ATT["burst"] = hk.load_iot_attack(attack_name='http_ddos', thr_time=1)
        _ATT["pk"] = hk.iForest_detect.filter(_ATT["burst"], df_attack)
        _ATT["eval"] = hk.load_attacks()
    return _ATT


def train(con, epochs, select, seed=20, deadline_min=None, sub="params"):
    hk.setup_seed(seed)
    scaler = preprocessing.MinMaxScaler()
    tr, ev = hk.train_test_split(con, test_size=0.2, random_state=20)
    X_train = scaler.fit_transform(hk.features(tr))
    os.makedirs(sub, exist_ok=True)
    pickle.dump(scaler, open(os.path.join(sub, "scaler.pkl"), "wb"))
    X_ben = hk.to_tensor_2d(scaler.transform(hk.features(ev)))
    if select == "auc":
        df_eval = pd.concat([ev, attack_eval()["pk"]], axis=0)
        X_valid = hk.to_tensor_2d(scaler.transform(hk.features(df_eval)))
        y_valid = df_eval["class"].values.astype(float).reshape(-1)
    X_train = hk.to_tensor_2d(X_train)
    loader = Data.DataLoader(Data.TensorDataset(X_train, torch.tensor(tr["class"].values)), batch_size=256, shuffle=True, num_workers=0)
    model = hk.Magnifier(input_size=105).to(hk.DEVICE)
    crit = nn.MSELoss()
    opt = optim.Adam(model.parameters(), lr=1e-2, weight_decay=0.01)
    path = os.path.join(sub, "CNN_DW_dilation_channel_port.pkl")
    best, best_ep, hist, t_start = None, -1, [], time.time()

    def rmse(X):
        with torch.no_grad():
            return np.concatenate([model.excute_RMSE(model(X[i:i + 60000].to(hk.DEVICE)), X[i:i + 60000].to(hk.DEVICE))
                                   for i in range(0, len(X), 60000)])
    for ep in range(epochs):
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
        ben_loss = float(rmse(X_ben).mean())
        if select == "auc":
            fpr, tpr, _ = hk.roc_curve(y_valid, rmse(X_valid))
            crit_val, better = hk.auc(fpr, tpr), (lambda a, b: b is None or a > b)
        else:
            crit_val, better = ben_loss, (lambda a, b: b is None or a < b)
        if better(crit_val, best):
            best, best_ep = crit_val, ep
            torch.save(model.state_dict(), path)
        hist.append({"epoch": ep, "benign_val_rmse": ben_loss, "criterion": crit_val, "sec": round(time.time() - t0, 1)})
        hk.log("  epoch %d crit %.5f benign_val_rmse %.5f (%.0fs)" % (ep, crit_val, ben_loss, time.time() - t0))
        if deadline_min is not None and (time.time() - t_start) / 60 > deadline_min:
            hk.log("  STOP: training deadline reached after epoch %d (PARTIAL)" % ep)
            return best_ep, best, hist, len(tr), ep + 1, True
    return best_ep, best, hist, len(tr), epochs, False


def run(task, name, corpus, con, data, epochs, select, test_devices=None, retrain_gulliver=True, deadline_min=None, extra=None):
    """Train in work/<task>_<name>/ and evaluate HorusEye + Magnifier on the same devices' benign test set."""
    t0 = time.time()
    hk.workdir("%s_%s" % (task, name), rules_from=None if retrain_gulliver else "repro")
    A = attack_eval()
    if retrain_gulliver:
        tr_b, ev_b = hk.train_test_split(data, test_size=0.2, random_state=20)
        hk.iForest_detect.train('all', hk.FEATURE_SET, tr_b, ev_b, A["burst"])
    sub = os.path.join("params", "Open-Source") if corpus == "B" else "params"
    best_ep, best, hist, n_tr, ep_done, partial = train(con, epochs, select, deadline_min=deadline_min, sub=sub)
    pd.DataFrame(hist).to_csv(os.path.join(c.T, "logs", "%s_%s_epochs.csv" % (task, name)), index=False)
    con_b, data_b = hk.load_benign_test(corpus, devices=test_devices)
    sc = hk.MagScorer(os.path.join(sub, "CNN_DW_dilation_channel_port.pkl"), os.path.join(sub, "scaler.pkl"))
    for det, g in (("HorusEye", True), ("Magnifier", False)):
        m, _ = hk.evaluate(con_b, data_b, A["eval"], sc, g, tag="%s %s %s" % (task, name, det))
        ex = {"corpus": corpus, "epochs_planned": epochs, "epochs_done": ep_done, "select": select, "best_epoch": best_ep,
              "n_train_rows": len(con), "gulliver": "retrained" if retrain_gulliver else "artifact rules",
              "minutes": round((time.time() - t0) / 60, 1), "status": "PARTIAL" if partial else "ok"}
        ex.update(extra or {})
        c.record(task, name, det, m, ex)
