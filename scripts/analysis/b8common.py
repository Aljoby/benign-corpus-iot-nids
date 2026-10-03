"""Shared helpers for the B8 tasks (G1-G5, C1-C6)."""
import datetime
import math
import os
import sys
import time

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
import hekit as hk  # noqa: E402
import numpy as np  # noqa: E402
import pandas as pd  # noqa: E402

T = os.path.abspath(hk.OUTPUTS)
T0 = time.time()
BOX_MIN = float(os.environ.get("BOX_MIN", "60"))
# optional global stop time, e.g. HARD_STOP="2026-10-03 00:05" (none by default)
HARD_STOP = (datetime.datetime.strptime(os.environ["HARD_STOP"], "%Y-%m-%d %H:%M") if os.environ.get("HARD_STOP")
             else datetime.datetime.max)


def over_box(margin_min=0.0):
    return (time.time() - T0) / 60.0 > BOX_MIN - margin_min or datetime.datetime.now() > HARD_STOP


def minutes_left():
    left_box = BOX_MIN - (time.time() - T0) / 60.0
    if HARD_STOP == datetime.datetime.max:
        return left_box
    return min(left_box, (HARD_STOP - datetime.datetime.now()).total_seconds() / 60.0)


def max_fp(n_benign, fpr=5e-5):
    return int(math.floor((fpr + 1e-6) * n_benign))


def record(task, condition, detector, m, extra=None, fname=None):
    """Append one result row (macros over the 16 new attacks + per-attack values) to outputs/B8_<task>.csv."""
    nb = int(m.n_benign.iloc[0])
    rec = {"task": task, "condition": condition, "detector": detector, "n_benign_test": nb,
           "max_fp_5e5": max_fp(nb), "max_fp_5e4": max_fp(nb, 5e-4),
           "macro_tpr_5e5": hk.macro(m, "tpr_5e5"), "macro_roc_auc": hk.macro(m, "roc_auc"),
           "macro_tpr_5e4": hk.macro(m, "tpr_5e4"), "macro_pr_auc": hk.macro(m, "pr_auc"),
           "fp_5e5_realized_max": int(m.fp_5e5.max()), "status": "ok"}
    rec.update(extra or {})
    for _, x in m.iterrows():
        rec["tpr_5e5:" + x.attack] = x.tpr_5e5
        rec["roc_auc:" + x.attack] = x.roc_auc
    p = os.path.join(T, fname or "B8_%s.csv" % task)
    new = pd.DataFrame([rec])
    if os.path.exists(p):                      # align columns (rows can carry different extra fields)
        new = pd.concat([pd.read_csv(p), new], ignore_index=True, sort=False)
    new.to_csv(p, index=False)
    hk.log("RESULT %s | %s | %s | macro TPR %.4f ROC %.4f | n_benign %d (<=%d FP)" % (
        task, condition, detector, rec["macro_tpr_5e5"], rec["macro_roc_auc"], nb, rec["max_fp_5e5"]))
    return rec


def note(task, text, fname=None):
    p = os.path.join(T, fname or "B8_%s_notes.md" % task)
    with open(p, "a") as f:
        f.write(text.rstrip() + "\n")
    hk.log("NOTE", task, text[:200])


# ---------------------------------------------------------------- subsets shared by GPU and CPU lanes
OS_ROWS = {0: 402162, 2: 370228, 4: 366107, 6: 359531, 7: 513119}


def os_volume(frac, seed=0):
    """Random fraction of the open-source training packet rows (files 0,2,4,6,7), seed 0 (C5b / G5)."""
    con, data = hk.load_benign_train("B")
    rs = np.random.RandomState(seed)
    ic = np.sort(rs.choice(len(con), int(round(frac * len(con))), replace=False))
    ib = np.sort(rs.choice(len(data), int(round(frac * len(data))), replace=False))
    return con.iloc[ic], data.iloc[ib]


def prop_files(n_files, devices=None):
    """First n of the 4 proprietary training files per device (C5a / G5)."""
    from load_data import load_iot_data, load_iot_data_seq
    order = [d for d in hk.CAM + hk.GW if devices is None or d in devices]
    con = pd.concat([load_iot_data_seq(device_list=[d], begin=0, end=n_files) for d in order], ignore_index=True)
    data = pd.concat([load_iot_data(device_list=[d], thr_time=1, begin=0, end=n_files) for d in order], ignore_index=True)
    return con, data


def enter(name):
    """Enter outputs/work/<name> (create with artifact rules if new) and run the preflight link check."""
    wd = os.path.join(T, "work", name)
    if os.path.isdir(wd):
        os.chdir(wd)
        hk.preflight()
        return wd
    return hk.workdir(name)
