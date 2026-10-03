"""Shared helpers for the revision analyses (B1x-B8). Reuses the artifact's own code from ../../horuseye_artifact.

Conventions
- Paths are relative to this file. A *work dir* (outputs/work/<name>/) holds a relative symlink `DataSets`
  -> ../../../horuseye_artifact/DataSets, a `result/` folder with Gulliver rules, and a `params/` folder.
  All artifact code reads './DataSets', './result', './params', so we chdir into the work dir.
- Evaluation replicates control_plane.py test mode exactly (same loaders, same 10 % benign down-sampling
  after setup_seed(20), same iForest_detect.filter / get_Anomaly_ID(0.95) / pass_ logic, passed rows
  scored 0, same TPR@FPR loop and PR-AUC/ROC-AUC), but scores each row once (cached) instead of
  re-scoring the benign rows for every attack.
- Never prints keys/IPs/MACs; only counts and metrics.
"""
import os
import pickle
import random
import sys
import time

import numpy as np
import pandas as pd
import torch

TOOLS = os.path.dirname(os.path.abspath(__file__))
RUN_REL = os.path.join(TOOLS, "..", "..", "horuseye_artifact")     # code + DataSets (built by scripts/setup_datasets.sh)
OUTPUTS = os.path.join(TOOLS, "..", "..", "outputs")                # all generated outputs (git-ignored)
sys.path.insert(0, RUN_REL)

import iForest_detect  # noqa: E402  (also does `from load_data import *`)
from load_data import (load_iot_attack, load_iot_attack_seq, load_iot_data, load_iot_data_seq,  # noqa: E402
                       open_source_load_iot_data, open_source_load_iot_data_seq)
from model import Magnifier  # noqa: E402
from sklearn.metrics import auc, precision_recall_curve, roc_curve  # noqa: E402
from sklearn.model_selection import train_test_split  # noqa: E402

CAM = ['philips_camera', '360_camera', 'ezviz_camera', 'hichip_battery_camera', 'mercury_wirecamera',
       'skyworth_camera', 'tplink_camera', 'xiaomi_camera']
GW = ['aqara_gateway', 'gree_gateway', 'ihorn_gateway', 'tcl_gateway', 'xiaomi_gateway', 'linksys_router']
ATTACKS = sorted(['UDP_scan', 'Sparta', 'Muhstik', 'Password_attack', 'bruteforce', 'MITM', 'Torii',
                  'Vulnerability_scanner', 'Uploading_attack', 'Ransomware', 'http_ddos', 'Hide_and_seek',
                  'SQL_injection', 'Okiru', 'XSS_attack', 'DOS_synflooding', 'Hakai'])
NEW16 = [a for a in ATTACKS if a != 'http_ddos']
FEATURE_SET = ['pk_num', 'sum_len']
DEVICE = torch.device('mps' if torch.backends.mps.is_available() else 'cpu')


def log(*a):
    print(time.strftime('%H:%M:%S'), *a, flush=True)


def setup_seed(seed):  # identical to control_plane.setup_seed
    torch.manual_seed(seed)
    np.random.seed(seed)
    random.seed(seed)
    os.environ['PYTHONHASHSEED'] = str(seed)
    torch.backends.cudnn.benchmark = False
    torch.backends.cudnn.deterministic = True


def preflight():
    """Abort if any DataSets symlink is broken (rule: run before each block)."""
    ds = os.path.join(RUN_REL, "DataSets")
    broken = [os.path.join(r, n) for r, dd, ff in os.walk(ds) for n in dd + ff
              if os.path.islink(os.path.join(r, n)) and not os.path.exists(os.path.join(r, n))]
    if broken or not os.path.isdir(os.path.join(ds, "normal-kitsune_test")):
        raise SystemExit("PREFLIGHT FAILED: broken DataSets links %s" % broken[:5])
    log("preflight ok: all DataSets links resolve")


def workdir(name, rules_from="repro", params_from="repro"):
    """Create/enter outputs/work/<name>/ with DataSets symlink, result/ rules and params/."""
    wd = os.path.join(OUTPUTS, "work", name)
    os.makedirs(os.path.join(OUTPUTS, "work"), exist_ok=True)
    os.makedirs(os.path.join(wd, "result"), exist_ok=True)
    os.makedirs(os.path.join(wd, "params", "Open-Source"), exist_ok=True)
    link = os.path.join(wd, "DataSets")
    if not os.path.islink(link):
        os.symlink(os.path.join("..", "..", "..", "horuseye_artifact", "DataSets"), link)
    if rules_from == "repro":
        for f in ["tcp_rule_all.csv", "udp_rule_all.csv", "tcp_port_rule_all.csv", "udp_port_rule_all.csv"]:
            dst = os.path.join(wd, "result", f)
            if not os.path.exists(dst):
                with open(os.path.join(RUN_REL, "result", f), "rb") as s, open(dst, "wb") as d:
                    d.write(s.read())
    os.chdir(wd)
    preflight()
    return wd


# ---------------------------------------------------------------- data
def load_benign_test(corpus, devices=None, seed=20):
    """Benign test rows exactly as control_plane test mode (10 % down-sampling, global RNG after seed 20)."""
    setup_seed(seed)
    if corpus == 'A':
        cams = [d for d in CAM if devices is None or d in devices]
        gws = [d for d in GW if devices is None or d in devices]
        con = load_iot_data_seq(device_list=cams, begin=4, end=6) if cams else pd.DataFrame()
        if gws:
            con = con.append(load_iot_data_seq(device_list=gws, begin=4, end=6))
        data = load_iot_data(device_list=cams, thr_time=1, begin=4, end=6) if cams else pd.DataFrame()
        if gws:
            data = data.append(load_iot_data(device_list=gws, thr_time=1, begin=4, end=6))
    else:
        con = open_source_load_iot_data_seq(selected_list=[1, 3, 5, 8])
        data = open_source_load_iot_data(thr_time=1, selected_list=[1, 3, 5, 8])
    _, con = train_test_split(con, test_size=0.1)
    _, data = train_test_split(data, test_size=0.1)
    return con, data


def load_benign_train(corpus, devices=None, os_files=(0, 2, 4, 6, 7)):
    """Training rows as in control_plane TRAIN mode (idx 0-3 per device / open-source files)."""
    if corpus == 'A':
        cams = [d for d in CAM if devices is None or d in devices]
        gws = [d for d in GW if devices is None or d in devices]
        con, data = pd.DataFrame(), pd.DataFrame()
        if cams:
            con = con.append(load_iot_data_seq(device_list=cams, begin=0, end=4))
            data = data.append(load_iot_data(device_list=cams, thr_time=1, begin=0, end=4))
        if gws:
            con = con.append(load_iot_data_seq(device_list=gws, begin=0, end=4))
            data = data.append(load_iot_data(device_list=gws, thr_time=1, begin=0, end=4))
    else:
        con = open_source_load_iot_data_seq(selected_list=list(os_files))
        data = open_source_load_iot_data(thr_time=1, selected_list=list(os_files))
    return con, data


def load_attacks(names=ATTACKS):
    out = {}
    for a in names:
        out[a] = (load_iot_attack_seq(a), load_iot_attack(attack_name=a, thr_time=1))
    return out


# ---------------------------------------------------------------- scoring
_INDEX = None


def _two_d_index():
    global _INDEX
    if _INDEX is None:
        index = np.empty((0, 0))
        P, M, H, J, HP = (np.arange(4, -1, -1).reshape(5, -1), np.arange(5, 20).reshape(5, -1),
                          np.arange(20, 55).reshape(5, -1), np.arange(55, 70).reshape(5, -1),
                          np.arange(70, 105).reshape(5, -1))
        for i in range(5):
            for arr in (P, M, H, J, HP):
                index = np.append(index, arr[i])
        _INDEX = index.astype(int).tolist()
    return _INDEX


def to_tensor_2d(Xs):
    Xs = np.pad(Xs, ((0, 0), (3, 0)), 'constant')
    return torch.tensor(Xs[:, _two_d_index()].reshape(-1, 5, 21), dtype=torch.float32)


def features(df):
    return df.drop(columns=['class', 0]).values


class MagScorer:
    def __init__(self, model_path, scaler_path):
        self.scaler = pickle.load(open(scaler_path, 'rb'))
        self.m = Magnifier(input_size=105)
        self.m.load_state_dict(torch.load(model_path, map_location='cpu'), strict=False)
        self.m.to(DEVICE).eval()

    def score(self, df, bs=60000):
        if len(df) == 0:
            return np.zeros(0)
        X = to_tensor_2d(self.scaler.transform(features(df)))
        out = []
        with torch.no_grad():
            for i in range(0, len(X), bs):
                b = X[i:i + bs].to(DEVICE)
                out.append(self.m.excute_RMSE(self.m(b), b))
        return np.concatenate(out)


class KitScorer:
    def __init__(self, model_path, scaler_path):
        self.scaler = pickle.load(open(scaler_path, 'rb'))
        self.K = pickle.load(open(model_path, 'rb'))

    def score(self, df):
        # KITSUNE mode sets PORT=False -> control_plane drops the port columns [1, 2] before data_processing
        X = self.scaler.transform(df.drop(columns=['class', 0, 1, 2]).values)
        return np.array([self.K.process(X[i, ]) for i in range(X.shape[0])], dtype=float)


def artifact_scorer(kind, corpus, params_dir=None):
    p = params_dir or os.path.join(RUN_REL, "params")
    sub = os.path.join(p, "Open-Source") if corpus == 'B' else p
    if kind == 'mag':
        return MagScorer(os.path.join(sub, "CNN_DW_dilation_channel_port.pkl"), os.path.join(sub, "scaler.pkl"))
    return KitScorer(os.path.join(sub, "Kitsune_model.pkl"), os.path.join(sub, "scaler_kitsune.pkl"))


# ---------------------------------------------------------------- evaluation
def metrics(y, s):
    """Exactly control_plane.py: TPR at the last ROC point with FPR <= 5e-5(+eps) and <= 5e-4(+eps)."""
    fpr, tpr, thr = roc_curve(y, s)
    eps = 1e-6
    res = {}
    for tag, lim in (("5e5", 5e-5), ("5e4", 5e-4)):
        f = t = th = 0
        for i in range(len(fpr)):
            if fpr[i] <= lim + eps:
                f, t, th = fpr[i], tpr[i], thr[i]
            else:
                break
        res["fpr_" + tag], res["tpr_" + tag], res["thr_" + tag] = f, t, th
    precision, recall, _ = precision_recall_curve(y, s)
    res["pr_auc"] = auc(recall, precision)
    res["roc_auc"] = auc(fpr, tpr)
    nb = int((np.asarray(y) == 0).sum())
    res["n_benign"], res["n_attack"] = nb, int(len(y) - nb)
    res["fp_5e5"], res["fp_5e4"] = int(round(res["fpr_5e5"] * nb)), int(round(res["fpr_5e4"] * nb))
    return res


def evaluate(con_b, data_b, attacks, scorer, use_gulliver, keep_rows=False, pass_scored=False, tag=""):
    """Return (per-attack metrics DataFrame, optional per-row frame with key/label/score).

    pass_scored=True: Gulliver-passed rows get the model score instead of 0 (block B1x)."""
    con_b = con_b.reset_index(drop=True)
    b_scores = scorer.score(con_b)                              # benign scored once
    rows, per_row = [], []
    for a, (con_a, data_a) in attacks.items():
        con_a = con_a.reset_index(drop=True)
        con_a.index = con_a.index + len(con_b)                  # unique row ids
        a_scores = scorer.score(con_a)
        cache = np.concatenate([b_scores, a_scores])
        df_test_con = pd.concat([con_b, con_a], axis=0)
        df_test_data = pd.concat([data_b, data_a], axis=0)
        df_test_data.dropna(axis=0, inplace=True)
        df_test_con = iForest_detect.filter(df_test_data, df_test_con)
        if use_gulliver:
            pred = iForest_detect.test(['all'], FEATURE_SET, df_test_data)
            anomaly_df = iForest_detect.get_Anomaly_ID(pred, 0.95)
            scored = iForest_detect.filter(anomaly_df, df_test_con)
            passed = iForest_detect.pass_(anomaly_df, df_test_con)
        else:
            scored, passed = df_test_con, df_test_con.iloc[0:0]
        y = np.concatenate([(scored['class'].values != 0).astype(int), (passed['class'].values != 0).astype(int)])
        s = np.concatenate([cache[scored.index.values],
                            cache[passed.index.values] if pass_scored else np.zeros(len(passed))])
        m = metrics(y, s)
        m.update(attack=a, n_scored_benign=int((scored['class'].values == 0).sum()),
                 n_passed_benign=int((passed['class'].values == 0).sum()),
                 n_passed_attack=int((passed['class'].values != 0).sum()))
        rows.append(m)
        if keep_rows:
            keys = np.concatenate([scored[0].values, passed[0].values])
            per_row.append(pd.DataFrame({"attack": a, "key": keys, "label": y, "score": s,
                                         "rid": np.concatenate([scored.index.values, passed.index.values])}))
        log(tag, a, "tpr5e5=%.4f roc=%.4f nb=%d" % (m["tpr_5e5"], m["roc_auc"], m["n_benign"]))
    out = pd.DataFrame(rows)
    return out, (pd.concat(per_row) if keep_rows else None)


def macro(df, col, names=NEW16):
    return float(df.set_index("attack").loc[[n for n in names if n in set(df.attack)], col].mean())


def gulliver_scores(con, data, scorer):
    """HorusEye scores for a benign-only set (validation / transfer): rows passed by Gulliver get 0.

    iForest_detect.test ends with a classification_report that fails when only one class is present;
    it only prints/writes a report, so it is stubbed during this call. Predictions are unchanged."""
    import contextlib

    @contextlib.contextmanager
    def no_report():
        orig = iForest_detect.classification_report
        iForest_detect.classification_report = lambda *a, **k: (
            {"abnormal": {"precision": 0, "recall": 0}, "normal": {"precision": 0, "recall": 0, "support": 0}}
            if k.get("output_dict") else "")
        try:
            yield
        finally:
            iForest_detect.classification_report = orig

    con = con.reset_index(drop=True)
    data = data.dropna(axis=0)
    s_all = scorer.score(con)
    con_f = iForest_detect.filter(data, con)
    with no_report():
        pred = iForest_detect.test(['all'], FEATURE_SET, data)
    anomaly_df = iForest_detect.get_Anomaly_ID(pred, 0.95)
    scored = iForest_detect.filter(anomaly_df, con_f)
    s = np.zeros(len(con_f))
    pos = pd.Series(np.arange(len(con_f)), index=con_f.index)
    s[pos[scored.index].values] = s_all[scored.index.values]
    return s, s_all[con_f.index.values], len(con_f), len(scored)


# ================================================================ B8 additions
def load_benign_test_dev(devices=None, seed=20, begin=4, end=6):
    """Proprietary benign test rows + per-row device labels. Same rows and same 10 % sample as
    load_benign_test('A', devices): devices are loaded one by one in the original camera-then-gateway order
    (identical concatenation order) and the device array is split with the same train_test_split call."""
    setup_seed(seed)
    order = [d for d in CAM + GW if devices is None or d in devices]
    cons, datas, dc, dd = [], [], [], []
    for d in order:
        c = load_iot_data_seq(device_list=[d], begin=begin, end=end)
        b = load_iot_data(device_list=[d], thr_time=1, begin=begin, end=end)
        cons.append(c); datas.append(b); dc += [d] * len(c); dd += [d] * len(b)
    con, data = pd.concat(cons, ignore_index=True), pd.concat(datas, ignore_index=True)
    _, con, _, dev_c = train_test_split(con, np.array(dc), test_size=0.1)
    _, data = train_test_split(data, test_size=0.1)
    return con, data, dev_c


def dev_type(d):
    return "router" if d == "linksys_router" else ("gateway" if "gateway" in d else "camera")


class ScaledScorer:
    """Base for reference detectors: MinMax scaling (fit on training rows) of the packet table used by Magnifier."""

    def __init__(self, train_df):
        from sklearn import preprocessing
        self.scaler = preprocessing.MinMaxScaler().fit(features(train_df))

    def X(self, df):
        return self.scaler.transform(features(df))


class IFScorer(ScaledScorer):
    def __init__(self, train_df, seed=0):
        super().__init__(train_df)
        from sklearn.ensemble import IsolationForest
        self.m = IsolationForest(n_estimators=100, max_samples=256, random_state=seed, n_jobs=4).fit(self.X(train_df))

    def score(self, df):
        return -self.m.score_samples(self.X(df)) if len(df) else np.zeros(0)  # higher = more anomalous


class KNNScorer(ScaledScorer):
    def __init__(self, train_df, k=5, n_ref=100000, seed=0):
        super().__init__(train_df)
        X = self.X(train_df)
        if len(X) > n_ref:
            X = X[np.random.RandomState(seed).choice(len(X), n_ref, replace=False)]
        self.ref = torch.tensor(X, dtype=torch.float32)
        self.ref_sq = (self.ref ** 2).sum(1)
        self.k = k

    def score(self, df, bs=4096):
        """Euclidean distance to the k-th nearest reference row (exact, brute force, float32 on CPU)."""
        if len(df) == 0:
            return np.zeros(0)
        Q = torch.tensor(self.X(df), dtype=torch.float32)
        out = []
        with torch.no_grad():
            for i in range(0, len(Q), bs):
                q = Q[i:i + bs]
                d2 = (q ** 2).sum(1, keepdim=True) + self.ref_sq[None, :] - 2 * q @ self.ref.T
                out.append(torch.topk(d2, self.k, dim=1, largest=False).values[:, -1].clamp_min(0).sqrt())
        return torch.cat(out).numpy()


def train_kitsune(con_train, seed=20):
    """control_plane.train_Kitsune: MinMax on the 80 % split (ports dropped), KitNET(n, maxAE=20, FMgrace=5000,
    ADgrace=N-5000), one pass. The original's post-training AUC loop only selects between epochs (1 epoch) -> skipped."""
    import Kitsune.KitNET as kit
    from sklearn import preprocessing
    df = con_train.drop(columns=[1, 2])                       # PORT = False in KITSUNE mode
    tr, ev = train_test_split(df, test_size=0.2, random_state=20)
    scaler = preprocessing.MinMaxScaler()
    X = scaler.fit_transform(tr.drop(columns=[0, 'class']).values)
    K = kit.KitNET(X.shape[1], 20, 5000, X.shape[0] - 5000)
    t0 = time.time()
    for i in range(X.shape[0]):
        K.process(X[i, ], changeState=(i == 0))
    # In the original, the first row of the post-training benign evaluation loop is still a training step
    # (n_trained == FM+AD is not > FM+AD) before the model is pickled; replicate that single step.
    K.process(scaler.transform(ev.drop(columns=[0, 'class']).values[:1])[0, ])
    return K, scaler, X.shape[0], time.time() - t0


class KitTrainedScorer(KitScorer):
    def __init__(self, K, scaler):
        self.K, self.scaler = K, scaler
