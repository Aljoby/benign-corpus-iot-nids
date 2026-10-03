"""C5: symmetric ablation with Isolation Forest and kNN (same settings as C4).
(a) proprietary segment sweep: first 1, 2, 3 of the 4 training files per device (all 14 devices; test = all14 test)
(b) open-source volume: random 25 % / 50 % of the training rows (seed 0)
(c) open-source device subsets: device identification check; if possible, two random halves of the devices (seed 0),
    trained and tested on the same devices
(d) five more random 5-device proprietary subsets (seeds 2-6), test on the same devices; mean/range with rand5_a/b (C4b)
No MAC/IP is printed or stored: devices are referred to by anonymous index."""
import ast
import os
import sys

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
import b8common as c  # noqa: E402
import hekit as hk  # noqa: E402
import b5_ablation as b5  # noqa: E402
import numpy as np  # noqa: E402
import pandas as pd  # noqa: E402

c.enter("b5_common")
attacks = hk.load_attacks()
DET = {"IsolationForest": hk.IFScorer, "kNN": hk.KNNScorer}
tests = {"A": hk.load_benign_test("A"), "B": hk.load_benign_test("B")}


def fit_eval(cond, con_train, corpus, test, extra):
    tr, _ = hk.train_test_split(con_train, test_size=0.2, random_state=20)
    for dn, D in DET.items():
        if c.over_box(3):
            c.note("C5", "C5 %s %s SKIPPED (box)" % (cond, dn)); continue
        try:
            m, _ = hk.evaluate(*test, attacks, D(tr), False, tag="C5 %s %s" % (cond, dn))
            c.record("C5", cond, dn, m, dict(extra, corpus=corpus, n_train_rows=len(con_train)))
        except Exception as e:
            import traceback
            traceback.print_exc()
            c.note("C5", "C5 %s %s ERROR %r" % (cond, dn, e))


# (a)
for k in (1, 2, 3):
    con, _ = c.prop_files(k)
    fit_eval("prop_files%d" % k, con, "A", tests["A"], {"part": "a"})
# (b)
for f in (0.25, 0.50):
    con, _ = c.os_volume(f)
    fit_eval("open_%dpct" % int(f * 100), con, "B", tests["B"], {"part": "b"})

# (c) device identification in the open-source CSVs
from load_data import open_source_load_iot_data  # noqa: E402
bt = open_source_load_iot_data(thr_time=1, selected_list=[0, 2, 4, 6, 7])
bs = open_source_load_iot_data(thr_time=1, selected_list=[1, 3, 5, 8])
has_mac = "MAC" in bt.columns
c.note("C5", "C5c: packet-feature CSVs (normal_kitsune) have no device column; burst CSVs %s a MAC column; packet rows "
       "link to burst rows through the flow key (column 0 = burst 'key')." % ("have" if has_mac else "do NOT have"))
if has_mac and not c.over_box(10):
    def pair(s):
        try:
            v = ast.literal_eval(s)
            return v[0], v[1]
        except Exception:
            return None, None
    allb = pd.concat([bt, bs], ignore_index=True)
    pairs = allb["MAC"].map(pair)
    src = pairs.map(lambda p: p[0]); dst = pairs.map(lambda p: p[1])
    gw = pd.concat([src, dst]).value_counts().index[0]                     # most frequent MAC = gateway/router
    dev = np.where(src != gw, src, dst)
    keymap = pd.Series(dev, index=allb["key"].values)
    keymap = keymap[~keymap.index.duplicated()]
    con_tr = hk.load_benign_train("B")[0]
    d_tr = keymap.reindex(con_tr[0].values).values
    con_te, data_te = tests["B"]
    d_te = keymap.reindex(con_te[0].values).values
    counts = pd.Series(d_tr).value_counts()
    devices = [d for d in counts.index if counts[d] >= 1000 and d is not None and d != gw]
    c.note("C5", "C5c: %d devices with >=1000 training packets (gateway excluded); %.1f %% of training packets and %.1f %% "
           "of benign test packets could be attributed to a device." % (
               len(devices), 100 * pd.notna(d_tr).mean(), 100 * pd.notna(d_te).mean()))
    rs = np.random.RandomState(0)
    perm = list(rs.permutation(len(devices)))
    halves = {"open_devhalf_A": [devices[i] for i in perm[:len(devices) // 2]],
              "open_devhalf_B": [devices[i] for i in perm[len(devices) // 2:]]}
    dmap_b = keymap.reindex(data_te["key"].values).values
    for name, ds in halves.items():
        sel_tr = np.isin(d_tr, ds)
        sel_te = np.isin(d_te, ds)
        test = (con_te[sel_te], data_te[np.isin(dmap_b, ds)])
        fit_eval(name, con_tr[sel_tr], "B", test, {"part": "c", "n_devices": len(ds)})
else:
    c.note("C5", "C5c SKIPPED: devices cannot be identified or no time left.")

# (d) five more random 5-device subsets
for s in (2, 3, 4, 5, 6):
    devs = b5.rand5(s)
    con, _, order = b5.proprietary_train(devs)
    fit_eval("rand5_seed%d" % s, con, "A", hk.load_benign_test("A", devices=order),
             {"part": "d", "devices": ";".join(order)})
hk.log("C5 done")
