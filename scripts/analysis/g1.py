"""G1: gateway cross-test. all14-retrained HorusEye (B5, 18 epochs) on the gw6 benign test set, and gw6-retrained
HorusEye on the all14 benign test set; diagonal (own test set) included as a check against B5. Same 17 attacks,
same protocol; each model uses its own Gulliver rules and scaler (work/b5_<subset>/)."""
import os
import sys

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
import b8common as c  # noqa: E402
import hekit as hk  # noqa: E402

c.enter("b5_all14")
attacks = hk.load_attacks()
tests = {"all14_test": hk.load_benign_test("A"), "gw6_test": hk.load_benign_test("A", devices=hk.GW)}
for model in ("all14", "gw6"):
    c.enter("b5_" + model)
    sc = hk.MagScorer(os.path.join("params", "CNN_DW_dilation_channel_port.pkl"), os.path.join("params", "scaler.pkl"))
    for tname, (con_b, data_b) in tests.items():
        for det, g in (("HorusEye", True), ("Magnifier", False)):
            m, _ = hk.evaluate(con_b, data_b, attacks, sc, g, tag="G1 %s->%s %s" % (model, tname, det))
            c.record("G1", "train=%s, test=%s" % (model, tname), det, m, {"train": model, "test": tname, "epochs": 18})
hk.log("G1 done")
