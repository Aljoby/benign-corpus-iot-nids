"""G4: original 20 epochs + original checkpoint selection on gw6, cam8, rand5_a (Gulliver retrained), vs B5 18-epoch values."""
import os, sys
sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
import b8common as c  # noqa: E402
import glane  # noqa: E402
import hekit as hk  # noqa: E402
import b5_ablation as b5  # noqa: E402

c.enter("b5_common")
for name in ("gw6", "cam8", "rand5_a"):
    left = c.minutes_left()
    if left < 8:
        c.note("G4", "G4 %s SKIPPED: box exhausted (%.0f min left)" % (name, left)); continue
    try:
        devs = b5.SUBSETS[name][1]
        con, data, order = b5.proprietary_train(devs)
        glane.run("G4", name, "A", con, data, 20, "auc", test_devices=order, retrain_gulliver=True,
                  deadline_min=left - 5, extra={"devices": ";".join(order)})
    except Exception as e:
        import traceback; traceback.print_exc(); c.note("G4", "G4 %s ERROR %r" % (name, e))
hk.log("G4 done")
