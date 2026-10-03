"""G5: HorusEye (18 epochs, original selection, as B5) on the symmetric-ablation subsets of C5:
proprietary first 1 file, open-source 25 %, proprietary first 2 files, open-source 50 % (seed 0).
Proprietary: Gulliver retrained, test = all14 benign test; open-source: artifact rules (as B5 os_days), standard test."""
import os, sys
sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
import b8common as c  # noqa: E402
import glane  # noqa: E402
import hekit as hk  # noqa: E402

c.enter("b5_common")
for name in ("prop_files1", "open_25pct", "prop_files2", "open_50pct"):
    left = c.minutes_left()
    if left < 8:
        c.note("G5", "G5 %s SKIPPED: time exhausted (%.0f min left)" % (name, left)); continue
    try:
        if name.startswith("prop"):
            con, data = c.prop_files(int(name[-1]))
            glane.run("G5", name, "A", con, data, 18, "auc", retrain_gulliver=True, deadline_min=left - 5)
        else:
            con, data = c.os_volume(0.25 if "25" in name else 0.50)
            glane.run("G5", name, "B", con, data, 18, "auc", retrain_gulliver=False, deadline_min=left - 5)
    except Exception as e:
        import traceback; traceback.print_exc(); c.note("G5", "G5 %s ERROR %r" % (name, e))
hk.log("G5 done")
