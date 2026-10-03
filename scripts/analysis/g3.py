"""G3: benign-only checkpoint selection, original 20 epochs, all14 and full open-source corpus (Gulliver retrained on each)."""
import os, sys
sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
import b8common as c  # noqa: E402
import glane  # noqa: E402
import hekit as hk  # noqa: E402
import b5_ablation as b5  # noqa: E402

c.enter("b5_common")
jobs = [("all14", "A"), ("open_full", "B")]
for i, (name, corpus) in enumerate(jobs):
    left = c.minutes_left()
    if left < 10:
        c.note("G3", "G3 %s SKIPPED: box exhausted (%.0f min left)" % (name, left)); continue
    try:
        if corpus == "A":
            con, data, _ = b5.proprietary_train(b5.ALL14)
        else:
            con, data = hk.load_benign_train("B")
        # leave room for the evaluation (~4 min) and for the remaining job
        dl = left - 6 - (25 if i == 0 else 0)
        glane.run("G3", name, corpus, con, data, 20, "benign_loss", retrain_gulliver=True, deadline_min=dl)
    except Exception as e:
        import traceback; traceback.print_exc(); c.note("G3", "G3 %s ERROR %r" % (name, e))
hk.log("G3 done")
