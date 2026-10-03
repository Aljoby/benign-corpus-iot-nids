#!/usr/bin/env python3
"""Run one evaluation of horuseye_artifact/control_plane.py (patched copy) and archive its outputs.

usage: run_eval.py <run_id> <experiment A|B> <horuseye True|False> <kitsune 0|1>

- logs every pandas.read_csv path (to check that test mode does not read training CSVs)
- records peak RSS and wall time
- after the run, moves result/{HorusEye,Kitsune,Magnifier,Open-Source/*,rmse}, roc_counts.csv
  into outputs/repro/<run_id>/ so the next run cannot overwrite them
"""
import json
import os
import resource
import runpy
import shutil
import sys
import time

# All paths below are RELATIVE to horuseye_artifact/ (after chdir), so the run survives the project folder being moved.
run_id, exp, he, kit = sys.argv[1:5]
os.chdir(os.path.join(os.path.dirname(os.path.abspath(__file__)), "..", "horuseye_artifact"))
out = os.path.join("..", "outputs", "repro", run_id)
if os.path.exists(out):
    sys.exit("refusing to overwrite " + out)
broken = [os.path.join(r, n) for r, ds, fs in os.walk("DataSets") for n in ds + fs
          if os.path.islink(os.path.join(r, n)) and not os.path.exists(os.path.join(r, n))]
if broken or not os.path.isdir("DataSets/normal-kitsune_test"):
    sys.exit("broken DataSets links: %s" % broken[:5])
os.environ["HE_KITSUNE"] = kit
res = "result"
dirs = ["HorusEye", "Kitsune", "Magnifier", "rmse",
        "Open-Source/HorusEye", "Open-Source/Kitsune", "Open-Source/Magnifier"]
for d in dirs:  # start every run from empty output folders
    shutil.rmtree(os.path.join(res, d), ignore_errors=True)
    os.makedirs(os.path.join(res, d))
if os.path.exists(os.path.join(res, "roc_counts.csv")):
    os.remove(os.path.join(res, "roc_counts.csv"))

import pandas as pd  # noqa: E402

reads = []
_orig = pd.read_csv


def _logged(path, *a, **k):
    reads.append(os.path.relpath(os.path.realpath(path), os.path.realpath(".."))
                 if isinstance(path, str) else str(path))
    return _orig(path, *a, **k)


pd.read_csv = _logged
sys.argv = ["control_plane.py", "--train", "False", "--experiment", exp, "--horuseye", he]
sys.path.insert(0, os.getcwd())
t0 = time.time()
status = "ok"
try:
    runpy.run_path("control_plane.py", run_name="__main__")
except SystemExit:
    pass
except Exception as e:  # keep the meta file even on failure
    status = "error: %r" % e
    raise
finally:
    meta = {
        "run_id": run_id, "experiment": exp, "horuseye": he, "kitsune": kit, "status": status,
        "wall_s": round(time.time() - t0, 1),
        "peak_rss_GB": round(resource.getrusage(resource.RUSAGE_SELF).ru_maxrss / 1e9, 2),  # bytes on macOS
        "csv_reads": reads,
    }
    os.makedirs(out)
    for d in dirs:
        src = os.path.join(res, d)
        if os.listdir(src):
            shutil.copytree(src, os.path.join(out, d))
    if os.path.exists(os.path.join(res, "roc_counts.csv")):
        shutil.copy(os.path.join(res, "roc_counts.csv"), out)
    json.dump(meta, open(os.path.join(out, "run_meta.json"), "w"), indent=1)
    print("[run_eval] %s %s wall=%ss peak=%sGB -> %s" % (run_id, status, meta["wall_s"], meta["peak_rss_GB"], os.path.realpath(out)))
