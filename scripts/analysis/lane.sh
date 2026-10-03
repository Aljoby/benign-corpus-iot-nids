#!/bin/zsh
# Run analysis tasks one after another, each with an optional time box (minutes; the task saves partial results).
#   scripts/analysis/lane.sh "g1:30 g2:20 g3:120"      (run from anywhere; logs go to outputs/logs/)
# Tasks are scripts in this folder (g1.py ...). PYTHON selects the interpreter (default python3).
cd "${0:A:h}"
PY=${PYTHON:-python3}
mkdir -p ../../outputs/logs
for t in ${=1}; do
  name=${t%%:*}; box=${t##*:}
  echo "[lane] START $name box=${box}min $(date +%H:%M:%S)"
  BOX_MIN=$box $PY -u $name.py > ../../outputs/logs/$name.log 2>&1 &
  pid=$!
  ( sleep $(( (box + 5) * 60 )); kill $pid 2>/dev/null && echo "[lane] KILLED $name at box+5" ) &
  wd=$!
  wait $pid; rc=$?
  kill $wd 2>/dev/null
  echo "[lane] END $name rc=$rc $(date +%H:%M:%S)"
done
