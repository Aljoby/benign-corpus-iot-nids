#!/bin/zsh
# Reproduction run matrix R1-R8 (evaluation only, released models), sequential: each run is a fresh process
# -> setup_seed(20) -> identical 10 % benign sample. Usage: scripts/run_all.sh [runs...]   (default: all eight)
# PYTHON can point to the interpreter of the environment from requirements.txt (default: python3).
cd "${0:A:h}"
PY=${PYTHON:-python3}
mkdir -p ../outputs/logs
typeset -A CFG
CFG=(R1_A_HE "A True 0" R2_A_MAG "A False 0" R3_A_KITHE "A True 1" R4_A_KIT "A False 1"
     R5_B_HE "B True 0" R6_B_MAG "B False 0" R7_B_KITHE "B True 1" R8_B_KIT "B False 1")
runs=($@)
(( ${#runs} )) || runs=(R1_A_HE R2_A_MAG R3_A_KITHE R4_A_KIT R5_B_HE R6_B_MAG R7_B_KITHE R8_B_KIT)
for r in $runs; do
  echo "[run_all] START $r $(date +%H:%M:%S)"
  $PY -u run_eval.py $r ${=CFG[$r]} > ../outputs/logs/$r.log 2>&1
  echo "[run_all] END $r exit=$? $(date +%H:%M:%S) $(tail -1 ../outputs/logs/$r.log)"
done
echo "[run_all] ALL DONE"
