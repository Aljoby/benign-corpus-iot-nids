#!/bin/bash
# Build horuseye_artifact/DataSets/ from the downloaded data with RELATIVE symlinks (no data is copied).
#
#   scripts/setup_datasets.sh <HORUSEYE_FEATURES_DIR> <NEW_ATTACKS_DIR> [--original-attacks]
#
#   HORUSEYE_FEATURES_DIR  extracted HorusEye feature release; the folder that contains
#                          normal-flow-level-device_1_dou_burst_14_add_pk/, normal-kitsune_test/, Open-Source/, Anomaly/
#   NEW_ATTACKS_DIR        extracted new-attack dataset (Datasets.rar); the folder that contains Anomaly/
#   --original-attacks     link the 15 original HorusEye attacks instead of the 16 new attacks (+ HTTP DDoS)
#
# macOS WARNING: the default macOS file system is case-INSENSITIVE, so "DataSets" and "Datasets" are the SAME name.
# Never extract the new-attack archive (which unpacks to "Datasets/") next to the HorusEye feature archive
# ("DataSets/"), and never inside horuseye_artifact/: keep them in separate parent folders (see data/DATA.md).
set -euo pipefail
cd "$(dirname "$0")/.."
FEAT="${1:?usage: $0 <HORUSEYE_FEATURES_DIR> <NEW_ATTACKS_DIR> [--original-attacks]}"
NEW="${2:?usage: $0 <HORUSEYE_FEATURES_DIR> <NEW_ATTACKS_DIR> [--original-attacks]}"
MODE="${3:-}"
DS="horuseye_artifact/DataSets"
for d in "$FEAT/normal-flow-level-device_1_dou_burst_14_add_pk" "$FEAT/normal-kitsune_test" "$FEAT/Open-Source" "$NEW/Anomaly/attack_kitsune"; do
  [ -d "$d" ] || { echo "missing: $d"; exit 1; }
done
# case-insensitivity guard: refuse if a real directory with the same name (any case) exists in horuseye_artifact/
for e in horuseye_artifact/*; do
  b="$(basename "$e")"
  if [ "$(echo "$b" | tr '[:upper:]' '[:lower:]')" = "datasets" ] && [ ! -L "$e" ] && [ -d "$e" ] && [ "$b" != "DataSets" ]; then
    echo "ERROR: horuseye_artifact/$b exists; on macOS it collides with DataSets/. Move or delete it first."; exit 1
  fi
done
rel() { python3 -c 'import os,sys; print(os.path.relpath(os.path.realpath(sys.argv[1]), os.path.realpath(sys.argv[2])))' "$1" "$2"; }
mkdir -p "$DS/Anomaly/attack_kitsune" "$DS/Anomaly/attack-flow-level-device_1_dou_burst_14_add_pk"
for n in normal-flow-level-device_1_dou_burst_14_add_pk normal-kitsune_test Open-Source; do
  ln -sfn "$(rel "$FEAT/$n" "$DS")" "$DS/$n"
done
if [ "$MODE" = "--original-attacks" ]; then SRC="$FEAT/Anomaly"; else SRC="$NEW/Anomaly"; fi
for k in attack_kitsune attack-flow-level-device_1_dou_burst_14_add_pk; do
  for a in "$SRC/$k"/*/; do
    a="${a%/}"; n="$(basename "$a")"
    ln -sfn "$(rel "$a" "$DS/Anomaly/$k")" "$DS/Anomaly/$k/$n"
  done
done
broken=$(find "$DS" -type l ! -exec test -e {} \; -print | wc -l | tr -d ' ')
echo "DataSets ready: $(find "$DS" -type l | wc -l | tr -d ' ') links, $broken broken; attacks: $(ls "$DS/Anomaly/attack_kitsune" | wc -l | tr -d ' ')"
[ "$broken" = "0" ] || exit 1
