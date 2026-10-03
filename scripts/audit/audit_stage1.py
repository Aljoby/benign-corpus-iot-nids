#!/usr/bin/env python3
"""Stage 1 data-completeness audit (REPRODUCTION_GUIDE.md).

Read-only. Emits counts, file names and md5s only -- never cell values
(the burst CSVs contain 5-tuple/MAC columns).
Output: outputs/stage1_audit.json.
"""
import hashlib
import json
import os
import re

HERE = os.path.dirname(os.path.abspath(__file__))
ROOT = os.path.abspath(os.path.join(HERE, "..", ".."))                  # repository root
# Inputs (override with environment variables; defaults follow data/DATA.md):
REPO = os.path.join(ROOT, "horuseye_artifact")                             # code, params, Gulliver rules
HE = os.environ.get("HORUSEYE_FEATURES", os.path.join(ROOT, "data", "horuseye_features", "DataSets"))
ST = os.environ.get("NEW_ATTACKS", os.path.join(ROOT, "data", "new_attacks", "Datasets"))
PCAP_PROFILE = {   # written by scripts/audit/profile_datasets.py (pcap mode)
    "proprietary": os.path.join(ROOT, "outputs", "profile_proprietary_benign.json"),
    "open_source": os.path.join(ROOT, "outputs", "profile_open_source_benign.json"),
}
BURST = "normal-flow-level-device_1_dou_burst_14_add_pk"
ATK_BURST = "attack-flow-level-device_1_dou_burst_14_add_pk"


def csv_stats(path):
    """Return (data_rows, has_header, md5). Header = first byte not a digit/sign."""
    h = hashlib.md5()
    nl = 0
    first = b""
    last = b""
    with open(path, "rb") as f:
        while True:
            b = f.read(1 << 24)
            if not b:
                break
            if not first:
                first = b[:1]
            h.update(b)
            nl += b.count(b"\n")
            last = b[-1:]
    lines = nl + (1 if last and last != b"\n" else 0)
    has_header = bool(first) and first not in b"0123456789-."
    return lines - (1 if has_header else 0), has_header, h.hexdigest()


def audit_dir(path, per_sub=True):
    out = {"exists": os.path.isdir(path), "path": os.path.relpath(path, ROOT)}
    if not out["exists"]:
        return out
    subs = sorted(d for d in os.listdir(path) if os.path.isdir(os.path.join(path, d)))
    out["n_subfolders"] = len(subs)
    groups = {s: os.path.join(path, s) for s in subs} if (per_sub and subs) else {".": path}
    out["groups"] = {}
    n_csv = rows = 0
    for g, gp in groups.items():
        files = sorted(fn for fn in os.listdir(gp) if fn.endswith(".csv"))
        entries = []
        for fn in files:
            r, hdr, md5 = csv_stats(os.path.join(gp, fn))
            entries.append({"file": fn, "rows": r, "header": hdr, "md5": md5})
            n_csv += 1
            rows += r
        out["groups"][g] = entries
    out["n_csv"] = n_csv
    out["total_rows"] = rows
    return out


def device_lists():
    src = open(os.path.join(REPO, "control_plane.py")).read()
    res = {}
    for name in ("device_list_camera", "device_list_gateway"):
        m = re.search(name + r"\s*=\s*\[(.*?)\]", src, re.S)
        res[name] = re.findall(r"'([^']+)'", m.group(1)) if m else None
        res[name + "_line"] = src[:m.start()].count("\n") + 1 if m else None
    return res


def map_to_pcaps(kit_groups, corpus):
    """Match each Kitsune CSV (1 row per packet, see FE.py) to the pcap with the same packet count."""
    prof = json.load(open(PCAP_PROFILE[corpus]))
    out = {}
    for dev, entries in kit_groups.items():
        folder = prof["folders"].get(dev if corpus == "proprietary" else ".")
        if folder is None:
            out[dev] = {"error": "no pcap folder"}
            continue
        pcaps = sorted(folder["files"], key=lambda x: x["file"])
        rows = []
        for i, e in enumerate(entries):
            exact = [p["file"] for p in pcaps if p["packets"] == e["rows"]]
            best = min(pcaps, key=lambda p: abs(p["packets"] - e["rows"]))
            same_idx = pcaps[i]["file"] if i < len(pcaps) else None
            rows.append({
                "csv": e["file"], "csv_rows": e["rows"],
                "pcap_same_sorted_index": same_idx,
                "pcap_same_index_packets": pcaps[i]["packets"] if i < len(pcaps) else None,
                "exact_match_pcaps": exact,
                "closest_pcap": best["file"], "closest_pcap_packets": best["packets"],
            })
        out[dev] = {"n_pcaps": len(pcaps), "n_csv": len(entries), "rows": rows,
                    "pcap_files": [p["file"] for p in pcaps]}
    return out


def main():
    res = {"roots": {"repo": os.path.relpath(REPO, ROOT), "horuseye_features": os.path.relpath(HE, ROOT),
                     "student_attacks": os.path.relpath(ST, ROOT)}}
    # 1. expected paths
    p = {}
    p["HE:" + BURST] = audit_dir(os.path.join(HE, BURST))
    p["HE:normal-kitsune_test"] = audit_dir(os.path.join(HE, "normal-kitsune_test"))
    p["HE:Open-Source/" + BURST] = audit_dir(os.path.join(HE, "Open-Source", BURST), per_sub=False)
    p["HE:Open-Source/normal_kitsune"] = audit_dir(os.path.join(HE, "Open-Source", "normal_kitsune"), per_sub=False)
    p["HE:Anomaly/" + ATK_BURST] = audit_dir(os.path.join(HE, "Anomaly", ATK_BURST))
    p["HE:Anomaly/attack_kitsune"] = audit_dir(os.path.join(HE, "Anomaly", "attack_kitsune"))
    p["ST:Anomaly/" + ATK_BURST] = audit_dir(os.path.join(ST, "Anomaly", ATK_BURST))
    p["ST:Anomaly/attack_kitsune"] = audit_dir(os.path.join(ST, "Anomaly", "attack_kitsune"))
    p["HE:robust"] = {"exists": os.path.isdir(os.path.join(HE, "robust")), "note": "Experiment D only"}
    res["paths"] = p

    # repo files: params + Gulliver rules
    repo = {}
    for rel in ["params", "params/Open-Source"]:
        d = os.path.join(REPO, rel)
        repo[rel] = [
            {"file": f, "bytes": os.path.getsize(os.path.join(d, f)),
             "md5": hashlib.md5(open(os.path.join(d, f), "rb").read()).hexdigest()}
            for f in sorted(os.listdir(d)) if os.path.isfile(os.path.join(d, f))] if os.path.isdir(d) else None
    rules = {}
    for f in ["tcp_rule_all.csv", "udp_rule_all.csv", "tcp_port_rule_all.csv", "udp_port_rule_all.csv"]:
        fp = os.path.join(REPO, "result", f)
        rules[f] = {"exists": os.path.isfile(fp)}
        if os.path.isfile(fp):
            r, hdr, md5 = csv_stats(fp)
            rules[f].update(rows=r, header=hdr, md5=md5)
        # same file in every saved new-attack run?
        md5s = {}
        nar = os.path.join(REPO, "new_attacks_results")
        for run in sorted(os.listdir(nar)):
            q = os.path.join(nar, run, f)
            if os.path.isfile(q):
                md5s[run] = hashlib.md5(open(q, "rb").read()).hexdigest()
        rules[f]["saved_runs_md5"] = md5s
    repo["result_rules"] = rules
    res["repo"] = repo

    # 2. device lists
    dl = device_lists()
    folders = sorted(p["HE:" + BURST]["groups"].keys())
    kfolders = sorted(p["HE:normal-kitsune_test"]["groups"].keys())
    code = sorted((dl["device_list_camera"] or []) + (dl["device_list_gateway"] or []))
    res["device_check"] = {
        **dl, "code_devices": code, "burst_folders": folders, "kitsune_folders": kfolders,
        "code_minus_burst": sorted(set(code) - set(folders)), "burst_minus_code": sorted(set(folders) - set(code)),
        "code_minus_kitsune": sorted(set(code) - set(kfolders)), "kitsune_minus_code": sorted(set(kfolders) - set(code)),
    }

    # 3. CSV <-> pcap mapping (Kitsune rows = packets); burst rows per file for reference
    res["mapping"] = {
        "proprietary": map_to_pcaps(p["HE:normal-kitsune_test"]["groups"], "proprietary"),
        "open_source": map_to_pcaps(p["HE:Open-Source/normal_kitsune"]["groups"], "open_source"),
    }

    # 4. attacks present in both sets
    cmp = {}
    for kind in (ATK_BURST, "attack_kitsune"):
        he, st = p["HE:Anomaly/" + kind]["groups"], p["ST:Anomaly/" + kind]["groups"]
        for a in sorted(set(he) & set(st)):
            cmp.setdefault(a, {})[kind] = {
                "horuseye": [(e["file"], e["rows"], e["md5"]) for e in he[a]],
                "student": [(e["file"], e["rows"], e["md5"]) for e in st[a]],
                "identical": [(e["file"], e["md5"]) for e in he[a]] == [(e["file"], e["md5"]) for e in st[a]],
            }
    res["attack_overlap"] = cmp
    res["attack_sets"] = {k: sorted(p[k]["groups"]) for k in p if k.startswith(("HE:Anomaly", "ST:Anomaly"))}

    os.makedirs(os.path.join(ROOT, "outputs"), exist_ok=True)
    with open(os.path.join(ROOT, "outputs", "stage1_audit.json"), "w") as f:
        json.dump(res, f, indent=1)
    print("wrote outputs/stage1_audit.json")


if __name__ == "__main__":
    main()
