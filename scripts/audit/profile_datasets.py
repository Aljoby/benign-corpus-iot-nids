#!/usr/bin/env python3
"""Privacy-preserving profiler for pcap corpora (pure stdlib, no scapy/dpkt).

Usage:
    python3 profile_datasets.py pcap --root <folder> --label <name> [--max-pkts N] [--out FILE]

Writes aggregate statistics only (counts, dates, protocol mix) to JSON.
No IP addresses, MAC addresses or payload bytes are written or printed.
"""
import argparse
import collections
import datetime as dt
import json
import os
import struct
import sys

WELL_KNOWN = {
    53: "DNS", 67: "DHCP", 68: "DHCP", 80: "HTTP", 123: "NTP", 443: "HTTPS/TLS",
    554: "RTSP", 1883: "MQTT", 8883: "MQTT-TLS", 1900: "SSDP", 5353: "mDNS",
    8080: "HTTP-alt", 5683: "CoAP", 137: "NetBIOS", 138: "NetBIOS", 139: "NetBIOS",
}
ETHERTYPES = {0x0800: "IPv4", 0x86DD: "IPv6", 0x0806: "ARP", 0x888E: "EAPOL"}
IPPROTO = {6: "TCP", 17: "UDP", 1: "ICMP", 58: "ICMPv6", 2: "IGMP"}


def iter_pcap(path):
    with open(path, "rb") as f:
        gh = f.read(24)
        if len(gh) < 24:
            return
        magic = gh[:4]
        if magic in (b"\xd4\xc3\xb2\xa1", b"\x4d\x3c\xb2\xa1"):
            endian = "<"
        elif magic in (b"\xa1\xb2\xc3\xd4", b"\xa1\xb2\x3c\x4d"):
            endian = ">"
        else:
            raise ValueError("unsupported capture format (pcapng?)")
        nano = magic in (b"\x4d\x3c\xb2\xa1", b"\xa1\xb2\x3c\x4d")
        linktype = struct.unpack(endian + "I", gh[20:24])[0]
        if linktype != 1:
            raise ValueError("unsupported link type %d" % linktype)
        hdr = struct.Struct(endian + "IIII")
        while True:
            h = f.read(16)
            if len(h) < 16:
                return
            ts_s, ts_frac, incl, orig = hdr.unpack(h)
            data = f.read(incl)
            if len(data) < incl:
                return
            yield ts_s + ts_frac / (1e9 if nano else 1e6), orig, data


def parse(data):
    """Return (src_mac, ethertype, l3_proto, src_ip, dst_ip, sport, dport)."""
    if len(data) < 14:
        return None
    src_mac = data[6:12]
    et = struct.unpack("!H", data[12:14])[0]
    off = 14
    while et in (0x8100, 0x88A8) and len(data) >= off + 4:  # VLAN tags
        et = struct.unpack("!H", data[off + 2:off + 4])[0]
        off += 4
    proto = sip = dip = None
    sport = dport = 0
    if et == 0x0800 and len(data) >= off + 20:
        ihl = (data[off] & 0x0F) * 4
        proto = data[off + 9]
        sip, dip = data[off + 12:off + 16], data[off + 16:off + 20]
        frag = struct.unpack("!H", data[off + 6:off + 8])[0] & 0x1FFF
        l4 = off + ihl
        if proto in (6, 17) and frag == 0 and len(data) >= l4 + 4:
            sport, dport = struct.unpack("!HH", data[l4:l4 + 4])
    elif et == 0x86DD and len(data) >= off + 40:
        proto = data[off + 6]
        sip, dip = data[off + 8:off + 24], data[off + 24:off + 40]
        l4 = off + 40
        if proto in (6, 17) and len(data) >= l4 + 4:
            sport, dport = struct.unpack("!HH", data[l4:l4 + 4])
    return src_mac, et, proto, sip, dip, sport, dport


def service(sport, dport):
    for p in (min(sport, dport), sport, dport):
        if p in WELL_KNOWN:
            return WELL_KNOWN[p]
    return "other (port >= 1024)" if min(sport, dport) >= 1024 else "other (well-known port)"


def profile(root, label, max_pkts):
    files = []
    for r, _, fs in os.walk(root):
        for fn in fs:
            if fn.endswith((".pcap", ".cap")):
                files.append(os.path.join(r, fn))
    files.sort()
    total = 0
    truncated = False
    agg = {"ethertype": collections.Counter(), "l4": collections.Counter(),
           "service": collections.Counter()}
    all_macs, all_flows = set(), set()
    per_folder = collections.OrderedDict()
    tmin = tmax = None
    days = set()
    bytes_total = 0
    for path in files:
        rel_dir = os.path.relpath(os.path.dirname(path), root)
        pf = per_folder.setdefault(rel_dir, {
            "files": [], "packets": 0, "bytes": 0, "macs": set(), "mac_pkts": collections.Counter(),
            "flows": set(), "first": None, "last": None})
        fstat = {"file": os.path.basename(path), "packets": 0, "first_utc": None, "last_utc": None}
        try:
            for ts, orig, data in iter_pcap(path):
                if max_pkts and total >= max_pkts:
                    truncated = True
                    break
                total += 1
                fstat["packets"] += 1
                pf["packets"] += 1
                pf["bytes"] += orig
                bytes_total += orig
                tmin = ts if tmin is None or ts < tmin else tmin
                tmax = ts if tmax is None or ts > tmax else tmax
                pf["first"] = ts if pf["first"] is None or ts < pf["first"] else pf["first"]
                pf["last"] = ts if pf["last"] is None or ts > pf["last"] else pf["last"]
                fstat["first_utc"] = ts if fstat["first_utc"] is None else min(ts, fstat["first_utc"])
                fstat["last_utc"] = ts if fstat["last_utc"] is None else max(ts, fstat["last_utc"])
                p = parse(data)
                if p is None:
                    agg["ethertype"]["malformed"] += 1
                    continue
                smac, et, proto, sip, dip, sport, dport = p
                all_macs.add(smac)
                pf["macs"].add(smac)
                pf["mac_pkts"][smac] += 1
                agg["ethertype"][ETHERTYPES.get(et, "other")] += 1
                if proto is None:
                    continue
                agg["l4"][IPPROTO.get(proto, "other")] += 1
                if proto in (6, 17):
                    agg["service"][IPPROTO[proto] + "/" + service(sport, dport)] += 1
                a, b = (sip, sport), (dip, dport)
                key = (proto,) + ((a, b) if a <= b else (b, a))  # bidirectional 5-tuple
                all_flows.add(key)
                pf["flows"].add(key)
        except ValueError as e:
            fstat["error"] = str(e)
        if fstat["first_utc"] is not None:
            for k in ("first_utc", "last_utc"):
                fstat[k] = dt.datetime.fromtimestamp(fstat[k], dt.timezone.utc).strftime("%Y-%m-%d %H:%M:%S")
        pf["files"].append(fstat)
        sys.stderr.write("[%s] %s: %d pkts (total %d)\n" % (label, os.path.relpath(path, root), fstat["packets"], total))
        if truncated:
            break

    def utc(t):
        return dt.datetime.fromtimestamp(t, dt.timezone.utc).strftime("%Y-%m-%d %H:%M:%S") if t is not None else None

    folders_out = collections.OrderedDict()
    for k, pf in per_folder.items():
        top = pf["mac_pkts"].most_common(1)
        dom_share = round(top[0][1] / pf["packets"], 3) if top and pf["packets"] else None
        file_days = sorted({f["first_utc"][:10] for f in pf["files"] if f.get("first_utc")})
        days.update(file_days)
        folders_out[k] = {
            "n_files": len(pf["files"]), "packets": pf["packets"], "bytes": pf["bytes"],
            "distinct_src_macs": len(pf["macs"]), "dominant_src_mac_pkt_share": dom_share,
            "flows_5tuple": len(pf["flows"]), "first_utc": utc(pf["first"]), "last_utc": utc(pf["last"]),
            "capture_days_utc": file_days, "files": pf["files"]}
    total_l4 = sum(agg["l4"].values()) or 1
    total_et = sum(agg["ethertype"].values()) or 1
    total_sv = sum(agg["service"].values()) or 1
    return {
        "label": label, "root": os.path.abspath(root), "max_pkts": max_pkts, "truncated": truncated,
        "n_files": len(files), "packets": total, "bytes": bytes_total,
        "distinct_src_macs": len(all_macs), "flows_5tuple_bidirectional": len(all_flows),
        "first_utc": utc(tmin), "last_utc": utc(tmax), "capture_days_utc": sorted(days),
        "ethertype_mix": {k: [v, round(100 * v / total_et, 2)] for k, v in agg["ethertype"].most_common()},
        "l4_mix": {k: [v, round(100 * v / total_l4, 2)] for k, v in agg["l4"].most_common()},
        "service_mix_top": {k: [v, round(100 * v / total_sv, 2)] for k, v in agg["service"].most_common(15)},
        "folders": folders_out,
    }


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("mode", choices=["pcap"])
    ap.add_argument("--root", required=True)
    ap.add_argument("--label", required=True)
    ap.add_argument("--max-pkts", type=int, default=0, help="stop after N packets (0 = no limit)")
    ap.add_argument("--out", default=None, help="output JSON (default: profile_<label>.json)")
    a = ap.parse_args()
    res = profile(a.root, a.label, a.max_pkts)
    out = a.out or "profile_%s.json" % a.label
    with open(out, "w") as f:
        json.dump(res, f, indent=2)
    print("%s: %d files, %d packets, %d flows, %d distinct src MACs, %s -> %s%s; wrote %s" % (
        a.label, res["n_files"], res["packets"], res["flows_5tuple_bidirectional"], res["distinct_src_macs"],
        res["first_utc"], res["last_utc"], " (TRUNCATED)" if res["truncated"] else "", out))


if __name__ == "__main__":
    main()
