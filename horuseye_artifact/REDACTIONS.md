# Redactions in this release (privacy)

Two changes to the original HorusEye pre-processing code. Both are in pcap → feature pre-processing, which the
evaluation in this repository does not run (it uses the released feature files).

| File | Original | In this release |
|---|---|---|
| `pcap_process/extract_flow_size.py`, function `add_server_port` | two hard-coded lists of device MAC addresses (open-source UNSW devices and the HorusEye testbed devices) | both lists are empty, with a comment: fill in the MAC addresses of the devices in your own captures before running this step |
| `pcap_process/normal_dec2data_all.py`, last line | absolute output path in the original author's home directory | relative path `../DataSets/normal-dec-feature/all_data.csv`, as used by the other `pcap_process` scripts |

All other changes to the original code are listed in `patch_control_plane.diff`.
