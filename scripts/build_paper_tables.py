#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""Emit the *authoritative* SRDS paper ATT&CK tables, verbatim from the paper.

These tables are transcribed directly from the published paper so the
repository's numbers are, by construction, identical to it — they are NOT
recomputed here.

  SRDS 2025, Table VI  — ATT&CK TACTIC usage frequency (command-weighted share)
  SRDS 2025, Table VII — ATT&CK TECHNIQUE usage frequency (command-weighted)

    python scripts/build_paper_tables.py --out dataset

(The HoneyGPT deception-evaluation tables are maintained separately in the
HoneyGPT project, not here.)
"""
from __future__ import annotations

import argparse
import json
import os

# --------------------------------------------------------------------------- #
# SRDS Table VI — ATT&CK TACTIC usage frequency (command-weighted share).      #
# --------------------------------------------------------------------------- #
SRDS_TACTICS = [
    # tactic, 2021-2022, 2024, trend
    ("Discovery",            0.3313, 0.1805, "down"),
    ("Collection",           0.0002, 0.0021, "up"),
    ("Command and Control",  0.0160, 0.0179, "up"),
    ("Credential Access",    0.0000, 0.0001, "up"),
    ("Defense Evasion",      0.0758, 0.3877, "up"),
    ("Execution",            0.1801, 0.1488, "down"),
    ("Impact",               0.0002, 0.0007, "up"),
    ("Persistence",          0.1975, 0.1311, "down"),
    ("Privilege Escalation", 0.1988, 0.1312, "down"),
]

# --------------------------------------------------------------------------- #
# SRDS Table VII — ATT&CK TECHNIQUE usage frequency (command-weighted).        #
# --------------------------------------------------------------------------- #
SRDS_TECHNIQUES = [
    # technique_id, technique name, 2021-2022, 2024, trend
    ("T1016", "System Network Configuration Discovery", 0.00085, 0.01751, "up"),
    ("T1033", "System Owner/User Discovery",            0.00004, 0.01589, "up"),
    ("T1069", "Permission Groups Discovery",            0.00000, 0.00016, "up"),
    ("T1082", "System Information Discovery",           0.18294, 0.06894, "down"),
    ("T1083", "File and Directory Discovery",           0.08058, 0.04499, "down"),
    ("T1087", "Account Discovery",                      0.11551, 0.04382, "down"),
    ("T1124", "System Time Discovery",                  0.00004, 0.00002, "down"),
    ("T1424", "Process Discovery",                      0.05726, 0.01835, "down"),
    ("T1518", "Software Discovery",                     0.00004, 0.00133, "up"),
    ("T1614", "System Location Discovery",              0.00000, 0.00006, "up"),
    ("T1005", "Data from Local System",                 0.00023, 0.00240, "up"),
    ("T1071", "Application Layer Protocol",             0.00000, 0.00019, "up"),
    ("T1105", "Ingress Tool Transfer",                  0.02113, 0.02070, "down"),
    ("T1003", "OS Credential Dumping",                  0.00000, 0.00017, "up"),
    ("T1059", "Command and Scripting Interpreter",      0.18043, 0.15815, "down"),
    ("T1053", "Scheduled Task/Job",                     0.05731, 0.01583, "down"),
    ("T1098", "Account Manipulation",                   0.20268, 0.13740, "down"),
    ("T1547", "Boot or Logon Autostart Execution",      0.00069, 0.00005, "down"),
    ("T1548", "Abuse Elevation Control Mechanism",      0.00173, 0.00019, "down"),
    ("T1027", "Obfuscated Files or Information",        0.00499, 0.01582, "up"),
    ("T1070", "Indicator Removal",                      0.01834, 0.17176, "up"),
    ("T1222", "File and Directory Permissions Modification", 0.05840, 0.22948, "up"),
    ("T1562", "Impair Defenses",                        0.00000, 0.01585, "up"),
    ("T1564", "Hide Artifacts",                         0.00005, 0.00146, "up"),
    ("T1655", "Masquerading",                           0.01650, 0.01874, "up"),
    ("T1489", "Service Stop",                           0.00021, 0.00073, "up"),
    ("T1496", "Resource Hijacking",                     0.00005, 0.00004, "down"),
]


def _write_jsonl(path, header, rows):
    os.makedirs(os.path.dirname(path), exist_ok=True)
    with open(path, "w", encoding="utf-8") as fh:
        for row in rows:
            rec = {}
            for k, v in zip(header, row):
                rec[k] = round(v, 5) if isinstance(v, float) else v
            fh.write(json.dumps(rec, ensure_ascii=False) + "\n")
    print(f"  wrote {len(rows):>3} rows -> {os.path.relpath(path)}")


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--out", default="dataset")
    args = ap.parse_args()
    ttp = os.path.join(args.out, "attack_ttp")
    _write_jsonl(os.path.join(ttp, "paper_tactics.jsonl"),
                 ["tactic", "share_2021_2022", "share_2024", "trend"],
                 [list(r) for r in SRDS_TACTICS])
    _write_jsonl(os.path.join(ttp, "paper_techniques.jsonl"),
                 ["technique_id", "technique", "share_2021_2022",
                  "share_2024", "trend"],
                 [list(r) for r in SRDS_TECHNIQUES])
    print("done.")


if __name__ == "__main__":
    main()
