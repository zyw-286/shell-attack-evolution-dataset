#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
build_dataset.py — Reproducible builder for the Shell-Honeypot Attack Dataset.

This script reads the *raw* analysis outputs produced by the research pipeline
(the messy working directories used for the SRDS'25 paper) and emits a clean,
standardized, HuggingFace-loadable dataset (JSONL) under ``dataset/``.

It never fabricates data: every record is derived from a real source file.
Provenance of every field is documented in ``dataset/README.md`` (the dataset
card) and in this script.

Standardized configs produced
-----------------------------
1. commands/{2021_2022,2024}.jsonl
       One row per unique shell command observed in a period, with its
       occurrence frequency, a structural complexity flag, and its abstracted
       command pattern.
2. sessions/{2021_2022,2024}.jsonl
       One row per effective attack session (commands grouped by attacker IP),
       with the session's command list, its session pattern, and the sequence
       of MITRE ATT&CK techniques invoked.
3. request_response/{vm_replay_2021_2022,curated_2024}.jsonl
       The flagship request/response interactions. Each row is a single
       (command -> real system response) turn. The 2024 curated split is
       additionally annotated with a natural-language description of the
       induced system change and a harm/severity index Vi in [0, 4].
4. attack_ttp/derived_session_coverage_{techniques,tactics}.jsonl
       Derived MITRE ATT&CK technique / tactic usage frequencies per period
       (the quantities behind Tables VI and VII of the paper).

Usage
-----
    python scripts/build_dataset.py --raw-root <path-to-raw-data> \
        --gpt-cowrie <path-to-gpt_cowrie> --out dataset

If the raw inputs are not available, the pre-built JSONL files already shipped
in ``dataset/`` can be used directly.
"""
from __future__ import annotations

import argparse
import hashlib
import json
import os
import re
import sys
from collections import Counter, defaultdict

# --------------------------------------------------------------------------- #
# Source layout (relative to the original research working directories).       #
# Override the two roots on the command line; the rest are resolved from them. #
# --------------------------------------------------------------------------- #
SRC = {
    # period 2021-2022  (data-analyse/analyse_2022/Data-process-new/data)
    "p22_dir": "analyse_2022/Data-process-new/data",
    "p22_sessions": "session_dict.json",
    "p22_cmd_counter": "sorted_cmd_counter.json",
    "p22_session_groups": "5-session归类.json",
    "p22_session_tech": "7-session_tech.json",
    "p22_complex": "4-复杂指令类型分析-sorted.json",
    "p22_reqresp": "6-提取设备响应/6-请求响应对(pattern).json",
    # period 2024  (data-analyse/analyse_2024/data)
    "p24_dir": "analyse_2024/data",
    "p24_sessions": "session_dict.json",
    "p24_cmd_counter": "2-sorted_cmd_counter.json",
    "p24_session_groups": "5-session归类.json",
    "p24_session_tech": "7-session_tech.json",
    "p24_complex": "4-复杂指令类型分析-sorted.json",
    # curated request/response (gpt_cowrie working dir)
    "curated_reqresp": "result-4-new-1.json",
}

# MITRE ATT&CK technique -> tactic mapping, transcribed from Table VI of the
# paper. A technique may belong to more than one tactic (e.g. T1098, T1053).
TECHNIQUE_TACTICS = {
    "T1082": ["Discovery"], "T1083": ["Discovery"], "T1087": ["Discovery"],
    "T1424": ["Discovery"], "T1033": ["Discovery"], "T1016": ["Discovery"],
    "T1518": ["Discovery"], "T1069": ["Discovery"], "T1124": ["Discovery"],
    "T1614": ["Discovery"],
    "T1005": ["Collection"],
    "T1105": ["Command and Control"], "T1071": ["Command and Control"],
    "T1003": ["Credential Access"],
    "T1222": ["Defense Evasion"], "T1070": ["Defense Evasion"],
    "T1655": ["Defense Evasion"], "T1562": ["Defense Evasion"],
    "T1027": ["Defense Evasion"], "T1564": ["Defense Evasion"],
    "T1036": ["Defense Evasion"],
    "T1548": ["Defense Evasion", "Privilege Escalation"],
    "T1059": ["Execution"],
    "T1489": ["Impact"], "T1496": ["Impact"], "T1531": ["Impact"],
    "T1098": ["Persistence", "Privilege Escalation"],
    "T1053": ["Persistence", "Privilege Escalation"],
    "T1547": ["Persistence", "Privilege Escalation"],
}

# Shell operators that make a command "complex" (multi-stage / compound).
_COMPLEX_RE = re.compile(r"[|&;><`]|\$\(|\&\&|\|\|")

# Residual Cowrie echo-prompt artifacts wrongly recorded as commands
# (password-change prompts during privilege elevation). These were already
# filtered from the published command counter; we drop them here too so the
# released `commands` config stays byte-identical to the published data.
_ECHO_ARTIFACTS = {
    "Enter new UNIX password: ",
    "Retype new password: ",
    "Retype new UNIX password: ",
    "New password: ",
}

CMD_PREFIX = "CMD: "


# --------------------------------------------------------------------------- #
# Helpers                                                                      #
# --------------------------------------------------------------------------- #
def load_json(path):
    with open(path, encoding="utf-8", errors="replace") as fh:
        return json.load(fh)


def strip_cmd(raw):
    """Normalize a stored command string ('CMD: ls' -> 'ls')."""
    return raw[len(CMD_PREFIX):] if raw.startswith(CMD_PREFIX) else raw


def session_id(period, ip):
    """Stable, anonymized session id derived from period + attacker IP."""
    return hashlib.sha1(f"{period}|{ip}".encode()).hexdigest()[:12]


def is_complex(cmd):
    return bool(_COMPLEX_RE.search(cmd))


def write_jsonl(rows, path):
    os.makedirs(os.path.dirname(path), exist_ok=True)
    with open(path, "w", encoding="utf-8") as fh:
        for r in rows:
            fh.write(json.dumps(r, ensure_ascii=False) + "\n")
    print(f"  wrote {len(rows):>6} rows -> {os.path.relpath(path)}")


def build_pattern_index(complex_path):
    """Invert {pattern: {command: count}} into {command: pattern}."""
    index = {}
    if not os.path.exists(complex_path):
        return index
    for pattern, variants in load_json(complex_path).items():
        # pattern keys are stringified tuples like "('echo', '|', 'passwd')"
        pat = pattern.strip("()").replace("'", "").replace(", ", " ")
        for cmd in variants:
            index[cmd] = pat
    return index


def build_ip_pattern_index(groups_path):
    """Invert {pattern: {ip: [cmds]}} into {ip: pattern}."""
    index = {}
    if not os.path.exists(groups_path):
        return index
    for pattern, ip_map in load_json(groups_path).items():
        for ip in ip_map:
            index[ip] = pattern
    return index


# --------------------------------------------------------------------------- #
# Config builders                                                              #
# --------------------------------------------------------------------------- #
def build_commands(raw_root, out, period, dir_key, counter_key, complex_key):
    counter_path = os.path.join(raw_root, SRC[dir_key], SRC[counter_key])
    if not os.path.exists(counter_path):
        print(f"  [skip] missing {counter_path}")
        return
    pattern_index = build_pattern_index(
        os.path.join(raw_root, SRC[dir_key], SRC[complex_key]))
    counter = load_json(counter_path)
    rows = []
    for cmd, freq in counter.items():
        if cmd in _ECHO_ARTIFACTS:
            continue
        rows.append({
            "command": cmd,
            "period": period,
            "frequency": int(freq),
            "is_complex": is_complex(cmd),
            "command_pattern": pattern_index.get(cmd),
        })
    rows.sort(key=lambda r: r["frequency"], reverse=True)
    write_jsonl(rows, os.path.join(out, "commands", f"{period}.jsonl"))


def build_sessions(raw_root, out, period, dir_key, sess_key,
                   groups_key, tech_key):
    sess_path = os.path.join(raw_root, SRC[dir_key], SRC[sess_key])
    if not os.path.exists(sess_path):
        print(f"  [skip] missing {sess_path}")
        return
    ip_pattern = build_ip_pattern_index(
        os.path.join(raw_root, SRC[dir_key], SRC[groups_key]))
    tech_path = os.path.join(raw_root, SRC[dir_key], SRC[tech_key])
    pattern_tech = load_json(tech_path) if os.path.exists(tech_path) else {}
    rows = []
    for ip, cmds in load_json(sess_path).items():
        commands = [strip_cmd(c) for c in cmds]
        pattern = ip_pattern.get(ip)
        techs = pattern_tech.get(pattern, []) if pattern else []
        # de-duplicate consecutive identical techniques, keep order
        ordered, prev = [], None
        for t in techs:
            if t != prev:
                ordered.append(t)
            prev = t
        rows.append({
            "session_id": session_id(period, ip),
            "period": period,
            "src_ip": ip,
            "commands": commands,
            "command_count": len(commands),
            "session_pattern": pattern,
            "attack_techniques": ordered,
        })
    write_jsonl(rows, os.path.join(out, "sessions", f"{period}.jsonl"))
    return rows


def build_request_response(raw_root, gpt_cowrie, out):
    # 1) 2021-2022 real VM replay: {sid: [[command, response], ...]}
    vm_path = os.path.join(raw_root, SRC["p22_dir"], SRC["p22_reqresp"])
    if os.path.exists(vm_path):
        rows = []
        for sid, turns in load_json(vm_path).items():
            for i, turn in enumerate(turns):
                if not isinstance(turn, list) or len(turn) < 2:
                    continue
                rows.append({
                    "session_id": sid,
                    "period": "2021_2022",
                    "turn_index": i,
                    "command": turn[0],
                    "response": turn[1],
                    "system_change": None,
                    "severity_vi": None,
                    "response_source": "real_vm",
                })
        write_jsonl(rows, os.path.join(
            out, "request_response", "vm_replay_2021_2022.jsonl"))

    # 2) Curated: the SAME 160 representative session templates as the VM
    #    replay above (verified: identical session-id sets), re-replayed in a
    #    standardized Ubuntu 22.04 Docker honeypot and annotated. Each turn is
    #    [command, response, system_change, Vi, note]. This pairs 1:1 with the
    #    raw VM responses, giving a real-vs-curated response benchmark.
    cur_path = os.path.join(gpt_cowrie, SRC["curated_reqresp"])
    if os.path.exists(cur_path):
        rows = []
        for sid, turns in load_json(cur_path).items():
            for i, turn in enumerate(turns):
                if not isinstance(turn, list) or len(turn) < 2:
                    continue
                vi = None
                if len(turn) >= 4:
                    try:
                        vi = int(turn[3])
                    except (TypeError, ValueError):
                        vi = None
                rows.append({
                    "session_id": sid,
                    "period": "2021_2022",
                    "turn_index": i,
                    "command": turn[0],
                    "response": turn[1],
                    "system_change": turn[2] if len(turn) >= 3 else None,
                    "severity_vi": vi,
                    "response_source": "curated_ubuntu",
                })
        write_jsonl(rows, os.path.join(
            out, "request_response", "curated.jsonl"))


def build_attack_ttp(out, sessions_by_period):
    """Derive technique & tactic usage frequency per period from sessions."""
    tech_rows, tac_rows = [], []
    for period, sessions in sessions_by_period.items():
        tech_counter = Counter()
        tac_counter = Counter()
        n_sessions = len(sessions) or 1
        for s in sessions:
            # count each technique / tactic once per session (presence), so
            # session_share is a true coverage fraction in [0, 1].
            seen_tech = set(s["attack_techniques"])
            seen_tac = set()
            for t in seen_tech:
                tech_counter[t] += 1
                tid = t.split()[0]
                for tac in TECHNIQUE_TACTICS.get(tid, ["Unmapped"]):
                    seen_tac.add(tac)
            for tac in seen_tac:
                tac_counter[tac] += 1
        for tech, cnt in tech_counter.most_common():
            tid = tech.split()[0]
            tech_rows.append({
                "period": period, "technique_id": tid,
                "technique": tech,
                "tactics": "; ".join(TECHNIQUE_TACTICS.get(tid, ["Unmapped"])),
                "session_count": cnt,
                "session_share": round(cnt / n_sessions, 6),
            })
        for tac, cnt in tac_counter.most_common():
            tac_rows.append({
                "period": period, "tactic": tac,
                "session_count": cnt,
                "session_share": round(cnt / n_sessions, 6),
            })
    # NOTE: these are a *supplementary, derived* view (per-session coverage
    # share computed from the released sessions). The AUTHORITATIVE figures are
    # the paper's command-weighted shares in attack_ttp/paper_*.jsonl, emitted by
    # scripts/build_paper_tables.py. The two use different denominators.
    write_jsonl(tech_rows, os.path.join(
        out, "attack_ttp", "derived_session_coverage_techniques.jsonl"))
    write_jsonl(tac_rows, os.path.join(
        out, "attack_ttp", "derived_session_coverage_tactics.jsonl"))


# --------------------------------------------------------------------------- #
def main():
    ap = argparse.ArgumentParser(description=__doc__,
                                 formatter_class=argparse.RawDescriptionHelpFormatter)
    ap.add_argument("--raw-root", required=True,
                    help="root of the data-analyse working dir "
                         "(contains analyse_2022/ and analyse_2024/)")
    ap.add_argument("--gpt-cowrie", required=True,
                    help="root of the gpt_cowrie working dir "
                         "(contains result-4-new-1.json)")
    ap.add_argument("--out", default="dataset", help="output dataset dir")
    args = ap.parse_args()

    print("[1/4] commands")
    build_commands(args.raw_root, args.out, "2021_2022",
                   "p22_dir", "p22_cmd_counter", "p22_complex")
    build_commands(args.raw_root, args.out, "2024",
                   "p24_dir", "p24_cmd_counter", "p24_complex")

    print("[2/4] sessions")
    sessions_by_period = {}
    s22 = build_sessions(args.raw_root, args.out, "2021_2022",
                         "p22_dir", "p22_sessions", "p22_session_groups",
                         "p22_session_tech")
    s24 = build_sessions(args.raw_root, args.out, "2024",
                         "p24_dir", "p24_sessions", "p24_session_groups",
                         "p24_session_tech")
    if s22:
        sessions_by_period["2021_2022"] = s22
    if s24:
        sessions_by_period["2024"] = s24

    print("[3/4] request_response")
    build_request_response(args.raw_root, args.gpt_cowrie, args.out)

    print("[4/4] attack_ttp")
    if sessions_by_period:
        build_attack_ttp(args.out, sessions_by_period)

    print("done.")


if __name__ == "__main__":
    main()
