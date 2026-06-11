# Key Findings (paper summary)

This page summarizes the quantitative findings of *“Unveiling Evolving Threats:
A Data Analysis for Next-Generation Honeypot Development”* (SRDS 2025), which this
dataset and pipeline reproduce. It is a reading aid, not a substitute for the
paper.

## Dataset overview (Table I)

| Dataset | Capture | Time span | # Attacks | Effective sessions |
|---|---|---|---:|---:|
| cowrie-2024 | Cowrie honeypot | 2024-03-01 – 2024-06-26 | 3,914,173 | 6,658 |
| cowrie-2021,2022 | Cowrie honeypot | 2021-04-06 – 2021-06-11; 2022-06-09 – 2022-07-04 | 5,099,153 | 5,365 |

These session counts match `dataset/sessions/{2024,2021_2022}.jsonl`.

## Three headline trends (2021–2022 → 2024)

1. **Rising command complexity.** Top commands shift from simple primitives
   (`uname`, `cat /proc/cpuinfo | …`) to multi-stage compound commands that chain
   directory changes and file-attribute manipulation
   (e.g. `cd ~; chattr -ia .ssh; lockr -ia .ssh`).
2. **Shorter, more targeted sessions.** Average session length drops from
   **12.65** to **5.00** commands — attackers sense the environment faster and act
   with fewer commands (better honeypot/decoy awareness).
3. **A pivot to defense evasion.** Defense-Evasion tactic usage jumps from
   **7.58% → 38.77%**, with a denser, more balanced spread of techniques.

## Session statistics (Table V)

| Characteristic | 2021–2022 | 2024 |
|---|---:|---:|
| Session counts | 5,363 | 6,658 |
| Session kinds | 4,161 | 3,118 |
| Distinct session patterns | 145 | 156 |
| Average session length | 12.65 | 5.00 |
| Average length per session kind | 10.97 | 11.80 |

## MITRE ATT&CK tactic shift (Table VI)

| Tactic | 2021–2022 | 2024 | Trend |
|---|---:|---:|:--:|
| Discovery | 33.13% | 18.05% | ↓ |
| Defense Evasion | 7.58% | 38.77% | ↑ |
| Execution | 18.01% | 14.88% | ↓ |
| Persistence | 19.75% | 13.11% | ↓ |
| Privilege Escalation | 19.88% | 13.12% | ↓ |
| Collection | 0.02% | 0.21% | ↑ |
| Command and Control | 1.60% | 1.79% | ↑ |
| Credential Access | 0.00% | 0.01% | ↑ (new) |
| Impact | 0.02% | 0.07% | ↑ |

> The values above (the paper's command-weighted shares) are shipped verbatim in
> `dataset/attack_ttp/paper_tactics.jsonl` and `paper_techniques.jsonl`. A separate
> `derived_session_coverage_*.jsonl` recomputes a per-session *coverage* share from
> the released sessions (different denominator → different values); it is
> supplementary, for reproducibility, not the headline figure.

## Most notable technique changes (Table VII)

| Technique | 2021–2022 | 2024 | Trend |
|---|---:|---:|:--:|
| T1070 Indicator Removal | 1.834% | 17.176% | ↑↑ |
| T1222 File and Directory Permissions Modification | 5.840% | 22.948% | ↑↑ |
| T1562 Impair Defenses | 0% | 1.585% | ↑ (new) |
| T1003 OS Credential Dumping | 0% | 0.017% | ↑ (new) |
| T1082 System Information Discovery | 18.294% | 6.894% | ↓ |
| T1087 Account Discovery | 11.551% | 4.382% | ↓ |
| T1098 Account Manipulation | 20.268% | 13.740% | ↓ |

## Technique chaining (Table VIII)

The dominant ordered technique 2-tuple shifts from a reconnaissance→execution
flow in 2020–2021 (`T1082 System Information Discovery → T1098 Account
Manipulation`, 12.0%) to an anti-forensics flow in 2024 (`T1222 File & Directory
Permissions Modification → T1070 Indicator Removal`, 14.0%). The number of
distinct techniques rises from 22 to 27, and their co-occurrence graph becomes
denser — i.e., more tightly integrated, stealth-first attack pipelines.

## Defensive recommendations (Section V)

1. Adopt AI-driven command analysis for complex/obfuscated shell attacks.
2. Strengthen defenses against defense-evasion (log deletion, permission/firewall
   tampering, file obfuscation).
3. Enhance honeypot realism (high-config hosts, dynamic attack-tailored responses)
   to counter decoy-aware attackers.
4. Broaden detection coverage across the full ATT&CK technique range.
