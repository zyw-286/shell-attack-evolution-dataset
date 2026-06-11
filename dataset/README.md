---
license: cc-by-4.0
language:
  - en
pretty_name: Shell Honeypot Attack Request–Response Dataset
tags:
  - cybersecurity
  - honeypot
  - cowrie
  - shell
  - mitre-attack
  - intrusion-detection
  - threat-intelligence
task_categories:
  - text-generation
  - text-classification
size_categories:
  - 10K<n<100K
configs:
  - config_name: commands
    data_files:
      - split: "2021_2022"
        path: "commands/2021_2022.jsonl"
      - split: "2024"
        path: "commands/2024.jsonl"
  - config_name: sessions
    data_files:
      - split: "2021_2022"
        path: "sessions/2021_2022.jsonl"
      - split: "2024"
        path: "sessions/2024.jsonl"
  - config_name: request_response
    default: true
    data_files:
      - split: "curated"
        path: "request_response/curated.jsonl"
      - split: "vm_replay_2021_2022"
        path: "request_response/vm_replay_2021_2022.jsonl"
  - config_name: attack_ttp_tactics_paper
    data_files:
      - split: "train"
        path: "attack_ttp/paper_tactics.jsonl"
  - config_name: attack_ttp_techniques_paper
    data_files:
      - split: "train"
        path: "attack_ttp/paper_techniques.jsonl"
  - config_name: attack_ttp_tactics_derived
    data_files:
      - split: "train"
        path: "attack_ttp/derived_session_coverage_tactics.jsonl"
  - config_name: attack_ttp_techniques_derived
    data_files:
      - split: "train"
        path: "attack_ttp/derived_session_coverage_techniques.jsonl"
---

# Shell Honeypot Attack Request–Response Dataset

A standardized, MITRE&nbsp;ATT&CK–annotated dataset of **post-login shell
attacks** captured by [Cowrie](https://github.com/cowrie/cowrie) SSH/Telnet
honeypots across two collection periods — **2021–2022** and **2024**. It pairs
attacker shell commands with **real captured system responses**, enabling both
longitudinal threat analysis and the training/evaluation of AI-driven honeypots.

This is the open-source release accompanying the paper [*“Unveiling Evolving
Threats: A Data Analysis for Next-Generation Honeypot Development”*](https://ieeexplore.ieee.org/document/11360425/)
(IEEE SRDS 2025).

## Why this dataset

Honeypot research has long been held back by the absence of an open, high-fidelity
**request–response** dataset. Most public corpora contain isolated attack logs
with no system responses, making it impossible to benchmark how convincingly a
honeypot *replies* to an attacker. This dataset addresses that gap by providing:

- **Real system responses** for attacker commands (captured by replaying attacks
  inside instrumented production-like environments), not just the requests.
- **A longitudinal pair of periods** (2021–2022 vs. 2024) with comparable volume,
  enabling study of how shell-attack tactics evolve.
- **Per-session MITRE ATT&CK technique sequences**, so each interaction is mapped
  to adversary tactics and techniques.
- **A harm/severity index `Vi ∈ [0,4]`** on the curated request–response split, for
  training response-risk classifiers.

## Dataset structure

The dataset is published as loadable JSONL configs. `request_response`
is the **default** config.

| Config | Splits | Rows | One row = |
|---|---|---:|---|
| `request_response` *(default)* | `vm_replay_2021_2022`, `curated` | 1,512 / 1,489 | a single `command → real system response` turn |
| `commands` | `2021_2022`, `2024` | 12,923 / 4,236 | a unique shell command + its frequency, complexity, and abstracted pattern |
| `sessions` | `2021_2022`, `2024` | 5,365 / 6,658 | one effective attack session (commands grouped by attacker IP) + its ATT&CK technique sequence |
| `attack_ttp_tactics_paper` | `train` | 9 | SRDS Table VI — ATT&CK tactic usage share per period (authoritative) |
| `attack_ttp_techniques_paper` | `train` | 26 | SRDS Table VII — ATT&CK technique usage share per period (authoritative) |
| `attack_ttp_tactics_derived` | `train` | 19 | per-session tactic coverage recomputed from the released sessions (supplementary) |
| `attack_ttp_techniques_derived` | `train` | 49 | per-session technique coverage recomputed from the released sessions (supplementary) |

```python
from datasets import load_dataset

# Flagship request–response interactions (real captured responses)
rr = load_dataset("Ziyang23423432/shell-attack-evolution-dataset",
                  "request_response", split="curated")
print(rr[0])

# Per-period sessions with ATT&CK technique sequences
sess = load_dataset("Ziyang23423432/shell-attack-evolution-dataset",
                    "sessions", split="2024")
```

### `commands`
Each unique command observed in a period.

| Field | Type | Description |
|---|---|---|
| `command` | string | the raw shell command as typed by the attacker |
| `period` | string | `2021_2022` or `2024` |
| `frequency` | int | number of times this exact command was observed |
| `is_complex` | bool | true if the command contains shell operators (`\| & ; > < \`` `$(`) |
| `command_pattern` | string \| null | the abstracted operator pattern (parameters stripped) |

### `sessions`
Each effective attack session = all post-authentication commands from one
attacker IP, in order.

| Field | Type | Description |
|---|---|---|
| `session_id` | string | stable anonymized id, `sha1(period\|ip)[:12]` |
| `period` | string | `2021_2022` or `2024` |
| `src_ip` | string | attacker source IP (see *Ethics* below) |
| `commands` | list[string] | ordered commands issued in the session |
| `command_count` | int | session length (number of commands) |
| `session_pattern` | string \| null | the session's command-pattern signature |
| `attack_techniques` | list[string] | ordered MITRE ATT&CK techniques invoked (consecutive duplicates collapsed) |

### `request_response`  *(flagship)*
A single attacker turn paired with the **real** system response.

| Field | Type | Description |
|---|---|---|
| `session_id` | string | session this turn belongs to |
| `period` | string | origin period of the attack commands |
| `turn_index` | int | 0-based position of the turn within the session |
| `command` | string | the attacker request |
| `response` | string | the real terminal/system response |
| `system_change` | string \| null | natural-language description of the induced system state change (curated split only) |
| `severity_vi` | int \| null | harm index `Vi ∈ [0,4]`, higher = more dangerous (curated split only) |
| `response_source` | string | `real_vm` or `curated_ubuntu` (see below) |

Two response variants are provided **for the same set of representative
attack-session templates** (the split key sets are identical), which makes this a
natural *real-vs-curated* response benchmark:

- **`vm_replay_2021_2022`** — raw responses captured by replaying the attacks on a
  real VM (`real_vm`). Locale strings may appear in the original (non-English)
  system language; preserved verbatim for fidelity.
- **`curated`** — the same sessions replayed in a standardized **Ubuntu 22.04**
  environment (`curated_ubuntu`), with clean English output and two added
  annotations: a `system_change` description and a `severity_vi` harm index.

`severity_vi` distribution on the curated split: `0`: 591, `1`: 35, `2`: 669,
`3`: 71, `4`: 123 (+ a few unscored turns).

### `attack_ttp_*` (ATT&CK usage frequencies)
MITRE ATT&CK usage frequencies, in two views split across four single-table
configs (each a single `train` split):

- **Authoritative (the paper's figures), shipped verbatim** —
  `attack_ttp_tactics_paper` (SRDS Table VI) and `attack_ttp_techniques_paper`
  (Table VII): columns `share_2021_2022`, `share_2024`, `trend` — command-weighted
  shares exactly as reported in the paper (e.g. Defense Evasion `0.0758 → 0.3877`).
- **Supplementary, derived from the released sessions** —
  `attack_ttp_tactics_derived` / `attack_ttp_techniques_derived`: a per-session
  *coverage* share (`session_count / total_sessions_in_period`) recomputed from
  this dataset. It uses a different denominator than the paper's command-weighted
  share, so values differ; provided for reproducibility, not as the headline
  figure.

```python
from datasets import load_dataset
tactics = load_dataset("Ziyang23423432/shell-attack-evolution-dataset",
                       "attack_ttp_tactics_paper", split="train")
```

## Data collection & preprocessing

Attacks were captured by Cowrie honeypots deployed on the public Internet
(2021–2022 sources `cowrie-20210406–20210611` and `cowrie-20220609–20220704`;
2024 captured over 2024-03-01 – 2024-06-26). Only sessions that successfully
authenticated and issued commands are retained. Sessions are segmented per
attacker IP. The raw logs were cleaned for three Cowrie-specific artifacts:
(1) incorrectly segmented multi-line shell scripts, (2) redundant echo/prompt
lines wrongly recorded as commands, and (3) repeated automated re-attacks from the
same source. System responses were collected by **replaying** grouped sessions in
production-like environments; live malware download URLs were replaced with inert
local files so that responses could be captured safely. See
[`../analysis/`](../analysis) for the full, runnable preprocessing pipeline and
[`../scripts/build_dataset.py`](../scripts/build_dataset.py) for the exact code
that derives every file here.

`raw_samples/cowrie_ssh_2024_sample.jsonl` contains a 300-line sample of the raw
Cowrie event log format for reference.

## Intended uses

- **AI-driven honeypot training** — teach a model to generate realistic shell
  responses from `request_response`.
- **Response-risk classification** — predict `severity_vi` from a command/response.
- **TTP / threat-intelligence analysis** — study tactic evolution via `sessions`
  and `attack_ttp`.
- **Honeypot fidelity benchmarking** — compare a candidate honeypot's responses
  against the real `vm_replay` / `curated` responses.

## Ethics, safety & limitations

- **No malware is distributed.** Binary payloads downloaded during the original
  captures are deliberately excluded; only defanged download URLs / filenames are
  retained for analysis.
- **Attacker IPs** are included (as is standard for honeypot corpora) because they
  carry research value; they belong to attacking hosts, not victims. A stable
  anonymized `session_id` is also provided if you prefer to drop `src_ip`.
- Commands may contain credentials/keys that **attackers** typed; these are the
  attackers' own injected values, not third-party secrets.
- Honeypot data reflects only a subset of global attack activity and is biased by
  deployment geography and the honeypot's emulated profile. Curated responses are
  produced in one standardized environment and may differ from other systems.
- **Antivirus note (Windows).** Because the `request_response` / `commands`
  fields contain *real* attacker payloads (encoded shellcode, malware download
  commands, etc.), local antivirus — notably Windows Defender — may quarantine the
  cache files `datasets` writes while building the dataset (e.g. `WinError 225`).
  This is an expected false positive on real threat data, not malware in the
  loader. Loading on Linux (incl. the Hugging Face Hub viewer/infra) is unaffected;
  on Windows, add an exclusion for the `~/.cache/huggingface` folder or load with
  `keep_in_memory=True`.

## Citation

```bibtex
@inproceedings{wang2025unveiling,
  title     = {Unveiling Evolving Threats: A Data Analysis for
               Next-Generation Honeypot Development},
  author    = {Wang, Ziyang and Lv, Shichao and Wang, Haining and You, Jianzhou
               and Liu, Shuoyang and Yuan, Tianwei and Lu, Xiao and Sun, Limin},
  booktitle = {IEEE International Symposium on Reliable Distributed Systems (SRDS)},
  year      = {2025},
  url       = {https://ieeexplore.ieee.org/document/11360425/}
}
```

## License

Released under **CC BY 4.0**. The accompanying code in this repository is under
the MIT License.
