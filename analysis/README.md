# analysis — the longitudinal analysis pipeline

The numbered scripts reproduce the paper's command-, session-, and ATT&CK-level
analysis. The **same pipeline is run independently for each collection period**:

- [`period_2021_2022/`](period_2021_2022/) — the 2021–2022 dataset
- [`period_2024/`](period_2024/) — the 2024 dataset (plus a [`compare/`](period_2024/compare/) sub-pipeline that diffs the two periods)
- [`common/`](common/) — shared helpers

The scripts were ported from the original research code: comments translated to
English, hardcoded absolute paths lifted into `RAW_ROOT` / `DATA_DIR` constants
at the top of each file, and logic left unchanged. They read/write the
intermediate data files in the raw working directory (some retain their original
Chinese data-file names, since each step consumes the previous step's output by
exact filename).

## Pipeline order

| Step | Script | Does | Output |
|---|---|---|---|
| 1 | `01_extract_sessions.py` | group Cowrie `command.input` events by attacker IP | `session_dict.json` |
| 2 | `02_command_frequency.py` | count command frequencies | `sorted_cmd_counter.json` |
| 3 | `03_classify_commands.py` | split simple vs complex; group simple by head command | `3-大类提取.json`, complex list |
| 4 | `04_complex_command_patterns.py` | tokenize complex commands into operator patterns | `4-复杂指令类型分析-sorted.json` |
| 5 | `05_cluster_sessions.py` | group sessions by command-pattern sequence | `5-session归类.json` |
| 6a–d | `06a_dedup_sessions.py` → `06b_build_download_replacement.py` → `06c_replace_downloads.py` → `06d_extract_responses.py` | dedup sessions, **defang** live malware download URLs (replace with inert files), replay & assemble request→response pairs | request/response pairs |
| 7a | `07a_map_attack_techniques.py` | map commands → MITRE ATT&CK techniques (rules in `common/attack_mapping.py`) | `7-session_tech.json` |
| 7b | `07b_technique_frequency.py` | aggregate technique usage frequency | technique stats |
| 8 | `08_session_length.py`, `08_ip_analysis.py` | session-length distribution / IP analysis | stats / plots |

`period_2024/` additionally has `03_2_system_commands.py` (Ubuntu standard-command
coverage) and an `07a_..._v0.py` earlier variant; `period_2024/compare/`
contains `compare_01_new_commands` … `compare_05_*_recluster` which diff the 2024
data against 2021–2022 (new commands, new parameters, behavior, sessions,
re-clustering).

## Shared helpers (`common/`)

- `primary_process.py` — builds the per-IP session dictionary from raw logs
- `command_pattern.py` — abstracts a concrete command into its operator pattern
- `attack_mapping.py` — the MITRE ATT&CK command→technique rule tables (JSON data)

> Note: the 2024 raw logs use a different event schema than 2021–2022
> (`info`/`tshark`/`src_host` vs `dst_port`/`message`/`src_ip`), so
> `period_2024/` keeps its own `primary_process.py` / `command_pattern.py`
> variants rather than importing from `common/`.

## Reproducing the released dataset

You do not need to re-run this pipeline to use the dataset — the cleaned outputs
are already in [`../dataset/`](../dataset). To rebuild them from raw analysis
outputs, see [`../scripts/build_dataset.py`](../scripts/build_dataset.py). The
paper's ATT&CK tables are emitted by
[`../scripts/build_paper_tables.py`](../scripts/build_paper_tables.py).
