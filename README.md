# Shell Honeypot Attack Dataset & Analysis Toolkit

> Open-source release for the IEEE **SRDS 2025** paper
> [*“Unveiling Evolving Threats: A Data Analysis for Next-Generation Honeypot
> Development”*](https://ieeexplore.ieee.org/document/11360425/).
>
> 📄 **Paper:** https://ieeexplore.ieee.org/document/11360425/

A standardized, MITRE&nbsp;ATT&CK–annotated dataset of post-login **shell
attacks** captured by [Cowrie](https://github.com/cowrie/cowrie) honeypots over
two periods (**2021–2022** and **2024**), together with the full **analysis
pipeline** that reproduces the paper's findings.

This repository delivers the dataset and its analysis as two modules:

| Module | What it is |
|---|---|
| 📦 [`dataset/`](dataset/) | The cleaned, HuggingFace-ready request–response dataset (JSONL) with a dataset card. |
| 🔬 [`analysis/`](analysis/) | The longitudinal command / session / ATT&CK analysis pipeline (per period). |

> The LLM-powered honeypot engine and its deception evaluation are maintained
> separately in the **[HoneyGPT](https://github.com/zyw-286/HoneyGPT)** project.

## Highlights

- **Real request → response pairs.** Unlike most public honeypot corpora (which
  ship attacker requests only), this dataset includes the **real system
  responses**, captured by replaying grouped attack sessions in production-like
  environments.
- **Two comparable periods** (2021–2022 vs. 2024) → study how shell tactics evolve.
- **MITRE ATT&CK technique sequences** per session, plus derived tactic/technique
  frequency tables.
- **Severity-labeled** curated split (`Vi ∈ [0,4]`) for response-risk modeling.

## What the data reveals

A longitudinal comparison of the two periods dismantles the long-held assumption
that automated shell attacks are static. Four shifts stand out (full tables in
[`docs/findings.md`](docs/findings.md)):

**1 · Commands grew more complex and multi-stage.**
The most frequent commands moved from simple primitives to chained, multi-tool
one-liners that probe, modify file attributes, and plant footholds in a single
shot:

| | Top command |
|---|---|
| 2021–2022 | `uname` |
| 2024 | `cd ~; chattr -ia .ssh; lockr -ia .ssh` &nbsp;·&nbsp; `cd && rm -rf .ssh && mkdir .ssh && echo {ssh-rsa key} >> .ssh/authorized_keys && chmod -R ~/.ssh && cd ~` |

**2 · Sessions got shorter and more targeted.**
Average session length fell from **12.65 → 5.00** commands. Attackers fingerprint
the environment faster — distinguishing real hosts from decoys with minimal
interaction — which *narrows the window for detection*.

**3 · A decisive pivot to Defense Evasion.**
Defense-Evasion tactic usage surged **7.58% → 38.77%**, overtaking discovery and
execution as the dominant tactic. At the technique level:

| MITRE technique | 2021–2022 | 2024 |
|---|---:|---:|
| T1070 Indicator Removal (log/history wiping) | 1.83% | **17.18%** |
| T1222 File & Directory Permissions Modification | 5.84% | **22.95%** |
| T1562 Impair Defenses (kill security processes) | 0% | **1.59%** (new) |
| T1003 OS Credential Dumping | 0% | 0.02% (new) |
| T1082 System Information Discovery | 18.29% | 6.89% |

**4 · Broader, more balanced, more tightly chained techniques.**
The number of distinct ATT&CK techniques rose **22 → 27**, and their distribution
flattened (Discovery technique std-dev `0.0645 → 0.0239`) — attackers spread
across more methods rather than relying on a few. The dominant ordered
technique-pair shifted from a noisy *reconnaissance → execution* flow
(`T1082 → T1098`) to a stealth-first *anti-forensics* flow
(`T1222 → T1070`), and the technique co-occurrence graph became markedly denser —
i.e. integrated, multi-stage, evasion-centric attack pipelines.

> **Takeaway for defenders.** Rule-based shell detection struggles against these
> obfuscated, evasion-heavy, decoy-aware campaigns. The findings argue for
> AI-driven command analysis, stronger anti–defense-evasion monitoring, and
> higher-fidelity honeypots that hold advanced attackers longer.

### The case for smarter honeypots → HoneyGPT

The single clearest signal in the data is that attackers now *fingerprint and
abandon* traditional honeypots within a handful of commands (avg. session length
**12.65 → 5.00**). Static, scripted honeypots can no longer keep advanced
adversaries engaged long enough to study them. Countering this calls for
honeypots that **understand intent and respond convincingly in real time** rather
than replaying canned output.

That is exactly what we built **🍯 [HoneyGPT](https://github.com/zyw-286/HoneyGPT)**
— an LLM-powered SSH/Telnet honeypot that extends [Cowrie](https://github.com/cowrie/cowrie)
to analyze each attacker's intent on the fly and generate tailored terminal
responses, breaking the trilemma of *flexibility, interaction depth, and
deceptive realism* at low cost. This dataset is the empirical foundation behind
it: the request–response pairs, ATT&CK annotations, and `Vi` severity labels here
are what make such intent-aware, response-generating honeypots trainable and
benchmarkable.

> 👉 **HoneyGPT project:** https://github.com/zyw-286/HoneyGPT &nbsp;·&nbsp;
> *“HoneyGPT: Breaking the Trilemma in Honeypots with Large Language Models”*,
> Computer Networks, Vol. 282 (2026).

## Repository layout

```
shell-attack-evolution-dataset/
├── dataset/                 # 📦 HuggingFace-standard dataset (see dataset/README.md = dataset card)
│   ├── commands/            #    unique commands + frequency/complexity/pattern  (per period)
│   ├── sessions/            #    attack sessions + ATT&CK technique sequences     (per period)
│   ├── request_response/    #    command → real response turns  (flagship)
│   ├── attack_ttp/          #    ATT&CK technique/tactic frequencies — paper + derived (JSONL)
│   └── raw_samples/         #    a small sample of the raw Cowrie log format
├── analysis/                # 🔬 reproducible analysis pipeline
│   ├── period_2021_2022/    #    numbered pipeline 01..08 for the 2021–2022 data
│   ├── period_2024/         #    numbered pipeline 01..08 for the 2024 data (+ compare/)
│   └── common/              #    shared helpers (session builder, pattern extractor, ATT&CK rules)
├── scripts/
│   ├── build_dataset.py     #    rebuilds dataset/ from the raw analysis outputs
│   └── build_paper_tables.py#    emits the SRDS ATT&CK tables (attack_ttp/paper_*.jsonl)
├── docs/                    # dataset & pipeline documentation
├── 2021,2022/cowrie/        # full raw Cowrie capture — 2021–2022 (unprocessed logs)
├── 2024/cowrie/             # full raw Cowrie capture — 2024 (~1.7 GB, unprocessed logs)
├── requirements.txt
├── CITATION.cff
└── LICENSE
```

> **Raw logs.** The original, unprocessed Cowrie capture is preserved under
> `2021,2022/cowrie/` and `2024/cowrie/` for full reproducibility. The cleaned,
> standardized, analysis-ready data derived from them lives in [`dataset/`](dataset/);
> most users should start there. (These raw directories are large and are not
> part of the Hugging Face dataset, which ships only `dataset/`.)

## Quick start

### Use the dataset

```python
from datasets import load_dataset

ds = load_dataset("Ziyang23423432/shell-attack-evolution-dataset",
                  "request_response", split="curated")
print(ds[0]["command"], "->", ds[0]["response"])
```

Or load the JSONL directly without the `datasets` library:

```python
import json
rows = [json.loads(l) for l in open("dataset/request_response/curated.jsonl", encoding="utf-8")]
```

See [`dataset/README.md`](dataset/README.md) for the full dataset card (configs,
splits, field schemas, provenance, ethics).

### Reproduce the dataset from raw outputs

```bash
python scripts/build_dataset.py \
    --raw-root  /path/to/data-analyse \
    --gpt-cowrie /path/to/gpt_cowrie \
    --out dataset
```

### Run the analysis pipeline

The numbered scripts run in order; each consumes the previous step's output.
See [`analysis/README.md`](analysis/README.md).

## Installation

```bash
pip install -r requirements.txt
```

Core analysis needs only the Python standard library + `pandas`/`openpyxl`;
`datasets`/`pyarrow` are optional, for loading the dataset.

## Ethics & responsible use

This project is for **defensive security research**. No malware binaries are
distributed — only defanged URLs/filenames are retained. The captured commands
and responses describe real intrusion behavior; use them to *build defenses*,
not attacks. See the *Ethics* section of the [dataset card](dataset/README.md).

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

- **Dataset** (`dataset/`): [CC BY 4.0](https://creativecommons.org/licenses/by/4.0/)
- **Code** (everything else): [MIT](LICENSE)
