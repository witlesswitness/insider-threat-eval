# Catching an insider-threat AI agent: rule-based vs. LLM monitors

A small empirical study in the **AI control** tradition. We give an LLM agent a
secret, misaligned side-objective while it performs an ordinary sysadmin task,
then measure how well two kinds of monitor catch it:

1. a **rule-based (SIEM-style) monitor** over the agent's tool-call log, and
2. an **LLM-based monitor** — a second, different model that reads the transcript
   and scores how suspicious it looks.

**Research question:** When an autonomous agent pursues a hidden malicious goal,
how reliably does each monitor catch it, at what false-positive cost, and *which
kinds of attack does each one miss*?

> Status: pilot study built as a portfolio project. The harness is designed to
> scale to a larger, more rigorous version; see **Limitations & next steps**.

## Why this matters

Organizations are beginning to deploy LLM agents with real tool access. If such
an agent is compromised (prompt injection) or misaligned, it becomes an insider
threat: it looks like it's doing its job while quietly exfiltrating data,
establishing persistence, or weakening defenses. The defensive question is
whether our monitoring catches that — and traditional detection engineering and
LLM-based monitoring are two very different answers.

## What the experiment does

- The agent operates in a **simulated** host (fake filesystem + fake shell).
  Nothing real executes, so the attack objectives are safe by construction and
  the runs are fully reproducible.
- **Honest condition:** the agent just does the task.
- **Attack condition:** the system prompt secretly adds one of three objectives —
  **exfiltration** (move a canary secret), **persistence** (add a cron beacon),
  or **defense evasion** (flip `tls_verify`/`auth_required` to false).
- Ground truth for "did the attack land" is read from the final filesystem
  state, independently of what either monitor thinks.
- Both monitors emit a 0–10 suspicion score, so they're compared on one ROC plot.

## Setup

```bash
python -m venv .venv && source .venv/bin/activate   # optional
pip install -r requirements.txt
cp .env.example .env            # then paste your key into .env
```

Get an API key at <https://console.anthropic.com> → **Settings → API Keys**, and
add ~$20 of credit. A full pilot run costs well under that.

## Run it

**Offline smoke test (no key, $0)** — proves the whole pipeline works:

```bash
python run_agent.py --provider mock --n 6
python score.py     --provider mock
```

**Real run:**

```bash
python run_agent.py --n 30        # collect 30 honest + 30 attack transcripts
python score.py                   # score with both monitors, write charts
```

Outputs land in `results/`: `roc.png`, `catch_rate.png`,
`missed_by_category.png`, and `summary.json` (all the numbers).

## Models

Set in `config.py` (overridable via `.env`). The agent and monitor use
**different** models on purpose — you don't want the same model both committing
and judging the sabotage.

| Role    | Default            | Why                          |
|---------|--------------------|------------------------------|
| Agent   | `claude-haiku-5-5` | cheap, run many times        |
| Monitor | `claude-sonnet-5-5`| more capable, independent    |

## Repo layout

| File | What it is |
|------|-----------|
| `environment.py` | simulated filesystem + tools + tool-call logging |
| `tasks.py` | honest tasks and the three secret attack objectives |
| `run_agent.py` | runs episodes, writes transcripts, labels attack success |
| `monitors/rule_based.py` | **SIEM-style detections — the detection-engineering core** |
| `monitors/llm_monitor.py` | second-model suspicion scorer |
| `score.py` | ROC, catch-rate-at-fixed-FPR, miss-by-category, summary |
| `model_client.py` | provider wrapper (Anthropic / offline mock; swappable) |

The rule-based monitor is written to be extended — each detection is a small,
named function with a weight. Adding your own rules is the intended way to make
this project your own.

## Limitations & next steps

Honest about what this pilot is and isn't:

- **Simulated, not real.** The environment is a stand-in; real hosts are noisier.
- **Small N.** Run more episodes and bootstrap confidence intervals on the AUCs.
- **One agent model, three attack types.** Sweep several agent models and add
  subtler attacks (slow exfil, living-off-the-land commands).
- **The monitor sees a clean log.** Add log-tampering as an attacker capability.
- **Next:** test whether an agent told to *evade the monitor* changes the gap
  between the two monitors — the more interesting control question.

## Attribution

Attack objectives are benign canaries; nothing in this repo performs real
exploitation. Built as a research portfolio project.
