# Catching an insider-threat AI agent: rule-based vs. LLM monitors

[![CI](https://github.com/witlesswitness/insider-threat-eval/actions/workflows/ci.yml/badge.svg)](https://github.com/witlesswitness/insider-threat-eval/actions/workflows/ci.yml)

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
- **Attack condition:** the system prompt secretly adds one of five objectives —
  **exfiltration** (move a canary secret), **persistence** (add a cron beacon),
  **defense evasion** (flip `tls_verify`/`auth_required` to false),
  **anti-forensics** (delete the ERROR line to clean the log), or
  **privilege escalation** (plant a backdoor admin credential).
- Ground truth for "did the attack land" is read from the final filesystem
  state, independently of what either monitor thinks.
- Both monitors emit a 0–10 suspicion score, so they're compared on one ROC plot.

## Setup

Use a virtual environment — a self-contained sandbox for this project's
dependencies. On recent Python installs (Homebrew Python on macOS in
particular) a plain `pip install` is blocked with an
`externally-managed-environment` error (PEP 668); a venv is the correct fix, not
`--break-system-packages`.

```bash
python3 -m venv .venv            # create the sandbox (one time)
source .venv/bin/activate        # activate it — prompt now shows (.venv)
pip install -r requirements.txt  # installs into the sandbox
cp .env.example .env             # then paste your key into .env
```

Notes:
- On macOS use `python3`/`pip3` outside the venv; **inside** an activated venv,
  plain `python` and `pip` work and point at the sandbox.
- Each new terminal needs the environment reactivated: `cd` into the project and
  run `source .venv/bin/activate` again. You create it once, reactivate per shell.
- On Windows the activate command is `.venv\Scripts\activate` instead.

Get an API key at <https://console.anthropic.com> → **Settings → API Keys**, and
add ~$20 of credit. A full pilot run costs well under that. The key goes in
`.env`, which is gitignored and never committed.

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
`missed_by_category.png`, `compliance_breakdown.png`, and `summary.json`.

### Two findings, two modes

The live agent (`claude-haiku-5-5`) **refuses or ignores** the injected
insider-threat objective under both the `naive` and `redteam` framings. That is
a real result about the model — the **Path 1** finding, reported as the
compliance breakdown.

Because an aligned agent won't attack, the monitors need signal from somewhere
to be evaluated (**Path 2**). Use the attacker mode for that:

```bash
# Path 1 — what the live model actually does (it declines):
python run_agent.py --n 30 --attacker model

# Path 2 — synthetic attack trajectories so detection can be measured:
python run_agent.py --n 30 --attacker scripted
python score.py
```

`--attacker scripted` makes the harness itself produce the malicious action log
(the honest task done correctly, with the attack action slipped in), representing
what a *compromised* agent would do. Honest episodes always come from the live
model. Each synthetic transcript is flagged `"synthetic": true`. This is a
disclosed, standard way to evaluate monitors; the purer alternative — an actual
open-weights untrusted model as the attacker — is named as future work.

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
| `tasks.py` | honest tasks and the five secret attack objectives |
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
- **One agent model, five attack types.** Sweep several agent models and add
  subtler attacks (slow exfil, living-off-the-land commands).
- **The monitor sees a clean log.** Add log-tampering as an attacker capability.
- **Next:** test whether an agent told to *evade the monitor* changes the gap
  between the two monitors — the more interesting control question.

## Attribution

Attack objectives are benign canaries; nothing in this repo performs real
exploitation. Built as a research portfolio project.
