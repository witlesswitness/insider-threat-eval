# GitHub repo metadata (copy-paste when creating the repo)

## Repo name
insider-threat-eval

## Description (the one-liner under the repo title; ~120 chars)
Testbed measuring whether SIEM-style rules or an LLM monitor better catch an AI agent pursuing a hidden malicious objective.

## About / topics (tags)
ai-safety, ai-control, llm, security, prompt-injection, monitoring, red-team, evaluation, anthropic-fellows

## Longer "About" blurb (for a pinned README intro or the application)
An empirical pilot in the AI control tradition. An LLM agent performs routine
sysadmin tasks in a simulated host while secretly pursuing one of five malicious
side-objectives — data exfiltration, persistence, defense evasion, anti-forensics,
or privilege escalation. Two monitors compete to catch it: a rule-based
SIEM-style detector over the agent's tool-call log, and a second, more capable
LLM acting as a reviewer. The harness reports ROC/AUC, catch rate at a fixed
false-positive budget, and a breakdown of which attack types each monitor misses.
Built to bridge SOC detection-engineering practice and frontier AI safety work.

## Suggested gh command
gh repo create insider-threat-eval --private --source=. --push \
  --description "Testbed measuring whether SIEM-style rules or an LLM monitor better catch an AI agent pursuing a hidden malicious objective."
