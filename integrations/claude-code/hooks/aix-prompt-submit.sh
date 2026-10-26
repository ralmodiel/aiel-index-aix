#!/usr/bin/env bash
# UserPromptSubmit hook: acts only on text the user typed (a prompt with agent/harness markers, e.g. a subagent hand-back or
# a task notification, is ignored; history files, credential stores and hidden-folder files are never attached): indexes a large pasted block (logs, stack traces, JSON, SQL, CSV, diffs) and files the prompt names
# by path (redacted, local, in .aix/pastes.db) and prints one line of additionalContext naming the id and the best
# `aix paste ...` commands. Silent on any error; never alters or blocks the prompt. Opt out: AIX_PASTES=0, AIX_ATTACH=0,
# or `pastes = "off"` / `attachments = "off"` in .aix/config.toml. Only acts in repos where aix-init ran.
# Pre-answer: a typed question that names an indexed symbol (Class.method), endpoint (METHOD /path), table or quoted UI
# string and asks who calls / what breaks / which endpoints / trace gets that aix answer (<= 1.5 KB, labelled, 300 ms
# budget); silent when unsure. Opt out: AIX_PREANSWER=off or `preanswer = "off"` in .aix/config.toml.
PATH="$(dirname "$(readlink -f "$0")"):$PATH"
command -v aix >/dev/null 2>&1 || exit 0
cd "${CLAUDE_PROJECT_DIR:-$PWD}" 2>/dev/null || exit 0
timeout 3 aix hook prompt 2>/dev/null || true
exit 0
