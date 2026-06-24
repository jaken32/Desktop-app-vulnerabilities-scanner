# Agent — Claude-powered Coding Agent

A self-contained agentic coding assistant built on the
[Anthropic Python SDK](https://github.com/anthropics/anthropic-sdk-python).
It lives in the `agent/` top-level package and is **completely independent**
from the `deskscanner` package in `src/deskscanner/`.

## Setup

```bash
# 1. Install the agent's own dependencies (do NOT touch the root requirements)
pip install -r agent/requirements.txt

# 2. Export your Anthropic key
export ANTHROPIC_API_KEY="sk-ant-..."
#    Or copy agent/.env.example -> agent/.env and fill it in,
#    then: set -a && source agent/.env && set +a
```

## Usage

### One-shot mode

```bash
# Ask a single question and exit
python -m agent.coding_agent -p "What does the deskscanner package do?"

# Auto-approve all write / edit / bash confirmations (CI-friendly)
python -m agent.coding_agent --yes -p "Run the test suite and report failures"

# Run from a specific workspace root
python -m agent.coding_agent -C /path/to/project -p "List all Python files"

# Choose compute effort (affects reasoning depth / cost)
python -m agent.coding_agent --effort max -p "Refactor the scan engine for readability"
```

### Interactive REPL

```bash
# Drop into a multi-turn conversation
python -m agent.coding_agent
# > What files are in src/deskscanner?
# > Add a docstring to scanner.py
# > exit   (or Ctrl-D)
```

### Programmatic

```python
from agent.coding_agent import CodingAgent

agent = CodingAgent(workspace=".", auto_approve=False, effort="high")
result = agent.run("Summarise the project structure")
print(result)
```

## CLI Reference

| Flag | Short | Default | Description |
|---|---|---|---|
| `--prompt TEXT` | `-p` | — | One-shot prompt; omit for REPL |
| `--workspace DIR` | `-C` | `.` | Project root (all paths confined here) |
| `--yes` | | `False` | Auto-approve write/edit/bash gates |
| `--effort LEVEL` | | `high` | Reasoning effort: `low` `medium` `high` `xhigh` `max` |
| `--help` | | | Show help and exit |

## Tools

| Tool | Description |
|---|---|
| `read_file` | Read a file with line numbers prepended |
| `list_dir` | List the contents of a directory |
| `glob_search` | Find paths matching a glob pattern |
| `grep_search` | Search file contents with a regex |
| `write_file` | Create or overwrite a file (confirmation gate) |
| `edit_file` | Replace a unique substring in a file (confirmation gate) |
| `run_bash` | Run a shell command, capture stdout/stderr/exit code (confirmation gate) |

## Safety

### Path Confinement

Every model-supplied path is resolved against the workspace root before use.
The `Workspace` class raises a `PermissionError` if the resolved path:

- escapes the root via `..` traversal,
- - is an absolute path outside the root,
  - - or is a symlink that points outside the root.
   
    - ### Confirmation Gates
   
    - The three mutating tools — `write_file`, `edit_file`, and `run_bash` — print a
    - summary of the proposed action and wait for `[y/N]` confirmation before
    - proceeding. Pass `--yes` to skip all gates (useful in CI or when running under
    - a human supervisor who pre-approved the task).
   
    - Errors from tool calls are returned to the model as `tool_result` blocks with
    - `is_error: true` rather than crashing the process, so the agent can self-correct.
   
    - ### Turn Limit
   
    - The agentic loop is capped at **100 turns** (one turn = one round-trip to the
    - API). If the cap is reached the session ends with a clear warning. This prevents
    - runaway loops and limits accidental cost overruns.
    - 
