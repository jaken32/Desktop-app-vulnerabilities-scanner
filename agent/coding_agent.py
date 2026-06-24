#!/usr/bin/env python3
"""coding_agent.py — Claude-powered agentic coding assistant.

Requires:  anthropic>=0.69.0  (see agent/requirements.txt)
Usage:     python -m agent.coding_agent --help
"""

from __future__ import annotations

import argparse
import fnmatch
import glob
import os
import re
import subprocess
import sys
import textwrap
from pathlib import Path
from typing import Any

# ---------------------------------------------------------------------------
# Graceful import guard
# ---------------------------------------------------------------------------
try:
    import anthropic
except ImportError:
    print(
        "ERROR: The 'anthropic' package is not installed.\n"
        "       Run:  pip install -r agent/requirements.txt",
        file=sys.stderr,
    )
    sys.exit(1)

# ---------------------------------------------------------------------------
# Constants
# ---------------------------------------------------------------------------
MODEL = "claude-opus-4-8"
MAX_TOKENS = 32000
MAX_TURNS = 100
EFFORT_MAP = {
    "low": "low",
    "medium": "medium",
    "high": "high",
    "xhigh": "xhigh",
    "max": "max",
}

SYSTEM_PROMPT = textwrap.dedent("""
    You are an expert software engineer and prompt engineer acting as an
    agentic coding assistant.  Your mission is to help the user understand,
    navigate, and improve a software project confined to a single workspace
    directory.

    Core principles
    ---------------
    1. READ BEFORE YOU EDIT — always inspect relevant files with read_file or
       grep_search before proposing or making changes.
    2. MATCH CONVENTIONS — adopt the style, naming, and structure already
       present in the codebase (indentation, docstring style, import order, …).
    3. MINIMAL TARGETED EDITS — change only what is necessary; prefer edit_file
       over write_file to reduce diff noise.
    4. VERIFY — after editing, re-read the changed file and, where sensible,
       run tests or a quick syntax check with run_bash.
    5. LEAD WITH THE OUTCOME — start every reply with a one-sentence summary of
       what was done or found; put rationale and details after.
    6. ONLY EDIT WHEN ASKED — never modify files unless the user explicitly
       requests a change.
    7. STAY IN THE WORKSPACE — every path you supply to tools must be relative
       to the workspace root; never use absolute paths or '..' traversal.
    8. HANDLE ERRORS GRACEFULLY — if a tool returns an error, explain it to the
       user and suggest a fix rather than retrying blindly.
""").strip()

# ---------------------------------------------------------------------------
# Workspace — path-confinement helper
# ---------------------------------------------------------------------------

class Workspace:
    """Resolves and validates model-supplied paths against the project root."""

    def __init__(self, root: str | Path) -> None:
        self.root = Path(root).expanduser().resolve()
        if not self.root.is_dir():
            raise NotADirectoryError(f"Workspace root is not a directory: {self.root}")

    def resolve(self, path: str) -> Path:
        """Return an absolute path that is guaranteed to be inside *self.root*.

        Raises PermissionError for any path that escapes the root.
        """
        p = Path(path)
        if p.is_absolute():
            candidate = p.resolve()
        else:
            candidate = (self.root / p).resolve()

        try:
            candidate.relative_to(self.root)
        except ValueError:
            raise PermissionError(
                f"Path escape detected: '{path}' resolves to '{candidate}' "
                f"which is outside the workspace root '{self.root}'."
            )

        if candidate.exists() and candidate.is_symlink():
            real = candidate.resolve()
            try:
                real.relative_to(self.root)
            except ValueError:
                raise PermissionError(
                    f"Symlink escape detected: '{path}' -> '{real}' "
                    f"which is outside the workspace root '{self.root}'."
                )

        return candidate

    def relative(self, path: Path) -> str:
        """Return a human-readable relative path string."""
        try:
            return str(path.relative_to(self.root))
        except ValueError:
            return str(path)


# ---------------------------------------------------------------------------
# Tool implementations
# ---------------------------------------------------------------------------

def tool_read_file(ws: Workspace, path: str, start_line: int = 1, end_line: int | None = None) -> str:
    """Read a file with 1-based line numbers prepended."""
    full = ws.resolve(path)
    if not full.exists():
        raise FileNotFoundError(f"File not found: {path!r}")
    if not full.is_file():
        raise IsADirectoryError(f"Path is a directory, not a file: {path!r}")
    lines = full.read_text(encoding="utf-8", errors="replace").splitlines()
    start = max(1, start_line)
    end = len(lines) if end_line is None else min(end_line, len(lines))
    width = len(str(len(lines)))
    result_lines = [f"{i:{width}d} | {lines[i-1]}" for i in range(start, end + 1)]
    return "\n".join(result_lines) if result_lines else "(empty file or range out of bounds)"


def tool_list_dir(ws: Workspace, path: str = ".") -> str:
    """List directory contents."""
    full = ws.resolve(path)
    if not full.exists():
        raise FileNotFoundError(f"Directory not found: {path!r}")
    if not full.is_dir():
        raise NotADirectoryError(f"Path is not a directory: {path!r}")
    entries = sorted(full.iterdir(), key=lambda p: (p.is_file(), p.name.lower()))
    lines = []
    for e in entries:
        kind = "/" if e.is_dir() else (" -> " + str(e.resolve()) if e.is_symlink() else "")
        lines.append(f"{e.name}{kind}")
    return "\n".join(lines) if lines else "(empty directory)"


def tool_glob_search(ws: Workspace, pattern: str, base: str = ".") -> str:
    """Return paths matching *pattern* (relative to *base*) as a newline list."""
    base_path = ws.resolve(base)
    matches = sorted(base_path.glob(pattern))
    if not matches:
        return "(no matches)"
    return "\n".join(ws.relative(m) for m in matches)


def tool_grep_search(ws: Workspace, regex: str, path: str = ".", include: str = "*") -> str:
    """Search for *regex* in files under *path* matching glob *include*."""
    root = ws.resolve(path)
    try:
        compiled = re.compile(regex)
    except re.error as exc:
        raise ValueError(f"Invalid regex: {exc}")

    results = []
    for fpath in sorted(root.rglob(include)):
        if not fpath.is_file():
            continue
        try:
            text = fpath.read_text(encoding="utf-8", errors="replace")
        except OSError:
            continue
        for i, line in enumerate(text.splitlines(), 1):
            if compiled.search(line):
                results.append(f"{ws.relative(fpath)}:{i}: {line}")
    return "\n".join(results) if results else "(no matches)"


def tool_write_file(ws: Workspace, path: str, content: str, auto_approve: bool = False) -> str:
    """Create or overwrite a file (prompts for confirmation unless auto_approve)."""
    full = ws.resolve(path)
    action = "overwrite" if full.exists() else "create"
    if not auto_approve:
        preview = content[:400] + ("…" if len(content) > 400 else "")
        ans = input(
            f"\n[write_file] About to {action} '{ws.relative(full)}':\n"
            f"--- preview ---\n{preview}\n--- end ---\n"
            f"Proceed? [y/N] "
        ).strip().lower()
        if ans != "y":
            return "Cancelled by user."
    full.parent.mkdir(parents=True, exist_ok=True)
    full.write_text(content, encoding="utf-8")
    return f"Written {len(content)} bytes to '{ws.relative(full)}'."


def tool_edit_file(ws: Workspace, path: str, old_str: str, new_str: str, auto_approve: bool = False) -> str:
    """Replace the first (and only) occurrence of *old_str* with *new_str*."""
    full = ws.resolve(path)
    if not full.exists():
        raise FileNotFoundError(f"File not found: {path!r}")
    original = full.read_text(encoding="utf-8", errors="replace")
    count = original.count(old_str)
    if count == 0:
        raise ValueError(
            f"old_str not found in '{path}'.  "
            f"Make sure the substring matches the file exactly (whitespace, indentation)."
        )
    if count > 1:
        raise ValueError(
            f"old_str matches {count} times in '{path}'.  "
            f"Provide a longer, unique substring."
        )
    if not auto_approve:
        print(f"\n[edit_file] In '{ws.relative(full)}':")
        print(f"  - {old_str[:200]!r}")
        print(f"  + {new_str[:200]!r}")
        ans = input("Proceed? [y/N] ").strip().lower()
        if ans != "y":
            return "Cancelled by user."
    updated = original.replace(old_str, new_str, 1)
    full.write_text(updated, encoding="utf-8")
    return f"Edit applied to '{ws.relative(full)}'."


def tool_run_bash(
    ws: Workspace,
    command: str,
    timeout: int = 60,
    auto_approve: bool = False,
) -> str:
    """Run *command* in a shell, cwd=workspace root; return stdout+stderr+exit."""
    if not auto_approve:
        ans = input(
            f"\n[run_bash] About to run:\n  $ {command}\n"
            f"  cwd: {ws.root}\n"
            f"Proceed? [y/N] "
        ).strip().lower()
        if ans != "y":
            return "Cancelled by user."
    try:
        proc = subprocess.run(
            command,
            shell=True,
            cwd=str(ws.root),
            capture_output=True,
            text=True,
            timeout=timeout,
        )
    except subprocess.TimeoutExpired:
        return f"ERROR: command timed out after {timeout}s"
    out = proc.stdout or ""
    err = proc.stderr or ""
    combined = []
    if out:
        combined.append("STDOUT:\n" + out)
    if err:
        combined.append("STDERR:\n" + err)
    combined.append(f"EXIT CODE: {proc.returncode}")
    return "\n".join(combined) if combined else f"EXIT CODE: {proc.returncode}"


# ---------------------------------------------------------------------------
# Tool schema for the Anthropic API
# ---------------------------------------------------------------------------

TOOLS: list[dict[str, Any]] = [
    {
        "name": "read_file",
        "description": (
            "Read a file from the workspace, with 1-based line numbers prepended to "
            "each line.  Optionally restrict to a line range."
        ),
        "input_schema": {
            "type": "object",
            "properties": {
                "path": {"type": "string", "description": "Path relative to workspace root."},
                "start_line": {"type": "integer", "description": "First line to return (1-based, default 1)."},
                "end_line": {"type": "integer", "description": "Last line to return (inclusive, default: end of file)."},
            },
            "required": ["path"],
        },
    },
    {
        "name": "list_dir",
        "description": "List the contents of a workspace directory.",
        "input_schema": {
            "type": "object",
            "properties": {
                "path": {"type": "string", "description": "Directory path relative to workspace root (default '.')."},
            },
            "required": [],
        },
    },
    {
        "name": "glob_search",
        "description": "Return paths inside the workspace that match a glob pattern.",
        "input_schema": {
            "type": "object",
            "properties": {
                "pattern": {"type": "string", "description": "Glob pattern, e.g. '**/*.py'."},
                "base": {"type": "string", "description": "Base directory (relative to workspace, default '.')."},
            },
            "required": ["pattern"],
        },
    },
    {
        "name": "grep_search",
        "description": "Search for a regex in files under a workspace directory.",
        "input_schema": {
            "type": "object",
            "properties": {
                "regex": {"type": "string", "description": "Python-compatible regular expression."},
                "path": {"type": "string", "description": "Directory to search (default '.')."},
                "include": {"type": "string", "description": "Glob filter for filenames (default '*')."},
            },
            "required": ["regex"],
        },
    },
    {
        "name": "write_file",
        "description": (
            "Create or overwrite a file with the given content. "
            "Requires user confirmation unless --yes was passed."
        ),
        "input_schema": {
            "type": "object",
            "properties": {
                "path": {"type": "string", "description": "Path relative to workspace root."},
                "content": {"type": "string", "description": "Full file content to write."},
            },
            "required": ["path", "content"],
        },
    },
    {
        "name": "edit_file",
        "description": (
            "Replace a unique substring in a file.  old_str must appear exactly once; "
            "use a longer string if there are duplicates.  "
            "Requires user confirmation unless --yes was passed."
        ),
        "input_schema": {
            "type": "object",
            "properties": {
                "path": {"type": "string", "description": "Path relative to workspace root."},
                "old_str": {"type": "string", "description": "Exact substring to replace (must be unique in the file)."},
                "new_str": {"type": "string", "description": "Replacement string."},
            },
            "required": ["path", "old_str", "new_str"],
        },
    },
    {
        "name": "run_bash",
        "description": (
            "Run a shell command with cwd=workspace root. "
            "Returns stdout, stderr, and the exit code. "
            "Requires user confirmation unless --yes was passed."
        ),
        "input_schema": {
            "type": "object",
            "properties": {
                "command": {"type": "string", "description": "Shell command to run."},
                "timeout": {"type": "integer", "description": "Timeout in seconds (default 60)."},
            },
            "required": ["command"],
        },
    },
]


# ---------------------------------------------------------------------------
# Tool dispatcher
# ---------------------------------------------------------------------------

def dispatch_tool(
    name: str,
    inputs: dict[str, Any],
    ws: Workspace,
    auto_approve: bool,
) -> tuple[str, bool]:
    """Execute a tool call and return (result_text, is_error)."""
    try:
        if name == "read_file":
            result = tool_read_file(ws, **inputs)
        elif name == "list_dir":
            result = tool_list_dir(ws, **inputs)
        elif name == "glob_search":
            result = tool_glob_search(ws, **inputs)
        elif name == "grep_search":
            result = tool_grep_search(ws, **inputs)
        elif name == "write_file":
            result = tool_write_file(ws, auto_approve=auto_approve, **inputs)
        elif name == "edit_file":
            result = tool_edit_file(ws, auto_approve=auto_approve, **inputs)
        elif name == "run_bash":
            result = tool_run_bash(ws, auto_approve=auto_approve, **inputs)
        else:
            return f"Unknown tool: {name!r}", True
        return result, False
    except (PermissionError, FileNotFoundError, NotADirectoryError,
            IsADirectoryError, ValueError) as exc:
        return str(exc), True
    except Exception as exc:  # noqa: BLE001
        return f"Unexpected error in tool '{name}': {type(exc).__name__}: {exc}", True


# ---------------------------------------------------------------------------
# CodingAgent
# ---------------------------------------------------------------------------

class CodingAgent:
    """Agentic loop wrapping the Anthropic messages API."""

    def __init__(
        self,
        workspace: str | Path = ".",
        auto_approve: bool = False,
        effort: str = "high",
    ) -> None:
        api_key = os.environ.get("ANTHROPIC_API_KEY", "")
        if not api_key:
            print(
                "ERROR: ANTHROPIC_API_KEY environment variable is not set.\n"
                "       Export it or add it to agent/.env.",
                file=sys.stderr,
            )
            sys.exit(2)
        self.client = anthropic.Anthropic(api_key=api_key)
        self.ws = Workspace(workspace)
        self.auto_approve = auto_approve
        self.effort = EFFORT_MAP.get(effort, "high")

    # ------------------------------------------------------------------
    def run(self, prompt: str) -> str:
        """Run a single agentic task and return the final assistant text."""
        messages: list[dict[str, Any]] = [{"role": "user", "content": prompt}]
        final_text = ""

        for turn in range(MAX_TURNS):
            with self.client.messages.stream(
                model=MODEL,
                max_tokens=MAX_TOKENS,
                system=SYSTEM_PROMPT,
                tools=TOOLS,
                messages=messages,
                thinking={"type": "adaptive", "display": "summarized"},
                output_config={"effort": self.effort},
            ) as stream:
                message = stream.get_final_message()

            assistant_text_parts = []
            for block in message.content:
                if block.type == "text":
                    print(block.text, flush=True)
                    assistant_text_parts.append(block.text)
                elif block.type == "thinking":
                    summary = getattr(block, "summary", None)
                    if summary:
                        print(f"\033[2m[thinking] {summary}\033[0m", flush=True)

            final_text = "\n".join(assistant_text_parts)
            messages.append({"role": "assistant", "content": message.content})

            if message.stop_reason != "tool_use":
                break

            tool_use_blocks = [b for b in message.content if b.type == "tool_use"]
            tool_results = []
            for tb in tool_use_blocks:
                print(f"\n\033[33m[tool] {tb.name}({tb.input})\033[0m", flush=True)
                result_text, is_error = dispatch_tool(
                    tb.name, tb.input, self.ws, self.auto_approve
                )
                if is_error:
                    print(f"\033[31m[error] {result_text}\033[0m", flush=True)
                else:
                    display = result_text[:2000] + ("…" if len(result_text) > 2000 else "")
                    print(f"\033[32m[result]\033[0m {display}", flush=True)
                tool_results.append(
                    {
                        "type": "tool_result",
                        "tool_use_id": tb.id,
                        "content": result_text,
                        "is_error": is_error,
                    }
                )

            messages.append({"role": "user", "content": tool_results})

        else:
            print(
                f"\n\033[31mWarning: reached the {MAX_TURNS}-turn limit.\033[0m",
                file=sys.stderr,
            )

        return final_text

    # ------------------------------------------------------------------
    def repl(self) -> None:
        """Interactive multi-turn REPL."""
        print(f"Claude Coding Agent  (workspace: {self.ws.root})")
        print("Type 'exit' or press Ctrl-D to quit.\n")
        while True:
            try:
                user_input = input("> ").strip()
            except (EOFError, KeyboardInterrupt):
                print("\nGoodbye.")
                break
            if user_input.lower() in ("exit", "quit", "q"):
                print("Goodbye.")
                break
            if not user_input:
                continue
            self.run(user_input)
            print()


# ---------------------------------------------------------------------------
# CLI
# ---------------------------------------------------------------------------

def build_parser() -> argparse.ArgumentParser:
    p = argparse.ArgumentParser(
        prog="python -m agent.coding_agent",
        description="Claude-powered agentic coding assistant.",
    )
    p.add_argument(
        "-p", "--prompt",
        metavar="TEXT",
        help="One-shot prompt.  Omit to enter interactive REPL.",
    )
    p.add_argument(
        "-C", "--workspace",
        metavar="DIR",
        default=".",
        help="Project root directory (default: current directory).",
    )
    p.add_argument(
        "--yes",
        action="store_true",
        help="Auto-approve all write/edit/bash confirmation gates.",
    )
    p.add_argument(
        "--effort",
        choices=list(EFFORT_MAP),
        default="high",
        help="Reasoning effort level (default: high).",
    )
    return p


def main() -> None:
    # Guard: key check before heavy work
    if not os.environ.get("ANTHROPIC_API_KEY"):
        print(
            "ERROR: ANTHROPIC_API_KEY is not set.\n"
            "       Export it:  export ANTHROPIC_API_KEY=sk-ant-...\n"
            "       Or copy agent/.env.example to agent/.env and source it.",
            file=sys.stderr,
        )
        sys.exit(2)

    parser = build_parser()
    args = parser.parse_args()

    agent = CodingAgent(
        workspace=args.workspace,
        auto_approve=args.yes,
        effort=args.effort,
    )

    if args.prompt:
        agent.run(args.prompt)
    else:
        agent.repl()


if __name__ == "__main__":
    main()
