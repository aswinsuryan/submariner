#!/usr/bin/env python3
# SPDX-License-Identifier: Apache-2.0
# Copyright Contributors to the Submariner project.
#
# External orchestration script for the issue-to-pr workflow.
# Claude acts as a pure thinker per phase — all shell commands run here.
#
# Usage:
#   export ANTHROPIC_API_KEY=sk-ant-...
#   python3 scripts/fix-issue.py <issue-number>
#
# Requirements:
#   pip install anthropic
#   gh, git, make, docker must be available in PATH

import json
import os
import re
import subprocess
import sys
from pathlib import Path

# ---------------------------------------------------------------------------
# Constants
# ---------------------------------------------------------------------------

REPO_ROOT = Path(__file__).parent.parent.resolve()
STATE_DIR = REPO_ROOT / ".agents" / "state"
ROLES_DIR = REPO_ROOT / ".agents" / "roles"
CONTEXT_FILE = REPO_ROOT / ".agents" / "context" / "project-overview.md"
MODEL = "claude-sonnet-4-6"

# Commands the script will NEVER run regardless of what Claude returns
BLOCKED_COMMANDS = [
    "git push",
    "gh pr create",
    "gh pr merge",
    "git add -A",
    "git add .",
    "git reset --hard",
    "git commit --amend",
    "git branch -D",
    "git rebase -i",
]

# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------

def banner(msg: str):
    print(f"\n{'='*60}")
    print(f"  {msg}")
    print(f"{'='*60}")


def info(msg: str):
    print(f"  → {msg}")


def error(msg: str):
    print(f"  ✗ ERROR: {msg}", file=sys.stderr)


def ask_user(prompt: str) -> str:
    print(f"\n  ? {prompt}")
    return input("    > ").strip().lower()


def shell(cmd: str, check: bool = True) -> subprocess.CompletedProcess:
    """Run a shell command. Never runs blocked commands."""
    for blocked in BLOCKED_COMMANDS:
        if blocked in cmd:
            raise RuntimeError(
                f"BLOCKED: '{blocked}' is not allowed to run automatically. "
                "Run it manually."
            )
    return subprocess.run(
        cmd, shell=True, text=True, capture_output=True,
        cwd=REPO_ROOT, check=check
    )


def read_role(name: str) -> str:
    path = ROLES_DIR / f"{name}.md"
    if not path.exists():
        raise FileNotFoundError(f"Role file not found: {path}")
    return path.read_text()


def read_context() -> str:
    return CONTEXT_FILE.read_text()


def read_state(issue_num: str) -> dict:
    state_file = STATE_DIR / f"fix-{issue_num}.state"
    state = {}
    if state_file.exists():
        for line in state_file.read_text().splitlines():
            if "=" in line:
                k, _, v = line.partition("=")
                state[k.strip()] = v.strip()
    return state


def write_state(issue_num: str, updates: dict):
    STATE_DIR.mkdir(parents=True, exist_ok=True)
    state = read_state(issue_num)
    state.update(updates)
    state_file = STATE_DIR / f"fix-{issue_num}.state"
    state_file.write_text(
        "\n".join(f"{k}={v}" for k, v in state.items()) + "\n"
    )
    info(f"State updated: {state_file}")


def validate_fields(output: str, required: list[str], phase: str) -> dict:
    """
    Parse KEY: value lines from Claude output.
    Raises if any required field is missing.
    """
    result = {}
    for line in output.splitlines():
        if ":" in line:
            k, _, v = line.partition(":")
            result[k.strip()] = v.strip()

    missing = [f for f in required if f not in result]
    if missing:
        raise ValueError(
            f"Phase {phase}: Claude output missing required fields: {missing}\n"
            f"Output was:\n{output}"
        )
    return result


# ---------------------------------------------------------------------------
# Claude API call
# ---------------------------------------------------------------------------

def call_claude(system: str, user: str) -> str:
    try:
        import anthropic
    except ImportError:
        error("anthropic SDK not installed. Run: pip install anthropic")
        sys.exit(1)

    api_key = os.environ.get("ANTHROPIC_API_KEY")
    if not api_key:
        error("ANTHROPIC_API_KEY environment variable not set.")
        sys.exit(1)

    client = anthropic.Anthropic(api_key=api_key)
    info(f"Calling Claude ({MODEL})...")

    message = client.messages.create(
        model=MODEL,
        max_tokens=4096,
        system=system,
        messages=[{"role": "user", "content": user}],
    )
    return message.content[0].text


# ---------------------------------------------------------------------------
# Phase 0: Triage
# ---------------------------------------------------------------------------

def phase0_triage(issue_num: str) -> dict:
    banner("Phase 0 — Triage")

    result = shell(
        f"gh issue view {issue_num} --json title,body,labels,comments"
    )
    issue = json.loads(result.stdout)
    title = issue["title"]
    body = issue.get("body", "")
    labels = [l["name"] for l in issue.get("labels", [])]

    info(f"Issue #{issue_num}: {title}")
    info(f"Labels: {labels}")

    role = read_role("triage")
    context = read_context()

    system = (
        "You are a triage agent for the submariner project. "
        "Classify the GitHub issue and return ONLY the structured output "
        "format specified. No extra commentary."
    )
    user = (
        f"Project context:\n{context}\n\n"
        f"Role instructions:\n{role}\n\n"
        f"Issue #{issue_num}\n"
        f"Title: {title}\n"
        f"Labels: {', '.join(labels)}\n"
        f"Body:\n{body}"
    )

    output = call_claude(system, user)
    print(f"\n  Claude triage output:\n{output}\n")

    fields = validate_fields(
        output,
        ["TYPE", "COMPONENT", "TITLE", "SUMMARY", "E2E"],
        "0-triage"
    )

    if fields["TYPE"] == "cve":
        error("Issue is a CVE. Use the cve-fix.md workflow instead.")
        sys.exit(1)

    write_state(issue_num, {
        "PHASE": "0",
        "TYPE": fields["TYPE"],
        "COMPONENT": fields["COMPONENT"],
        "TITLE": fields["TITLE"],
        "SUMMARY": fields["SUMMARY"],
        "E2E": fields["E2E"],
    })

    return fields


# ---------------------------------------------------------------------------
# Phase 1: Research
# ---------------------------------------------------------------------------

def phase1_research(issue_num: str, state: dict) -> dict:
    banner("Phase 1 — Research")

    role = read_role("researcher")
    context = read_context()

    # Collect directory listings for the relevant component path
    component_paths = {
        "ovn-handler": "pkg/routeagent_driver/handlers/ovn/",
        "gateway": "pkg/gateway/ pkg/cableengine/ pkg/cable/",
        "globalnet": "pkg/globalnet/",
        "route-agent": "pkg/routeagent_driver/",
        "mtu-handler": "pkg/routeagent_driver/handlers/mtu/",
        "healthchecker": "pkg/routeagent_driver/handlers/healthchecker/",
        "calico-handler": "pkg/routeagent_driver/handlers/calico/",
    }
    component = state.get("COMPONENT", "")
    path = component_paths.get(component, "pkg/")
    ls_result = shell(f"find {path} -name '*.go' | sort", check=False)

    system = (
        "You are a research agent for the submariner project. "
        "Find all relevant source files for the given issue. "
        "Return ONLY the structured output format. No extra commentary."
    )
    user = (
        f"Project context:\n{context}\n\n"
        f"Role instructions:\n{role}\n\n"
        f"Issue title: {state['TITLE']}\n"
        f"Summary: {state['SUMMARY']}\n"
        f"Component: {component}\n\n"
        f"Source files in component path:\n{ls_result.stdout}"
    )

    output = call_claude(system, user)
    print(f"\n  Claude research output:\n{output}\n")

    if "cannot locate relevant code" in output.lower():
        error("Researcher could not locate relevant code. Stopping.")
        sys.exit(1)

    fields = validate_fields(
        output,
        ["FILES_TO_CHANGE", "ROOT_CAUSE", "FIX_APPROACH"],
        "1-research"
    )

    write_state(issue_num, {
        "PHASE": "1",
        "FILES_TO_CHANGE": fields["FILES_TO_CHANGE"],
        "ROOT_CAUSE": fields["ROOT_CAUSE"],
    })

    return fields


# ---------------------------------------------------------------------------
# Phase 2: Plan
# ---------------------------------------------------------------------------

def phase2_plan(issue_num: str, state: dict, research: dict) -> dict:
    banner("Phase 2 — Plan")

    role = read_role("planner")
    context = read_context()

    system = (
        "You are a planning agent for the submariner project. "
        "Design a minimal, safe implementation plan. "
        "Return ONLY the structured output format. No extra commentary."
    )
    user = (
        f"Project context:\n{context}\n\n"
        f"Role instructions:\n{role}\n\n"
        f"Component: {state['COMPONENT']}\n"
        f"Summary: {state['SUMMARY']}\n"
        f"Files to change: {research['FILES_TO_CHANGE']}\n"
        f"Root cause: {research['ROOT_CAUSE']}\n"
        f"Fix approach: {research['FIX_APPROACH']}"
    )

    output = call_claude(system, user)
    print(f"\n  Claude plan output:\n{output}\n")

    fields = validate_fields(
        output,
        ["PLAN", "BREAKING_CHANGES", "RISK_LEVEL"],
        "2-plan"
    )

    if fields["RISK_LEVEL"] == "high":
        print(f"\n  ⚠ HIGH RISK plan:\n{output}\n")
        answer = ask_user("Risk level is HIGH. Proceed anyway? (yes/no)")
        if answer != "yes":
            info("Stopped by user at plan review.")
            sys.exit(0)

    if fields["BREAKING_CHANGES"].lower() != "none":
        print(f"\n  ⚠ Breaking changes detected: {fields['BREAKING_CHANGES']}")
        answer = ask_user("Breaking changes found. Proceed anyway? (yes/no)")
        if answer != "yes":
            info("Stopped by user at plan review.")
            sys.exit(0)

    if state.get("TYPE") == "feature":
        print(f"\n  Feature request plan:\n{output}\n")
        answer = ask_user("This is a feature. Approve plan and proceed? (yes/no)")
        if answer != "yes":
            info("Stopped by user at plan review.")
            sys.exit(0)

    write_state(issue_num, {
        "PHASE": "2",
        "RISK_LEVEL": fields["RISK_LEVEL"],
    })

    return fields


# ---------------------------------------------------------------------------
# Phase 3: Branch setup
# ---------------------------------------------------------------------------

def phase3_branch(issue_num: str, state: dict) -> str:
    banner("Phase 3 — Branch Setup")

    title = state["TITLE"]
    slug = re.sub(r"[^a-z0-9]+", "-", title.lower()).strip("-")[:40]
    branch = f"fix/{issue_num}/{slug}"

    info(f"Creating branch: {branch}")
    result = shell(f"git checkout -b {branch}", check=False)

    if result.returncode != 0:
        error(f"Branch creation failed:\n{result.stderr}")
        sys.exit(1)

    write_state(issue_num, {"PHASE": "3", "BRANCH": branch})
    info(f"Branch created: {branch}")
    return branch


# ---------------------------------------------------------------------------
# Phase 4: Code
# ---------------------------------------------------------------------------

def phase4_code(issue_num: str, state: dict, plan: dict) -> dict:
    banner("Phase 4 — Code")

    role = read_role("coder")
    context = read_context()

    # Read current content of files to change
    files_to_change = [
        f.strip()
        for f in state.get("FILES_TO_CHANGE", "").split(",")
        if f.strip()
    ]
    file_contents = ""
    for f in files_to_change:
        path = REPO_ROOT / f
        if path.exists():
            file_contents += f"\n\n--- {f} ---\n{path.read_text()}"

    system = (
        "You are a code agent for the submariner project. "
        "Implement the fix exactly as described in the plan. "
        "Return the complete updated file contents for each file to change, "
        "followed by the structured output fields. "
        "NEVER add git commands. NEVER push. Only return code and output fields."
    )
    user = (
        f"Project context:\n{context}\n\n"
        f"Role instructions:\n{role}\n\n"
        f"Plan:\n{plan['PLAN']}\n\n"
        f"Files to change: {state['FILES_TO_CHANGE']}\n\n"
        f"Current file contents:{file_contents}"
    )

    output = call_claude(system, user)
    print(f"\n  Claude code output (summary):\n{output[:500]}...\n")

    # Apply file changes — parse fenced code blocks per file
    # Format: ```go\n// file: path/to/file.go\n<content>\n```
    pattern = re.compile(
        r"```(?:go|)?\s*\n(?://\s*file:\s*(.+?)\n)?(.*?)```",
        re.DOTALL
    )
    changes_applied = []
    for match in pattern.finditer(output):
        filepath_hint = match.group(1)
        content = match.group(2)
        if filepath_hint:
            filepath_hint = filepath_hint.strip()
            target = REPO_ROOT / filepath_hint
            if target.exists():
                target.write_text(content)
                changes_applied.append(filepath_hint)
                info(f"Applied change to: {filepath_hint}")

    if not changes_applied:
        error(
            "Code agent did not return any file changes in expected format.\n"
            "Expected fenced blocks with '// file: path/to/file.go' headers."
        )
        sys.exit(1)

    # Verify diff scope
    diff = shell("git diff --stat")
    print(f"\n  Diff stat:\n{diff.stdout}")

    unexpected = [
        l for l in diff.stdout.splitlines()
        if l.strip() and not any(f in l for f in files_to_change)
        and "|" in l
    ]
    if unexpected:
        error(f"Unexpected files in diff:\n" + "\n".join(unexpected))
        answer = ask_user("Unexpected files changed. Revert and stop? (yes/no)")
        if answer == "yes":
            shell("git checkout -- .")
            sys.exit(1)

    files_changed = ",".join(changes_applied)
    write_state(issue_num, {
        "PHASE": "4",
        "FILES_CHANGED": files_changed,
    })

    return {"FILES_CHANGED": files_changed, "DIFF_STAT": diff.stdout}


# ---------------------------------------------------------------------------
# Phase 5: Unit tests
# ---------------------------------------------------------------------------

def phase5_tests(issue_num: str) -> bool:
    banner("Phase 5 — Unit Tests")

    for attempt in range(1, 3):
        info(f"Running make unit (attempt {attempt}/2)...")
        result = shell("make unit", check=False)

        if result.returncode == 0:
            info("Unit tests passed.")
            write_state(issue_num, {"PHASE": "5", "TESTS": "pass"})
            return True

        error(f"make unit failed (attempt {attempt}):\n{result.stdout[-2000:]}")

        if attempt == 2:
            error("Tests failed after 2 attempts. Stopping.")
            print("\n  Full error output:")
            print(result.stdout[-3000:])
            sys.exit(1)

        # Ask Claude to diagnose on attempt 1 failure
        role = read_role("tester")
        system = (
            "You are a test agent for the submariner project. "
            "Diagnose the test failure and describe the fix needed. "
            "Return only: DIAGNOSIS and FIX_DESCRIPTION fields."
        )
        user = (
            f"Role instructions:\n{role}\n\n"
            f"Test failure output:\n{result.stdout[-3000:]}"
        )
        diagnosis = call_claude(system, user)
        print(f"\n  Claude diagnosis:\n{diagnosis}\n")
        info("Please review diagnosis above and fix will be re-attempted.")

    return False


# ---------------------------------------------------------------------------
# Phase 6: E2E decision
# ---------------------------------------------------------------------------

def phase6_e2e(issue_num: str, state: dict):
    banner("Phase 6 — E2E Tests")

    e2e_cmd = state.get("E2E", "skip")

    if e2e_cmd == "skip":
        info("E2E not required for this issue type. Skipping.")
        return

    print(f"\n  Recommended e2e: {e2e_cmd}")
    print("  This requires Docker and kind. Takes 20-40 minutes.")
    answer = ask_user("Run e2e tests? (yes/skip)")

    if answer != "yes":
        info("E2E skipped by user.")
        return

    # For globalnet: run both commands
    commands = [c.strip() for c in e2e_cmd.split(" AND ")]
    for cmd in commands:
        info(f"Running: {cmd}")
        result = shell(cmd, check=False)
        if result.returncode != 0:
            error(f"E2E failed:\n{result.stdout[-2000:]}")
            answer = ask_user("E2E failed. Proceed to PR anyway? (yes/no)")
            if answer != "yes":
                sys.exit(1)
        else:
            info(f"E2E passed: {cmd}")


# ---------------------------------------------------------------------------
# Phase 7: PR creation
# ---------------------------------------------------------------------------

def phase7_pr(issue_num: str, state: dict, code_result: dict):
    banner("Phase 7 — Prepare PR")

    role = read_role("pr-creator")

    # Stage only the changed files
    files_changed = [
        f.strip()
        for f in state.get("FILES_CHANGED", "").split(",")
        if f.strip()
    ]

    for f in files_changed:
        shell(f"git add {f}")
        info(f"Staged: {f}")

    # Check natdiscovery.pb.go
    pb_diff = shell(
        "git diff -I'^//' pkg/natdiscovery/proto/natdiscovery.pb.go",
        check=False
    )
    if pb_diff.stdout.strip():
        shell("git add pkg/natdiscovery/proto/natdiscovery.pb.go")
        info("Staged natdiscovery.pb.go (has real changes)")
    else:
        shell(
            "git checkout pkg/natdiscovery/proto/natdiscovery.pb.go",
            check=False
        )

    # Verify staged
    staged = shell("git diff --staged --stat")
    print(f"\n  Staged files:\n{staged.stdout}")

    # Ask Claude for commit message
    system = (
        "You are a PR creator agent for the submariner project. "
        "Write a commit message following the commit-templates.md rules. "
        "Subject ≤50 chars, imperative mood, body lines ≤72 chars. "
        "Return ONLY: COMMIT_SUBJECT and COMMIT_BODY fields."
    )
    user = (
        f"Role instructions:\n{role}\n\n"
        f"Issue title: {state['TITLE']}\n"
        f"Summary: {state.get('SUMMARY', '')}\n"
        f"Files changed: {state.get('FILES_CHANGED', '')}\n"
        f"Staged diff:\n{staged.stdout}"
    )
    commit_output = call_claude(system, user)
    print(f"\n  Claude commit message:\n{commit_output}\n")

    fields = validate_fields(
        commit_output, ["COMMIT_SUBJECT", "COMMIT_BODY"], "7-pr"
    )
    subject = fields["COMMIT_SUBJECT"]
    body = fields.get("COMMIT_BODY", "")

    answer = ask_user(f"Commit message: '{subject}'. Accept? (yes/edit/no)")
    if answer == "no":
        info("Stopped by user.")
        sys.exit(0)
    if answer == "edit":
        subject = input("  Enter commit subject: ").strip()
        body = input("  Enter commit body (optional): ").strip()

    # Commit
    commit_msg = subject
    if body:
        commit_msg = f"{subject}\n\n{body}"

    commit_result = shell(
        f'git commit -s -m "{commit_msg}"', check=False
    )
    if commit_result.returncode != 0:
        error(f"Commit failed:\n{commit_result.stderr}")
        sys.exit(1)
    info("Committed.")

    # Final verification
    diff_check = shell("git diff -I'^//'")
    if diff_check.stdout.strip():
        error("Unexpected changes remain after commit.")
        print(diff_check.stdout)
        sys.exit(1)

    log = shell("git log origin/master..HEAD --oneline")
    print(f"\n  Commits on branch:\n{log.stdout}")

    # Extract PR variables
    branch = state.get("BRANCH", "")
    fork_remote_result = shell(
        "git remote -v | awk '!/submariner-io/ && /\\(push\\)/ { print $1; exit }'",
        check=False
    )
    fork_remote = fork_remote_result.stdout.strip() or "origin"

    fork_user_result = shell(
        f"git remote get-url {fork_remote} | awk -F '[:/]' '{{print $2}}'",
        check=False
    )
    fork_user = fork_user_result.stdout.strip()

    pr_body = (
        f"## Problem\n{state.get('SUMMARY', state['TITLE'])}\n\n"
        f"## Fix\n{code_result.get('DIFF_STAT', '')}\n\n"
        f"Fixes #{issue_num}"
    )

    print("\n" + "="*60)
    print("  PR READY — run this command to push and create the PR:")
    print("="*60)
    print(f"""
git push {fork_remote} {branch} && \\
gh pr create \\
  --title "{subject}" \\
  --body "$(cat <<'EOF'
{pr_body}
EOF
)" \\
  --base "master" \\
  --head "{fork_user}:{branch}" \\
  --assignee "@me"
""")


# ---------------------------------------------------------------------------
# Main
# ---------------------------------------------------------------------------

def main():
    if len(sys.argv) < 2:
        print("Usage: python3 scripts/fix-issue.py <issue-number>")
        sys.exit(1)

    issue_num = sys.argv[1]

    print(f"\n  Submariner Issue-to-PR Pipeline")
    print(f"  Issue: #{issue_num}")
    print(f"  Repo:  {REPO_ROOT}")
    print(f"  Model: {MODEL}")

    # Verify prerequisites
    for tool in ["gh", "git", "make"]:
        result = shell(f"which {tool}", check=False)
        if result.returncode != 0:
            error(f"Required tool not found: {tool}")
            sys.exit(1)

    auth = shell("gh auth status", check=False)
    if auth.returncode != 0:
        error("gh CLI not authenticated. Run: gh auth login")
        sys.exit(1)

    # Run pipeline
    triage = phase0_triage(issue_num)
    state = read_state(issue_num)

    research = phase1_research(issue_num, state)
    state = read_state(issue_num)

    plan = phase2_plan(issue_num, state, research)
    state = read_state(issue_num)

    phase3_branch(issue_num, state)
    state = read_state(issue_num)

    code_result = phase4_code(issue_num, state, plan)
    state = read_state(issue_num)

    phase5_tests(issue_num)
    state = read_state(issue_num)

    phase6_e2e(issue_num, state)
    state = read_state(issue_num)

    phase7_pr(issue_num, state, code_result)

    banner("Pipeline complete")


if __name__ == "__main__":
    main()
