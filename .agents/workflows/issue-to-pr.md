# Issue to PR — Coordinator Workflow

Orchestrates sub-agents to fix a GitHub issue end-to-end.
Each phase MUST complete successfully before the next begins.

## NEVER list — coordinator absolute restrictions

```
NEVER do any of the following:
- Skip a phase or proceed past a STOP gate without explicit user approval
- Edit any file yourself — delegate all file changes to the Code agent
- Run git push or gh pr create
- Proceed if any agent returns STOP or fail
- Assume tests pass without running them
```

---

## Phase 0 — Triage

Spawn **Triage agent** following `.agents/roles/triage.md` with `$ISSUE_NUM`.

**STOP gate:** Do not proceed until triage returns a structured result.

- If `TYPE=cve` → STOP, tell user to use `cve-fix.md` workflow instead
- If `TYPE=feature` → proceed but note: user approval required after Phase 2
- If `TYPE=docs` → skip to Phase 6 (PR Creator)
- Write triage result to `.agents/state/fix-$ISSUE_NUM.state`:

```bash
cat > .agents/state/fix-${ISSUE_NUM}.state << EOF
PHASE=0
TYPE=<value>
COMPONENT=<value>
TITLE=<value>
E2E=<value>
EOF
```

---

## Phase 1 — Research

Re-read state before starting:
```bash
cat .agents/state/fix-${ISSUE_NUM}.state
```

Spawn **Explore agent** following `.agents/roles/researcher.md` with:
- `$TITLE`, `$SUMMARY`, `$COMPONENT` from state file

**STOP gate:** Do not proceed until researcher returns `FILES_TO_CHANGE`.

- If researcher returns "cannot locate relevant code" → STOP, report to user
- Append to state file:

```bash
echo "FILES_TO_CHANGE=<comma-separated>" >> .agents/state/fix-${ISSUE_NUM}.state
echo "PHASE=1" >> .agents/state/fix-${ISSUE_NUM}.state
```

> Phases 1 and 2 MAY run in parallel if the issue description is unambiguous.

---

## Phase 2 — Plan

Re-read state before starting:
```bash
cat .agents/state/fix-${ISSUE_NUM}.state
```

Spawn **Plan agent** following `.agents/roles/planner.md` with:
- `$SUMMARY`, `$COMPONENT`, `$RESEARCH` from Phase 1 output

**STOP gate:** Do not proceed until planner returns a `PLAN`.

- If `RISK_LEVEL=high` → STOP, present risk to user, wait for explicit approval
- If `BREAKING_CHANGES` is not `none` → STOP, present to user, wait for approval
- If `TYPE=feature` (from state file) → present plan to user, wait for approval
- Append to state file:

```bash
echo "PHASE=2" >> .agents/state/fix-${ISSUE_NUM}.state
echo "RISK_LEVEL=<value>" >> .agents/state/fix-${ISSUE_NUM}.state
```

---

## Phase 3 — Branch Setup

Re-read state before starting:
```bash
cat .agents/state/fix-${ISSUE_NUM}.state
```

Create the fix branch (coordinator does this inline):

```bash
SLUG=$(gh issue view $ISSUE_NUM --json title -q .title \
  | tr '[:upper:]' '[:lower:]' \
  | sed 's/[^a-z0-9]/-/g' \
  | sed 's/--*/-/g' \
  | cut -c1-40)
git checkout -b fix/${ISSUE_NUM}/${SLUG}
echo "BRANCH=fix/${ISSUE_NUM}/${SLUG}" >> .agents/state/fix-${ISSUE_NUM}.state
echo "PHASE=3" >> .agents/state/fix-${ISSUE_NUM}.state
```

**STOP gate:** If branch creation fails → STOP, report to user.

---

## Phase 4 — Code

Re-read state before starting:
```bash
cat .agents/state/fix-${ISSUE_NUM}.state
```

Spawn **general-purpose agent** (`isolation=worktree`) following
`.agents/roles/coder.md` with:
- `$PLAN` from Phase 2
- `$FILES_TO_CHANGE` from state file
- `$ISSUE_NUM`

**STOP gate:** Do not proceed until coder returns `READY_FOR_TESTS: yes`.

- If coder returns STOP → halt pipeline, report to user
- If `DIFF_STAT` shows unexpected files → halt, report to user
- Apply worktree changes to fix branch
- Append to state file:

```bash
echo "FILES_CHANGED=<comma-separated>" >> .agents/state/fix-${ISSUE_NUM}.state
echo "PHASE=4" >> .agents/state/fix-${ISSUE_NUM}.state
```

---

## Phase 5 — Unit Tests

Re-read state before starting:
```bash
cat .agents/state/fix-${ISSUE_NUM}.state
```

Spawn **general-purpose agent** (`isolation=worktree`) following
`.agents/roles/tester.md` with:
- `$FILES_CHANGED` from state file
- `$ISSUE_NUM`

**STOP gate:** Do not proceed until tester returns `RESULT: pass`.

- If `RESULT: fail` → STOP, show user the full error, do not proceed to PR
- Append to state file:

```bash
echo "PHASE=5" >> .agents/state/fix-${ISSUE_NUM}.state
echo "TESTS=pass" >> .agents/state/fix-${ISSUE_NUM}.state
```

---

## Phase 6 — E2E Decision

Re-read state before starting:
```bash
cat .agents/state/fix-${ISSUE_NUM}.state
```

Present e2e command from state file to user:

> "Unit tests pass. The triage identified this as a `$COMPONENT` issue.
> Recommended e2e: `$E2E_COMMAND`
> This requires Docker and kind and takes 20-40 minutes.
> Proceed with e2e? (yes / skip)"

Run e2e only if user says yes. If e2e fails, report output to user and STOP.

---

## Phase 7 — PR

Re-read state before starting:
```bash
cat .agents/state/fix-${ISSUE_NUM}.state
```

Spawn **general-purpose agent** following `.agents/roles/pr-creator.md` with:
- `$ISSUE_NUM`, `$TITLE`, `$FILES_CHANGED`, `$BRANCH` from state file
- `$SUMMARY` from Phase 4 coder output

**STOP gate:** Do not proceed until pr-creator returns the push+PR command.

Present the exact `git push + gh pr create` command to the user.
**Do not run it.** Wait for user to copy and run it.

---

## State file

Written at each phase to `.agents/state/fix-$ISSUE_NUM.state`:

```
PHASE=<0-7>
TYPE=<bug|feature|docs|cve>
COMPONENT=<component>
E2E=<command>
FILES_TO_CHANGE=<comma separated>
FILES_CHANGED=<comma separated>
BRANCH=<branch name>
```

The `.agents/state/` directory is gitignored.

---

## Phase summary

| Phase | Agent | Role file | Blocks next? |
|-------|-------|-----------|-------------|
| 0 | Triage | `roles/triage.md` | yes |
| 1 | Explore | `roles/researcher.md` | yes |
| 2 | Plan | `roles/planner.md` | yes |
| 3 | Coordinator inline | — | yes |
| 4 | general-purpose (worktree) | `roles/coder.md` | yes |
| 5 | general-purpose (worktree) | `roles/tester.md` | yes |
| 6 | User decision | — | yes |
| 7 | general-purpose | `roles/pr-creator.md` | yes |
