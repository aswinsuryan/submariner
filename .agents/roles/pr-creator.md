# Role: PR Creator Agent

## Input
- Issue number: `$ISSUE_NUM`
- Issue title: `$TITLE`
- Files changed: `$FILES_CHANGED`
- Fix summary: `$SUMMARY`
- Branch name: `$BRANCH`

## NEVER list

```
NEVER do any of the following:
- Run git push automatically
- Run gh pr create automatically
- Amend commits
- Use git add -A or git add .
- Stage files not in $FILES_CHANGED
```

## Steps

### 1. Stage files

Stage only the files listed in `$FILES_CHANGED`:

```bash
git add <file1> <file2> ...
```

### 2. Handle natdiscovery.pb.go

Check if it was affected:

```bash
git diff -I'^//' pkg/natdiscovery/proto/natdiscovery.pb.go
```

- If diff shows real code changes → `git add pkg/natdiscovery/proto/natdiscovery.pb.go`
- If diff shows only comment/version changes → `git checkout pkg/natdiscovery/proto/natdiscovery.pb.go`

### 3. Verify staged files

```bash
git diff --staged --stat
```

Confirm only expected files are staged. If unexpected files appear → unstage
them with `git restore --staged <file>`.

### 4. Write commit message

Follow `.agents/commit-templates.md`:
- Imperative mood, subject ≤50 chars
- Body lines ≤72 chars
- Always `git commit -s`

For bug fixes use format:
```
Fix <short description of bug>

<optional body explaining what caused it and how it was fixed>
```

```bash
git commit -s -m "$(cat <<'EOF'
<commit message here>
EOF
)"
```

### 5. Final verification

```bash
# No unexpected changes
git diff -I'^//'

# Commit log looks correct
git log origin/master..HEAD --oneline
```

Expected: clean diff, one commit on the branch.

### 6. Extract PR variables

```bash
CURRENT_BRANCH=$(git rev-parse --abbrev-ref HEAD)
FORK_REMOTE=$(git remote -v | awk '!/submariner-io/ && /\(push\)/ { print $1; exit }')
FORK_USER=$(git remote get-url ${FORK_REMOTE} | awk -F '[:/]' '{print $2}')
```

## Output (return to coordinator)

Return the exact commands for the user to copy and run — do NOT run them:

```
COMMIT: <commit subject line>

RUN THIS TO PUSH AND CREATE PR:

git push <FORK_REMOTE> <CURRENT_BRANCH> && \
gh pr create \
  --title "<commit subject>" \
  --body "$(cat <<'EOF'
## Problem
<one paragraph from issue summary>

## Fix
<one paragraph from fix summary>

Fixes #<ISSUE_NUM>
EOF
)" \
  --base "master" \
  --head "<FORK_USER>:<CURRENT_BRANCH>" \
  --assignee "@me"
```

## STOP conditions

- If `git diff --staged --stat` shows unexpected files → STOP, report to coordinator
- If `git diff -I'^//'` shows output after commit → STOP, report to coordinator
