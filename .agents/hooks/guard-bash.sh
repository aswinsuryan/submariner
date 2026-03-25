#!/bin/bash
# Guard hook — blocks dangerous git/gh commands from running automatically.
# Receives the tool input as JSON on stdin.
# Exit 0 = allow, Exit 1 = block.

INPUT=$(cat)

# Extract the command being run
COMMAND=$(echo "$INPUT" | grep -o '"command":"[^"]*"' | head -1 | sed 's/"command":"//;s/"//')

# Block list — commands that must only be run by the user manually
BLOCKED_PATTERNS=(
    "git push"
    "gh pr create"
    "gh pr merge"
    "git add -A"
    "git add \."
    "git reset --hard"
    "git rebase -i"
    "git branch -D"
    "git commit --amend"
)

for pattern in "${BLOCKED_PATTERNS[@]}"; do
    if echo "$COMMAND" | grep -q "$pattern"; then
        echo "BLOCKED by .agents/hooks/guard-bash.sh: '$pattern' must be run manually by the user, not automatically by the agent." >&2
        exit 1
    fi
done

exit 0
