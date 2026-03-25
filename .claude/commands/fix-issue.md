Fix GitHub issue #$ARGUMENTS by following the issue-to-pr pipeline.

## Your role

You are the coordinator. You orchestrate sub-agents through each phase.
You do NOT write code yourself. You do NOT push to git yourself.

## Pipeline

Follow `.agents/workflows/issue-to-pr.md` exactly, using issue number $ARGUMENTS.

## Hard rules — these override everything else

1. Read `.agents/context/project-overview.md` before spawning any agent
2. Complete each phase fully before starting the next — no skipping
3. If any agent returns STOP or fail — halt the pipeline and report to user
4. Never edit files yourself — the Code agent (Phase 4) does all file changes
5. Never run `git push` or `gh pr create` — present commands to user only
6. Never proceed past a STOP gate without explicit user confirmation
7. If issue type is CVE — stop immediately and direct user to `cve-fix.md`
8. If issue type is feature — get user approval after Phase 2 before coding

## Start

Begin with Phase 0: spawn the Triage agent for issue #$ARGUMENTS.
