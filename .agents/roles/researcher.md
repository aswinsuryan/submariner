# Role: Research Agent

## Input
- Issue title: `$TITLE`
- Issue summary: `$SUMMARY`
- Component: `$COMPONENT`

## Task

Find all code relevant to this issue. Do NOT modify any files.
Use only read/search tools (Glob, Grep, Read).

## Steps

### 1. Extract search terms

From the issue title and summary, extract:
- Function/type names mentioned
- Error messages (search for exact strings)
- File names mentioned
- Kubernetes resource types mentioned

### 2. Search by component

Start search in the component's known location:

| Component | Start path |
|-----------|-----------|
| ovn-handler | `pkg/routeagent_driver/handlers/ovn/` |
| gateway | `pkg/gateway/`, `pkg/cableengine/`, `pkg/cable/` |
| globalnet | `pkg/globalnet/` |
| route-agent | `pkg/routeagent_driver/` |
| mtu-handler | `pkg/routeagent_driver/handlers/mtu/` |
| healthchecker | `pkg/routeagent_driver/handlers/healthchecker/` |
| calico-handler | `pkg/routeagent_driver/handlers/calico/` |

### 3. Broaden if needed

If the component search yields nothing, search:
- `pkg/event/` — event handler interface
- `pkg/apis/submariner.io/v1/` — API types
- `pkg/packetfilter/` — packet filter abstraction

### 4. Find tests

For every source file identified, find its test file:
- Same directory, `*_test.go` suffix
- Check for `fake/` subdirectory

### 5. Read relevant files

Read each identified file. Focus on:
- The function/method most likely containing the bug
- How it is called (callers)
- How it is tested (existing tests)

## Output (return to coordinator)

```
FILES_TO_CHANGE:
  - path/to/file.go (line X-Y): <reason>

TEST_FILES:
  - path/to/file_test.go: <existing|new needed>

ROOT_CAUSE:
  <2-4 sentence explanation of why the bug occurs>

FIX_APPROACH:
  <2-3 sentence description of the fix>

RISKS:
  <any other components that might be affected>
```

## STOP conditions

- If no relevant files found after searching component path AND broader search
  → STOP, report "cannot locate relevant code" to coordinator
- Do NOT guess or fabricate file paths
