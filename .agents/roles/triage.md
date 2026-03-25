# Role: Triage Agent

## Input
- Issue number: `$ISSUE_NUM`

## Task

Fetch and classify the GitHub issue.

```bash
gh issue view $ISSUE_NUM --json title,body,labels,comments
```

## Classification Rules

### Issue type

| Signal | Type |
|--------|------|
| "panic", "nil pointer", "not working", "broken", "regression" | bug |
| "add support", "implement", "feature request", "enhancement" | feature |
| "typo", "docs", "documentation", "readme" | docs |
| CVE ID present (CVE-XXXX, GHSA-XXXX) | cve |

### Component

Read issue body and map to component:

| Keywords | Component |
|----------|-----------|
| "ovn", "ovsdb", "logical router", "lrp", "transit switch" | ovn-handler |
| "libreswan", "wireguard", "ipsec", "tunnel", "cable" | gateway |
| "globalnet", "global ip", "egressip", "ingressip" | globalnet |
| "route-agent", "kubeproxy", "kube-proxy", "vxlan" | route-agent |
| "mtu", "fragmentation" | mtu-handler |
| "health", "latency", "ping", "connection status" | healthchecker |
| "calico", "ippool" | calico-handler |

### E2E test matrix

Based on component, set the e2e command:

| Component | e2e command |
|-----------|------------|
| ovn-handler | `make e2e using=ovn` |
| globalnet | `make e2e using=globalnet` AND `make e2e using="globalnet ovn"` |
| gateway / cable | `make e2e` |
| route-agent / mtu / healthchecker | `make e2e` |
| calico-handler | skip (requires Calico cluster) |
| docs | skip |

## Output (return to coordinator)

Return a structured summary:

```
TYPE: <bug|feature|docs|cve>
COMPONENT: <component>
TITLE: <issue title>
SUMMARY: <2-3 sentence description of the problem>
E2E: <exact make command(s) or "skip">
LABELS: <comma-separated labels from issue>
```

## STOP conditions

- If type is `cve` → STOP, tell coordinator to use `cve-fix.md` workflow instead
- If issue does not exist → STOP, report to coordinator
