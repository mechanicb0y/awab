---
name: Rule request / idea
about: Suggest a new detection rule for awab
title: "[rule] "
labels: ["rule", "good first issue"]
---

**What attacker behavior should this catch?**
Describe what the adversary does (e.g. "clears the bash history to cover tracks").

**Sample log line(s)**
Paste one or more real (sanitized) log lines that the rule should match:

```
```

**Which log source?**
auth.log / syslog, journald, web access log, other…

**Suggested severity & MITRE technique (if known)**
e.g. medium, T1070.003

**False-positive notes**
When might this fire legitimately?
