---
Last Verified: Not yet verified
Verified By: —
Status: Draft
---

# DevOps/SRE — Security Playbooks

## PB-SRE-001: Compromised AWS Credentials

**Trigger**: GuardDuty alert, credential exposure in repo, or anomalous API activity
**Lead Agent**: Gamma (SOC)
**Autonomy**: Credential rotation is pre-approved (autonomous). IAM policy changes require SRE Lead approval.

1. Immediately rotate compromised credential (pre-approved autonomous action)
2. Identify scope: which credential, what access, what was accessed
3. Review CloudTrail for unauthorized API calls during exposure window
4. Assess lateral movement (did attacker access other services/accounts?)
5. If cross-account: escalate to full incident response, consider account isolation
6. Verify no persistent access (new IAM users, roles, policies, access keys)
7. Update findings.md with full timeline and blast radius assessment

## PB-SRE-002: Container Escape / Kubernetes Compromise

**Trigger**: CrowdStrike Falcon Container alert, unexpected privileged process, or anomalous pod behavior
**Lead Agent**: Gamma (SOC)
**Autonomy**: Human-approved for production; Autonomous for staging

1. Identify affected pod/node and workload owner
2. Isolate affected node (cordon + drain — requires SRE on-call approval for production)
3. Capture forensic evidence (container filesystem, network connections, process tree)
4. Assess if attacker reached host level or remained in container
5. Check for lateral movement to other pods/nodes
6. Remediate: terminate compromised pod, patch vulnerability, redeploy from clean image
7. Review pod security standards compliance for the workload

## PB-SRE-003: Secret Exposure in Repository

**Trigger**: GHAS secret scanning alert or manual discovery
**Lead Agent**: Beta-4 (DevSecOps)
**Autonomy**: Autonomous for detection and alerting. Rotation autonomous if automated rotation exists.

1. Identify exposed secret type and scope
2. Immediately rotate secret (autonomous if rotation is automated)
3. Review git history: how long was secret exposed? Which commits?
4. Assess if secret was used by external party (API/access logs)
5. Scrub secret from git history if appropriate (coordinate with SRE)
6. Verify GHAS push protection would block recurrence
7. Update findings.md
