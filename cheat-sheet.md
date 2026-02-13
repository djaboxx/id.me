# 📋 Technical Interview Cheat Sheet

> **Quick-reference guide** for discussing all assessment solutions. Each section
> gives you the 30-second elevator pitch, key talking points, and a link to the
> full write-up for drill-down.

---

## Assessment Map

| Section | Report File | One-Liner |
|---|---|---|
| [1. OAuth 2.0 Security](#1-oauth-20-security-review--secure-design) | [`Oauth/oauth_assessment.md`](Oauth/oauth_assessment.md) | Found 3 vulns in a partner OAuth platform; designed a full secure replacement with PKCE, token rotation, encryption, scopes, and revocation |
| [2. GKE Multi-Tenancy](#2-gke-multi-tenancy-security-design) | [`gke-multi-tenancy/gke-multi-tenancy.md`](gke-multi-tenancy/gke-multi-tenancy.md) | Namespace-per-team isolation with RBAC, NetworkPolicy, ResourceQuota, Workload Identity, full Terraform IaC, and 3 attack/defense scenarios |
| [3. Container Image Build Security](#3-container-image-build-security) | [`container-image-build-security/container-image-build-security.md`](container-image-build-security/container-image-build-security.md) | Dockerfile hardening, GitHub Actions CI/CD with scan/sign/SBOM, Binary Authorization policy, and CVE vulnerability management process |
| [4. Python Programming](#4-python-programming-assessment) | [`python/python.md`](python/python.md) | Code review (SQL injection, mutable defaults, race conditions), rate limiter implementation, and production OOM debugging |
| [5. Incident Response](#5-incident-response--prioritization) | [`incident-response/incident-response.md`](incident-response/incident-response.md) | Triaged 4 simultaneous alerts; ranked by blast radius and exploitability; full response playbooks for each |

---

## 1. OAuth 2.0 Security Review & Secure Design

📄 **Full report:** [`Oauth/oauth_assessment.md`](Oauth/oauth_assessment.md)

### Vulnerabilities Found (Task 1)

| # | Vulnerability | Severity | 30-Second Pitch |
|---|---|---|---|
| 1 | **Missing PKCE** | CRITICAL | Auth code flow has no `code_challenge`/`code_verifier`. Anyone who intercepts the code (open redirect, referrer leak) can exchange it for tokens. PKCE (RFC 7636) cryptographically binds the code to the requester. |
| 2 | **Non-expiring refresh tokens, no rotation** | CRITICAL | 30-day access tokens + never-expiring refresh tokens = permanent access from a single leak. Should be 15-min access / 90-day refresh with **mandatory rotation** (new token each use, replay = revoke entire family). |
| 3 | **Plaintext token storage** | HIGH | Tokens stored as `VARCHAR(255)` in Cloud SQL. DB breach = mass credential theft. Need **AES-256-GCM** encryption via Cloud KMS + SHA-256 hash for lookup. |

> **Bonus findings:** No `state` param (CSRF), no `redirect_uri` validation, no auth code expiry, no scope enforcement, no revocation endpoint.

### Secure Design (Task 2) — Key Components

| Component | Gist | Drill-Down |
|---|---|---|
| **PKCE Flow** | `code_verifier` → SHA256 → `code_challenge` at `/authorize`; verifier proven at `/token`. S256 only, `plain` rejected. | [§1. Authorization Code Flow with PKCE](Oauth/oauth_assessment.md#1-authorization-code-flow-with-pkce) |
| **Token Encryption** | Refresh tokens: AES-256-GCM encrypted (Cloud KMS) + SHA-256 hash for lookup. Access tokens: signed JWT (RS256), **not stored in DB**. Auth codes: SHA-256 hash only. | [§2. Token Storage Security](Oauth/oauth_assessment.md#2-token-storage-security--encryption-at-rest) |
| **Refresh Token Rotation** | Every use invalidates old token, issues new one. `token_family_id` tracks lineage. Replayed used token → **revoke entire family** (theft detection). | [§3. Refresh Token Rotation](Oauth/oauth_assessment.md#3-refresh-token-rotation-strategy) |
| **Scope-Based Access Control** | `resource:action` naming (`verification:read`, `documents:list`). Enforced at 3 levels: auth server (grant), API gateway (request), resource server (data). | [§4. Scope-Based Access Control](Oauth/oauth_assessment.md#4-scope-based-access-control) |
| **Token Revocation** | RFC 7009 endpoint. Cascading: revoke refresh → revokes family + blocklists JTIs. Access token revocation via Redis JTI blocklist (TTL = 15 min). | [§5. Token Revocation](Oauth/oauth_assessment.md#5-token-revocation-mechanism) |
| **Database Schema** | 5 tables replace the original 1: `oauth_clients`, `oauth_authorization_codes`, `oauth_refresh_tokens`, `oauth_access_token_revocations`, `oauth_consent_records`. | [§6. Complete Database Schema](Oauth/oauth_assessment.md#6-complete-database-schema) |

### Key Numbers to Remember

- Access token: **15 min**, JWT RS256, self-validated
- Refresh token: **90-day absolute**, **14-day idle**, mandatory rotation
- Auth code: **10 min**, single-use, PKCE-bound
- KMS key rotation: **90 days**, auto
- `redirect_uri`: **exact string match**, pre-registered

---

## 2. GKE Multi-Tenancy Security Design

📄 **Full report:** [`gke-multi-tenancy/gke-multi-tenancy.md`](gke-multi-tenancy/gke-multi-tenancy.md)

### Architecture at a Glance

**One namespace per team** (`team-alpha`, `team-beta`, `team-gamma`), each with:

| Control | What It Does |
|---|---|
| **K8s RBAC** | Admin/Editor/Viewer RoleBindings scoped to namespace only (no ClusterRoleBindings for tenants) |
| **Workload Identity** | K8s SA → GCP SA binding; pods get GCP creds without JSON keys |
| **ResourceQuota** | CPU/memory/pod limits per namespace (e.g., 8 CPU / 16Gi / 20 pods) |
| **LimitRange** | Forces every pod to declare resource requests/limits |
| **NetworkPolicy** | Default-deny ingress from other namespaces + restricted egress (DNS only) |
| **PodSecurity `restricted`** | No root, no privilege escalation, no hostPath, drop ALL capabilities |

### Terraform IaC — What's Covered

| File | Resources | Drill-Down |
|---|---|---|
| `variables.tf` / `locals.tf` | Team definitions, project/region config | [§3.1](gke-multi-tenancy/gke-multi-tenancy.md#31-variables--locals) |
| `iam.tf` | Per-team GCP service accounts | [§3.2](gke-multi-tenancy/gke-multi-tenancy.md#32-create-gcp-service-account-for-each-team) |
| `cluster.tf` | GKE cluster with Workload Identity, Shielded Nodes, Binary Auth, Dataplane V2 | [§3.3](gke-multi-tenancy/gke-multi-tenancy.md#33-bind-gcp-sa-to-kubernetes-sa-workload-identity) |
| `cloud_sql.tf` | Per-team Cloud SQL instances + IAM bindings | [§3.4](gke-multi-tenancy/gke-multi-tenancy.md#34-grant-team-alphas-gcp-sa-access-to-only-their-cloud-sql-instance) |
| `storage.tf` | Per-team GCS buckets + IAM | [§3.5](gke-multi-tenancy/gke-multi-tenancy.md#35-cloud-storage-buckets-per-team) |
| `secrets.tf` | Per-team Secret Manager secrets + IAM | [§3.6](gke-multi-tenancy/gke-multi-tenancy.md#36-secret-manager-per-team) |
| `binary_auth.tf` | Binary Authorization attestor + policy | [§3.7](gke-multi-tenancy/gke-multi-tenancy.md#37-binary-authorization-policy) |
| `logging.tf` | Per-tenant log router sinks to team projects | [§3.8](gke-multi-tenancy/gke-multi-tenancy.md#38-multi-tenant-logging-log-router-sinks) |
| `network.tf` | VPC, subnet, firewall rules | [§3.9](gke-multi-tenancy/gke-multi-tenancy.md#39-vpc-network) |

### 3 Isolation Break-Out Scenarios (Task 4)

| Attack | Defense | Key Tech |
|---|---|---|
| **Container escape via kernel exploit** | GKE Sandbox (gVisor), PodSecurity `restricted`, Shielded Nodes, auto-upgrade | gVisor sandboxes syscalls in user-space |
| **K8s API abuse via stolen SA token** | `automountServiceAccountToken: false`, scoped RBAC (never ClusterRoleBinding for tenants), audit logging, deny `escalate`/`bind` verbs | Principle of least privilege at API layer |
| **Cross-tenant network sniffing** | Default-deny NetworkPolicy, Dataplane V2 (Cilium/eBPF), dedicated node pools with taints, mTLS via Cloud Service Mesh | Network-level + cryptographic isolation |

📖 [Full scenarios & defenses](gke-multi-tenancy/gke-multi-tenancy.md#task-4--isolation-break-out-scenarios--defenses)

---

## 3. Container Image Build Security

📄 **Full report:** [`container-image-build-security/container-image-build-security.md`](container-image-build-security/container-image-build-security.md)

### Dockerfile Issues Found (Task 1)

| # | Issue | Severity | Fix |
|---|---|---|---|
| 1 | Running as `root` | CRITICAL | `USER appuser` (UID 10001) + `RUN addgroup/adduser` |
| 2 | `ubuntu:latest` — unpinned, bloated | HIGH | `python:3.12-slim@sha256:...` with digest pin |
| 3 | Unpinned `pip install` deps | HIGH | Pin all versions + hash verification (`--require-hashes`) |
| 4 | No multi-stage build | MEDIUM | 2-stage: `builder` for deps, `runtime` for app only |

📖 [Rewritten Dockerfile](container-image-build-security/container-image-build-security.md#task-2--rewritten-dockerfile)

### CI/CD Pipeline (Task 3) — GitHub Actions

**Pipeline stages:** Lint (Hadolint) → Build → Scan (Trivy, critical=fail) → Sign (Cosign + Cloud KMS) → SBOM (Syft) → Push to Artifact Registry → Attest (Binary Auth) → Deploy

| Tool | Purpose |
|---|---|
| **Hadolint** | Dockerfile linting |
| **Trivy** | Container vulnerability scanning (CRITICAL/HIGH = fail gate) |
| **Cosign** | Image signing with Cloud KMS key |
| **Syft** | SBOM generation (SPDX format) |
| **Binary Authorization** | Only signed images deploy to GKE |

📖 [Full pipeline YAML](container-image-build-security/container-image-build-security.md#32-github-actions-workflow)

### Binary Authorization Policy (Task 4)

- **Production:** Require CI pipeline attestor + security-review attestor (2 attestors)
- **Staging:** Require CI pipeline attestor only
- **Dev:** Allow all (for rapid iteration)
- **Exempt images:** GKE system images, distroless

📖 [Full policy YAML](container-image-build-security/container-image-build-security.md#task-4--binary-authorization-policy)

### Vulnerability Management Process (Task 5)

**Scenario:** Critical CVE in `flask==2.0.1` found 3 months post-deploy.

| Step | Action | SLA |
|---|---|---|
| 1. Detection | Container Analysis, GKE Security Posture, Dependabot, nightly pip-audit, SBOM correlation | Automated, ~hours |
| 2. Impact Assessment | Query Artifact Registry + SBOMs + `kubectl get pods` to find all affected containers | Hour 0–1 |
| 3. Severity Classification | CRITICAL (CVSS ≥ 9.0) → **24h patch / 48h deploy** | Per SLA table |
| 4. Remediation | Update `requirements.txt`, rebuild, re-scan, re-sign, deploy | Hours 1–24 |
| 5. Verification | Confirm new image running, no CVE in new scan | Hour 24–48 |

📖 [Full vulnerability management process](container-image-build-security/container-image-build-security.md#task-5--vulnerability-management-process)

---

## 4. Python Programming Assessment

📄 **Full report:** [`python/python.md`](python/python.md)

### Part 1: Code Review — 3 Bugs in Flask API

| # | Bug | Severity | The Pitch |
|---|---|---|---|
| 1 | **SQL injection** in `find_by_id` | CRITICAL | Uses f-string interpolation instead of parameterized query (`%s`). Direct data breach vector. |
| 2 | **Mutable default argument** `data=[]` | HIGH | Default list shared across all calls → memory leak + cross-customer data leakage. Classic Python gotcha. |
| 3 | **Race conditions** on globals | HIGH | `request_count += 1` not atomic, `verification_cache` unsynchronized, single shared `psycopg2` connection across threads. |

**Fixes provided:** Parameterized query for SQL injection; `ThreadedConnectionPool` + `threading.Lock` for concurrency.

📖 [Full bug analysis + corrected code](python/python.md#part-1-code-review--bug-identification)

### Part 2: Rate Limiter — Key Design Decisions

| Decision | Choice | Why |
|---|---|---|
| **Algorithm** | Sliding window (list of timestamps per user) | Avoids fixed-window boundary problem |
| **Data structure** | `defaultdict(list)` keyed by user | O(1) user lookup, O(W) window filter |
| **Thread safety** | Per-user `threading.Lock` (not one global lock) | Different users don't block each other |
| **Memory management** | Background daemon thread cleans stale entries every 60s | Prevents unbounded growth |
| **Multi-worker?** | ❌ In-memory only. For Gunicorn `-w 4`, need **Redis** (`flask-limiter`) | Explicitly called out |

📖 [Full implementation](python/python.md#21-rate-limiter-implementation) · [Design questions](python/python.md#22-design-questions) · [Unit tests](python/python.md#23-unit-tests)

### Part 3: Production Debugging — FastAPI OOMKilled

**Scenario:** FastAPI in K8s, memory 200MB → 2GB over 6–8h, OOMKilled, DB connections refused, no errors in logs.

| Root Cause | Why It Fits |
|---|---|
| **DB connection leak** | Unclosed connections → exhaust `max_connections` + grow memory. Silent until pool exhausted. |
| **Unbounded in-memory cache** | Dict/list growing with every request, never evicted. Python dicts never shrink backing array. |
| **Async task/coroutine leak** | Un-awaited tasks hold references to local vars (including connections). `asyncio.all_tasks()` grows. |

**Debugging toolkit:** `tracemalloc` (line-level allocations), `pg_stat_activity` (connection leak), `objgraph` (growing types), `asyncio.all_tasks()` (coroutine leak), `pympler` (heap dump), `kubectl top` + Prometheus (external monitoring), `gc.get_stats()` (uncollectable cycles).

📖 [Full root cause analysis](python/python.md#31-top-3-most-likely-root-causes) · [Debugging steps](python/python.md#32-specific-debugging-steps) · [Personal story](python/python.md#33-personal-debugging-story)

---

## 5. Incident Response & Prioritization

📄 **Full report:** [`incident-response/incident-response.md`](incident-response/incident-response.md)

### Scenario

Friday 4:47 PM — 4 alerts fire simultaneously. You're the only security engineer on-call. How do you prioritize?

### Priority Ranking

| Priority | Alert | Severity | Why This Order |
|---|---|---|---|
| 🔴 **P1** | **Unauthenticated Snowflake proxy exposing customer PII** | CRITICAL | Active data exposure RIGHT NOW. No authentication = anyone on the internet can access PII. Highest blast radius. |
| 🔴 **P2** | **AWS `AdministratorAccess` keys committed to public repo** | CRITICAL | Keys are live and public. Bots scrape GitHub for keys within minutes. Full AWS account takeover possible but requires attacker action (not yet exploited vs. P1 which is already exposed). |
| 🟠 **P3** | **Log4Shell (CVE-2021-44228) in internal admin dashboard** | HIGH | RCE vulnerability but it's an *internal* app behind VPN/SSO. Exploitability requires internal access, reducing immediacy vs. P1/P2. |
| 🟡 **P4** | **GKE Workload Identity disabled, SA JSON keys in use** | MEDIUM | Security debt / misconfiguration, not an active exploit. Keys could be rotated but the immediate risk is lower than the others. |

### Triage Framework

**Decision factors:** Active exploitation? → External exposure? → Blast radius? → Exploitability?

📖 [Full playbooks for each alert](incident-response/incident-response.md#priority-ranking) · [Triage decision framework](incident-response/incident-response.md#triage-decision-framework)

---

## 🗣️ Interview Talking Points — Cross-Cutting Themes

If the interviewer asks about **patterns across your solutions**, you can reference these threads:

| Theme | Where It Shows Up |
|---|---|
| **Defense in depth** | OAuth: 3 layers of scope enforcement. GKE: RBAC + NetworkPolicy + PodSecurity + gVisor. Container: Hadolint + Trivy + Cosign + Binary Auth. |
| **Least privilege** | OAuth: per-partner scope registration. GKE: per-team GCP SAs with resource-specific IAM. Container: non-root user, read-only FS, drop all capabilities. |
| **Encryption & key management** | OAuth: AES-256-GCM via Cloud KMS for tokens, RS256 for JWTs. GKE: Secret Manager per team, CMEK for Cloud SQL. Container: Cosign signing via Cloud KMS. |
| **Automation over manual process** | OAuth: automatic key rotation. GKE: Terraform IaC (no manual gcloud). Container: full CI/CD pipeline, automated CVE scanning. Incident: automated detection + alerting. |
| **GCP-native tooling** | Cloud KMS, Secret Manager, Cloud SQL, Artifact Registry, Binary Authorization, Container Analysis, Workload Identity, Dataplane V2, Cloud Service Mesh, Log Router — used throughout. |
| **Python production patterns** | Parameterized queries, connection pooling, thread safety (`threading.Lock`), `time.monotonic()` over `time.time()`, daemon threads for cleanup, `tracemalloc`/`objgraph` for debugging. |
