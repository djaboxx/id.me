# Security Engineering Interview Prep — Questions & Answers

> Based on the technical assessment materials in this repository.
> Prepared for follow-up interview on February 19, 2026.

---

## Table of Contents

1. [Python / Application Security](#python--application-security)
2. [Container Image Build Security](#container-image-build-security)
3. [GKE Multi-Tenancy](#gke-multi-tenancy)
4. [Incident Response & Prioritization](#incident-response--prioritization)
5. [OAuth 2.0 Security](#oauth-20-security)
6. [Cross-Cutting / Behavioral](#cross-cutting--behavioral)

---

## Python / Application Security

### Q1: Why is the SQL injection in `find_by_id` especially dangerous given the context of this application?

**A:** This is a customer verification service — it likely stores sensitive identity data (SSNs, PII). SQL injection here isn't just read access; an attacker can use `UNION SELECT` to extract data from other tables, or `; DROP TABLE` to destroy data. The inconsistency with the `save` method (which correctly uses parameterized queries) makes it worse because it suggests a code review gap — the developer knew the right pattern but missed applying it in one place. The fix is straightforward: use `%s` placeholders with a tuple parameter and let psycopg2 handle escaping.

---

### Q2: Explain the mutable default argument bug. Why is it particularly insidious under load?

**A:** Python evaluates default arguments once at function definition time, not per call. `data=[]` means every invocation that doesn't pass `data` shares the same list object. Under load, verification results from Customer A bleed into Customer B's response (data leakage), and the list grows unboundedly (memory leak). It's insidious because it works perfectly on the first call and in unit tests — it only manifests after sustained production traffic. Fix: use `data=None` and `data = data if data is not None else []`.

---

### Q3: The app uses `threaded=True`. Walk me through the race condition on `request_count += 1`.

**A:** `request_count += 1` compiles to four bytecode instructions: `LOAD_GLOBAL`, `LOAD_CONST`, `BINARY_ADD`, `STORE_GLOBAL`. Two threads can both load the same value (say 42), both add 1, and both store 43 — losing a count. The GIL does not protect against this because it can release between any two bytecodes. The fix is wrapping the increment in a `threading.Lock`, or using `itertools.count()` or `threading` primitives. The same class of bug affects the `verification_cache` list — iterating while another thread appends can cause duplicate entries.

---

### Q4: Why did you choose a sliding window over a fixed window for the rate limiter?

**A:** A fixed window has a boundary problem: a user can send 100 requests at 11:59:59 and 100 more at 12:00:01 — 200 in 2 seconds, despite a 100/minute limit. The sliding window tracks individual timestamps so enforcement is accurate at any point in time. The tradeoff is O(W) per request (where W = max_requests) vs. O(1) for fixed window, but for typical limits (100 requests), this is negligible. For 10,000+ per window, I'd use a deque with `popleft()`.

---

### Q5: Your rate limiter uses per-user locks. Why not a single global lock?

**A:** A single global lock serializes *all* requests — User A's rate check blocks User B even though their limits are independent. Per-user locks allow concurrent rate checks for different users while serializing only same-user requests. There's a global lock that only protects creating new per-user locks (the dict of locks), which is fast and uncontended. This pattern reduces contention by orders of magnitude under production load.

---

### Q6: Would your rate limiter work with Gunicorn running 4 workers? What would you change?

**A:** No. Gunicorn with `--workers=4` uses separate processes, each with its own memory. The in-memory `_requests` dict is not shared. A user gets 4x the intended rate limit (100 per worker = 400 total). The production fix is **Redis** with atomic Lua scripts or `MULTI/EXEC` for sliding-window counting. Libraries like `flask-limiter` support this. Redis also works across multiple pods in Kubernetes.

---

### Q7: In your debugging story, why was the memory leak hard to find with `tracemalloc`?

**A:** `tracemalloc` showed `dict` objects growing, but Python uses dicts everywhere — function locals, module globals, object `__dict__`, etc. The signal was lost in noise. The breakthrough was taking *differential* snapshots 5 minutes apart and looking at the *delta*, which isolated the growing allocation to a specific line in the logging module. The lesson: absolute heap snapshots are noisy; time-differential analysis isolates leaks.

---

### Q8: What are the risks of dropping log records as a fix for the buffer overflow?

**A:** Seven key risks:

1. **Observability gaps during the worst moments** — you lose logs precisely when ES is failing, which correlates with incidents you need to investigate.
2. **Thread safety / race condition** — `self.buffer = self.buffer[-5000:]` is not atomic in a multithreaded Celery worker.
3. **Compliance and audit risk** — this is a financial reconciliation service; SOX/PCI-DSS may require complete log retention.
4. **Masking the root cause** — stability reduces urgency to fix the real problem (ES reliability).
5. **Unbounded loss during extended outages** — the fill→drop→refill cycle can retain <10% of records over a multi-hour outage.
6. **Severed causality chains** — dropping oldest records removes the *beginning* of cause-and-effect sequences.
7. **Dropped-record metric may itself be lost** — if the Prometheus gauge is emitted through the same buffered path.

---

## Container Image Build Security

### Q9: What's wrong with `FROM ubuntu:latest` for a production container handling SSNs?

**A:** Two issues:

1. **`latest` is a mutable tag** — two builds on different days get different images with no way to audit what ran. Non-reproducible builds.
2. **Full Ubuntu includes hundreds of unnecessary packages** (`curl`, `git`, shells, compilers) — each is added attack surface. An attacker who compromises the container can use `curl` to exfiltrate data.

Fix: use a minimal base like `python:3.12-slim-bookworm` pinned by digest hash, and multi-stage build to exclude all build tools from the final image.

---

### Q10: Walk me through your multi-stage Dockerfile. Why two stages?

**A:** Stage 1 (builder) installs build dependencies (`gcc`, `libpq-dev`) and `pip install`s packages to an isolated prefix. Stage 2 (runtime) starts from a clean slim image, copies only the compiled Python packages from stage 1, and copies the application code. Build tools, pip, apt caches, and `.git` history never exist in the final image. The runtime image runs as a non-root user (UID 10001), uses a read-only-compatible entrypoint, and includes a health check. Attack surface drops from hundreds of MB to just the runtime libraries.

---

### Q11: What does your CI/CD pipeline scan for, and at what stages?

**A:**

| Stage | Tool | What It Catches |
|---|---|---|
| Pre-commit | `gitleaks` | Secrets/credentials in code |
| PR / Static Analysis | `hadolint` | Dockerfile anti-patterns (USER root, unpinned tags) |
| PR / Dependency Audit | `pip-audit` | Known CVEs in Python dependencies |
| Post-build | `trivy` | OS-level + app-level CVEs in built image (build fails on CRITICAL/HIGH) |
| Post-push (continuous) | GCP Container Analysis | Continuous scanning of stored images for new CVEs |
| Pre-deploy | Binary Authorization | Ensures image has required attestation (was scanned + signed) |
| Runtime | GKE Security Posture Dashboard | Detects running containers with newly discovered CVEs |

Each layer catches different classes of issues — no single gate is sufficient.

---

### Q12: How does Binary Authorization work and what's the break-glass process?

**A:** Binary Authorization is a GKE admission controller. Before allowing pod creation, it checks that the image has attestations signed by specified attestors using Cloud KMS keys. My policy requires two attestations: (1) the CI pipeline built and signed it, and (2) vulnerability scanning confirmed zero CRITICAL/HIGH CVEs.

**Break-glass:** An on-call SRE creates a special attestation with a separate key and annotates the pod. This triggers a PagerDuty alert, creates a JIRA ticket automatically, requires two-person authorization, and the bypassed image must go through the normal pipeline within 48 hours or be rolled back.

#### Deep Dive: How PagerDuty Alerts and JIRA Tickets Are Created Automatically

Yes, this requires custom code — specifically a **Cloud Function** triggered by a **Cloud Audit Log → Pub/Sub** pipeline. The chain is:

```
Break-glass attestation created
  → Cloud Audit Log entry written (automatic by GCP)
  → Log Router sink matches the entry and publishes to Pub/Sub topic
  → Pub/Sub triggers a Cloud Function
  → Cloud Function calls PagerDuty Events API + JIRA REST API
```

**Step 1: Log Router Sink (Terraform)**

This routes any Binary Authorization break-glass event to a Pub/Sub topic:

```hcl
# pubsub.tf
resource "google_pubsub_topic" "break_glass_events" {
  name    = "break-glass-events"
  project = var.project_id
}

# logging_sink.tf
resource "google_logging_project_sink" "break_glass_sink" {
  name        = "break-glass-audit-sink"
  project     = var.project_id
  destination = "pubsub.googleapis.com/${google_pubsub_topic.break_glass_events.id}"

  # Match only break-glass attestation creation events
  filter = <<-EOT
    resource.type="audited_resource"
    AND protoPayload.serviceName="binaryauthorization.googleapis.com"
    AND protoPayload.methodName="google.cloud.binaryauthorization.v1.BinauthzManagementService.CreateAttestation"
    AND protoPayload.request.attestation.attestorName:"break-glass-attestor"
  EOT

  unique_writer_identity = true
}

# Grant the sink's service account permission to publish
resource "google_pubsub_topic_iam_member" "sink_publisher" {
  project = var.project_id
  topic   = google_pubsub_topic.break_glass_events.name
  role    = "roles/pubsub.publisher"
  member  = google_logging_project_sink.break_glass_sink.writer_identity
}
```

**Step 2: Cloud Function (Python)**

This is the actual code that fires when a break-glass event is detected:

```python
# break_glass_notifier/main.py

import base64
import json
import os
from datetime import datetime

import requests
from google.cloud import secretmanager


def get_secret(secret_id: str) -> str:
    """Retrieve a secret from GCP Secret Manager."""
    client = secretmanager.SecretManagerServiceClient()
    name = f"projects/{os.environ['GCP_PROJECT']}/secrets/{secret_id}/versions/latest"
    response = client.access_secret_version(request={"name": name})
    return response.payload.data.decode("utf-8")


def create_pagerduty_alert(event_details: dict) -> dict:
    """
    Create a PagerDuty incident via the Events API v2.
    https://developer.pagerduty.com/api-reference/events-api-v2
    """
    routing_key = get_secret("pagerduty-break-glass-routing-key")

    payload = {
        "routing_key": routing_key,
        "event_action": "trigger",
        "dedup_key": f"break-glass-{event_details['timestamp']}",
        "payload": {
            "summary": (
                f"BREAK-GLASS: Binary Authorization bypass by "
                f"{event_details['actor']} on image "
                f"{event_details['image_digest']}"
            ),
            "severity": "critical",
            "source": "gcp-binary-authorization",
            "timestamp": event_details["timestamp"],
            "component": "break-glass-attestor",
            "group": "security-incidents",
            "custom_details": {
                "actor": event_details["actor"],
                "image_digest": event_details["image_digest"],
                "attestor": event_details["attestor"],
                "project": event_details["project"],
                "action_required": (
                    "Image must pass normal CI/CD pipeline within 48 hours "
                    "or be rolled back. Review audit logs for justification."
                ),
            },
        },
    }

    resp = requests.post(
        "https://events.pagerduty.com/v2/enqueue",
        json=payload,
        timeout=10,
    )
    resp.raise_for_status()
    return resp.json()


def create_jira_ticket(event_details: dict) -> dict:
    """
    Create a JIRA ticket via the REST API v3.
    https://developer.atlassian.com/cloud/jira/platform/rest/v3/
    """
    jira_url = os.environ["JIRA_BASE_URL"]  # e.g. https://company.atlassian.net
    jira_email = get_secret("jira-service-account-email")
    jira_token = get_secret("jira-api-token")

    payload = {
        "fields": {
            "project": {"key": os.environ.get("JIRA_PROJECT_KEY", "SEC")},
            "issuetype": {"name": "Incident"},
            "summary": (
                f"[BREAK-GLASS] Binary Auth bypass — "
                f"{event_details['image_digest'][:30]}..."
            ),
            "description": {
                "type": "doc",
                "version": 1,
                "content": [
                    {
                        "type": "paragraph",
                        "content": [
                            {
                                "type": "text",
                                "text": (
                                    f"A break-glass Binary Authorization bypass "
                                    f"was performed.\n\n"
                                    f"Actor: {event_details['actor']}\n"
                                    f"Image: {event_details['image_digest']}\n"
                                    f"Attestor: {event_details['attestor']}\n"
                                    f"Time: {event_details['timestamp']}\n"
                                    f"Project: {event_details['project']}\n\n"
                                    f"ACTION REQUIRED:\n"
                                    f"1. Verify the bypass was justified\n"
                                    f"2. Ensure the image passes the normal "
                                    f"CI/CD pipeline within 48 hours\n"
                                    f"3. If not resolved, roll back the "
                                    f"deployment\n"
                                    f"4. Attach incident justification to "
                                    f"this ticket"
                                ),
                            }
                        ],
                    }
                ],
            },
            "priority": {"name": "Highest"},
            "labels": ["break-glass", "binary-authorization", "security-incident"],
            # Auto-assign to the security team lead
            "assignee": {"accountId": os.environ.get("JIRA_SECURITY_LEAD_ID", "")},
            # Set a 48-hour due date
            "duedate": (
                datetime.utcnow().replace(hour=0, minute=0, second=0)
                .__add__(__import__("datetime").timedelta(days=2))
                .strftime("%Y-%m-%d")
            ),
        }
    }

    resp = requests.post(
        f"{jira_url}/rest/api/3/issue",
        json=payload,
        auth=(jira_email, jira_token),
        headers={"Content-Type": "application/json"},
        timeout=10,
    )
    resp.raise_for_status()
    return resp.json()


def handle_break_glass_event(event: dict, context) -> None:
    """
    Cloud Function entrypoint. Triggered by Pub/Sub message
    from the Cloud Audit Log sink.
    """
    # Decode the Pub/Sub message (base64-encoded audit log entry)
    pubsub_data = base64.b64decode(event["data"]).decode("utf-8")
    log_entry = json.loads(pubsub_data)

    # Extract details from the audit log
    proto_payload = log_entry.get("protoPayload", {})
    event_details = {
        "actor": proto_payload.get("authenticationInfo", {}).get(
            "principalEmail", "unknown"
        ),
        "image_digest": proto_payload.get("request", {})
        .get("attestation", {})
        .get("resourceUri", "unknown"),
        "attestor": proto_payload.get("request", {}).get("attestorName", "unknown"),
        "project": log_entry.get("resource", {})
        .get("labels", {})
        .get("project_id", "unknown"),
        "timestamp": log_entry.get("timestamp", datetime.utcnow().isoformat()),
    }

    print(f"Break-glass event detected: {json.dumps(event_details)}")

    # Fire both notifications
    try:
        pd_result = create_pagerduty_alert(event_details)
        print(f"PagerDuty alert created: {pd_result}")
    except Exception as e:
        # Log but don't fail — still need to create the JIRA ticket
        print(f"ERROR creating PagerDuty alert: {e}")

    try:
        jira_result = create_jira_ticket(event_details)
        print(f"JIRA ticket created: {jira_result.get('key', 'unknown')}")
    except Exception as e:
        print(f"ERROR creating JIRA ticket: {e}")
```

**Step 3: Cloud Function Deployment (Terraform)**

```hcl
# cloud_function.tf
resource "google_cloudfunctions2_function" "break_glass_notifier" {
  name     = "break-glass-notifier"
  location = var.region
  project  = var.project_id

  build_config {
    runtime     = "python312"
    entry_point = "handle_break_glass_event"
    source {
      storage_source {
        bucket = google_storage_bucket.cloud_functions_source.name
        object = google_storage_bucket_object.break_glass_source.name
      }
    }
  }

  service_config {
    max_instance_count = 3
    available_memory   = "256Mi"
    timeout_seconds    = 30

    environment_variables = {
      GCP_PROJECT             = var.project_id
      JIRA_BASE_URL           = "https://company.atlassian.net"
      JIRA_PROJECT_KEY        = "SEC"
      JIRA_SECURITY_LEAD_ID   = var.security_lead_jira_id
    }

    # Least-privilege SA — only needs Secret Manager access
    service_account_email = google_service_account.break_glass_notifier_sa.email
  }

  event_trigger {
    trigger_region = var.region
    event_type     = "google.cloud.pubsub.topic.v1.messagePublished"
    pubsub_topic   = google_pubsub_topic.break_glass_events.id
    retry_policy   = "RETRY_POLICY_RETRY"  # Ensure delivery
  }
}

# Dedicated SA with only the permissions it needs
resource "google_service_account" "break_glass_notifier_sa" {
  account_id   = "break-glass-notifier"
  display_name = "Break Glass Notifier Cloud Function"
  project      = var.project_id
}

resource "google_secret_manager_secret_iam_member" "notifier_secret_access" {
  for_each = toset([
    "pagerduty-break-glass-routing-key",
    "jira-service-account-email",
    "jira-api-token",
  ])

  project   = var.project_id
  secret_id = each.value
  role      = "roles/secretmanager.secretAccessor"
  member    = "serviceAccount:${google_service_account.break_glass_notifier_sa.email}"
}
```

**Why this approach vs. alternatives:**

| Approach | Pros | Cons |
|---|---|---|
| **Cloud Function + Pub/Sub** (chosen) | Serverless, auto-scales, retries on failure, decoupled from the attestation flow | Slight latency (~1-5s) from log → alert |
| Cloud Monitoring alert policy | Simpler setup | Can't create JIRA tickets, limited payload customization |
| Inline in a wrapper script | Synchronous — alert fires before SRE proceeds | Couples alerting to the CLI workflow; if SRE uses `gcloud` directly, alerts are skipped |
| Eventarc (direct audit log trigger) | Eliminates the Pub/Sub sink step | Less flexible filtering; Pub/Sub gives you dead-letter queues for reliability |

The Cloud Function approach is the most robust because it's **decoupled** — no matter *how* the break-glass attestation is created (gcloud CLI, Terraform, API call, CI pipeline), the audit log is always written, and the function always fires.

---

## GKE Multi-Tenancy

### Q13: How do you prevent one team from accessing another team's resources in a shared GKE cluster?

**A:** Defense in depth across multiple layers:

1. **Namespace isolation** — one namespace per team
2. **RBAC** — RoleBindings scoped per-namespace using built-in `admin`/`edit`/`view` ClusterRoles, never cluster-wide
3. **NetworkPolicy** — deny-all ingress by default, only allow same-namespace traffic
4. **Workload Identity** — each team's pods get a GCP SA bound at the resource level (their bucket, their Cloud SQL, their secrets). No project-wide roles
5. **PodSecurity `restricted`** — prevents running as root, host namespaces, or hostPath mounts
6. **ResourceQuota** — caps CPU, memory, and pod count per namespace
7. **Binary Authorization** — only signed images can run

---

### Q14: How do you prevent namespace-level privilege escalation?

**A:** Multiple controls:

- RBAC denies `escalate` and `bind` verbs so tenant admins can't grant `cluster-admin`
- PodSecurity Standards prevent container escape vectors (no root, no host namespaces, no hostPath)
- `automountServiceAccountToken: false` prevents stolen K8s SA tokens from being used for API server escalation
- Binary Authorization blocks deploying privilege escalation tools
- GKE Sandbox (gVisor) adds a user-space kernel as an extra barrier

---

### Q15: Why did you use Terraform instead of gcloud commands?

**A:** gcloud commands should not be run manually in production. Infrastructure must be tracked, versioned, and auditable. Terraform provides:

1. Version-controlled infrastructure-as-code
2. `for_each` over a teams map so adding a team is just adding a map entry (DRY)
3. Plan/apply workflow for change review
4. State tracking for drift detection
5. Ability to recreate any portion of infrastructure to improve MTTR

It's essential for SOC 2 compliance (CC8.1 — manage changes to infrastructure).

---

### Q16: Describe the three isolation break-out attack scenarios and their defenses.

**A:**

1. **Container escape via kernel exploit** — attacker exploits a kernel CVE from inside a container. **Defense:** GKE Sandbox (gVisor) interposes a user-space kernel, PodSecurity prevents privileged mode, Shielded Nodes detect tampering, node auto-upgrade patches kernels.

2. **K8s API abuse via stolen SA token** — attacker probes RBAC for misconfigs. **Defense:** `automountServiceAccountToken: false`, scoped RBAC, audit logging, authorized networks restrict who can reach the API server.

3. **Cross-tenant network lateral movement** — attacker scans the pod CIDR to find other teams' services. **Defense:** deny-all NetworkPolicy, Dataplane V2 (eBPF-based enforcement), dedicated node pools with taints, mTLS via Cloud Service Mesh.

---

## Incident Response & Prioritization

### Q17: You receive 4 security alerts at 6 AM. How do you prioritize them?

**A:** I use a "fire closest to customer data" framework evaluating likelihood of exploitation, blast radius, and data sensitivity:

| Priority | Alert | Rationale |
|---|---|---|
| **1** | Unauthenticated Snowflake proxy exposing PII | Actively exploitable, zero barriers, entire customer dataset at risk, regulatory clock starts immediately |
| **2** | AWS admin keys on public GitHub | Near-certain exploitation (bots scrape in minutes), full account compromise, but non-customer-facing |
| **3** | Log4Shell on internal admin dashboard | CVSS 10 RCE but behind VPN + auth, so reachability is limited |
| **4** | Workload Identity disabled | Configuration weakness requiring prior pod compromise, plan and fix within 48h |

---

### Q18: What's the first thing you do for the Snowflake proxy alert?

**A:** Block the endpoint immediately — WAF rule, kill the pod, or Snowflake network policy restricting to internal-only. Then revoke the proxy's Snowflake credentials (they may have been extracted). Preserve evidence before remediation: export load balancer access logs, Snowflake `QUERY_HISTORY`, snapshot the container. Scope the exposure: what role does the proxy use, what tables can it access, are there unusual queries or large result sets? Notify incident commander and legal — if PII was accessed, breach notification deadlines start now (72 hours for GDPR).

---

### Q19: The AWS key commit has 15 stars and 3 forks. Why can't you just delete the commit?

**A:** The 3 forks already have the keys — those are beyond your control. Deleting the file leaves it in git history (it's recoverable). Even using `git filter-branch` or BFG Repo Cleaner to purge history, the forks still have it. The keys MUST be rotated regardless of whether you clean up the repo. Also, key scraping bots typically exploit within minutes — after 2 hours with visible stars/forks, you should assume the keys have already been used. First action: disable the keys in IAM, then check CloudTrail for unauthorized activity.

---

## OAuth 2.0 Security

### Q20: What are the three vulnerabilities in the proposed OAuth design?

**A:**

1. **Missing PKCE** (CRITICAL) — no `code_challenge`/`code_verifier`, so intercepted authorization codes can be replayed. With 100+ partner redirect URIs, the attack surface is enormous.
2. **Non-expiring refresh tokens with no rotation** (CRITICAL) — 30-day access tokens and never-expiring refresh tokens mean a stolen token grants permanent access to customer PII.
3. **Plaintext token storage** (HIGH) — tokens stored as `VARCHAR(255)` in Cloud SQL. Any DB breach (SQL injection, compromised SA, backup theft) immediately compromises every partner and user simultaneously.

---

### Q21: Explain PKCE and why it prevents authorization code interception.

**A:** The client generates a random `code_verifier` and sends `code_challenge = BASE64URL(SHA256(code_verifier))` with the authorization request. The server stores the challenge. At token exchange, the client presents the original `code_verifier`. The server recomputes the hash and compares.

An attacker who intercepts the authorization code in transit doesn't know the `code_verifier`, so they can't redeem the code. It's a cryptographic binding between the entity that initiated the request and the entity that redeems it. OAuth 2.1 mandates PKCE for all flows, including confidential clients.

---

### Q22: How does refresh token rotation detect theft?

**A:** Every refresh token belongs to a `token_family_id`. When a token is used, it's marked as used and a new one is issued in the same family. If a previously-used token is presented again, it means either the legitimate client or an attacker has a stale token — in either case, theft has occurred. The server revokes the entire token family (all tokens from that grant), forcing the user to re-authorize. This limits the window of exploitation to a single refresh interval.

---

### Q23: Why not just rely on Cloud SQL's encryption at rest for token storage?

**A:** Cloud SQL's transparent disk encryption (TDE) protects against physical disk theft but NOT against application-level access. SQL injection, a compromised Cloud Run service account, a database admin, or a leaked backup all bypass TDE and expose plaintext tokens. Application-level encryption with Cloud KMS means the database stores only ciphertext — even with full DB access, you can't decrypt tokens without KMS permissions. I use AES-256-GCM for encryption and a separate SHA-256 hash for token lookup, so the raw token never exists in the database.

---

### Q24: How do you handle token revocation if access tokens are JWTs?

**A:** JWTs are self-contained and can't be "invalidated" at the authorization server — any resource server with the public key can validate them. The solution is a lightweight revocation list: when a token needs to be revoked, its `jti` (unique token ID) is added to a Redis blocklist (Memorystore) with a TTL matching the token's remaining lifetime (max 15 minutes). Resource servers check the blocklist on each request. Since access tokens are only 15 minutes, the blocklist stays small. For refresh tokens, revocation is immediate in Cloud SQL by setting `revoked_at`.

---

## Cross-Cutting / Behavioral

### Q25: You mentioned choosing Terraform `for_each` for multi-tenancy. How would you onboard a sixth team?

**A:** Add one entry to the `teams` variable map with the team name, cost center, SQL tier, and bucket location. `terraform plan` will show exactly what resources will be created (namespace, SA, Cloud SQL instance, GCS bucket, Secret Manager secret, log sink, RBAC bindings). `terraform apply` creates everything consistently. No manual steps, no missed resources. This is the advantage of DRY infrastructure — the pattern is defined once and stamped for each team.

---

### Q26: How would you explain your incident response prioritization to a non-technical executive?

**A:** "We have four problems. I'm treating them in order of how close they are to customer data. The first is an open door to our customer database — I'm slamming it shut right now. The second is a leaked key to our infrastructure — I'm changing the locks. The third is a known weakness in an internal tool behind two locked doors — I'm patching it within an hour. The fourth is a configuration weakness that only matters if someone is already inside — we'll fix it this week. I'll brief legal on the first two within 30 minutes."

---

### Q27: A developer pushes back and says "PKCE is overkill for confidential clients since they already have a client_secret." How do you respond?

**A:** OAuth 2.0 Security BCP and the OAuth 2.1 draft mandate PKCE for ALL clients, including confidential ones. The `client_secret` authenticates the *client* but doesn't bind the authorization code to the specific session that requested it. PKCE closes the gap where the code is intercepted between the browser redirect and the token exchange — a gap the `client_secret` doesn't protect. Given that we're managing 100+ partner integrations with customer PII, defense-in-depth is not overkill; it's the minimum standard. The implementation cost is one hash per flow.
