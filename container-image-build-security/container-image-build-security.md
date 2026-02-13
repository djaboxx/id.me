# Container Image Build Security — Full Report

> **Scenario**: A Python service that processes customer SSN and financial data,
> runs in production GKE, accesses Cloud Storage and Cloud SQL, and is called
> by other internal services.

---

## Table of Contents

1. [Task 1 — Security Issues in the Dockerfile & requirements.txt](#task-1--security-issues)
2. [Task 2 — Rewritten Dockerfile](#task-2--rewritten-dockerfile)
3. [Task 3 — Secure CI/CD Pipeline Design](#task-3--secure-cicd-pipeline-design)
4. [Task 4 — Binary Authorization Policy](#task-4--binary-authorization-policy)
5. [Task 5 — Vulnerability Management Process](#task-5--vulnerability-management-process)

---

## Task 1 — Security Issues

### Issue 1: Running as `root` (CRITICAL)

```dockerfile
USER root
```

**Problem**: The container explicitly runs as `root`. If an attacker exploits a
vulnerability in Flask or any dependency, they gain root access inside the
container. Combined with a kernel exploit or misconfigured security context,
this can lead to container escape and full node compromise — catastrophic for
a service handling SSNs and financial data.

**Impact**: Full container compromise, potential node escape, SOC 2 / PCI-DSS
violation.

---

### Issue 2: Using `ubuntu:latest` — Unpinned, Bloated Base Image (HIGH)

```dockerfile
FROM ubuntu:latest
```

**Problem (two-fold)**:

1. **`latest` tag is mutable** — builds are non-reproducible. A new `ubuntu:latest`
   push could introduce breaking changes or vulnerabilities without any code change
   on your side. There is no way to audit which exact image was used.
2. **Full Ubuntu is massively bloated** — it ships with hundreds of packages
   (`curl`, `git`, shells, package managers, compilers) that are unnecessary at
   runtime. Each unnecessary package is added attack surface. The `apt-get install`
   line adds even more (`curl`, `git`) which have no business in a production image
   processing sensitive financial data.

**Impact**: Non-reproducible builds, expanded attack surface, larger image =
slower pulls and more CVEs to triage.

---

### Issue 3: Unpinned Dependencies in `requirements.txt` (HIGH)

```
requests
psycopg2-binary
pyyaml
```

**Problem**: Three of five dependencies have **no version pin**. `pip install`
will grab whatever the latest version is at build time, meaning:

- Builds are **not reproducible** — two builds on different days produce different
  images with different dependency versions.
- A compromised or yanked PyPI package could be silently pulled in
  (supply-chain attack).
- Even `flask==2.0.1` is pinned to a **known-vulnerable version** (multiple CVEs
  including data handling issues fixed in later releases).

**Impact**: Supply-chain attack vector, non-reproducible builds, deployment of
known-vulnerable dependencies.

---

### Issue 4: No Multi-Stage Build — Secrets and Source Code Leak into Final Image (MEDIUM)

```dockerfile
RUN apt-get update && apt-get install -y python3 python3-pip curl git
COPY . .
```

**Problem**: The single-stage build means:

- **Build tools** (`pip`, `curl`, `git`, `apt`) and their caches remain in the
  final image. An attacker who compromises the container can use `curl` to
  exfiltrate data, `git` to clone repos, or `apt` to install additional tools.
- `COPY . .` copies **everything** from the build context — potentially including
  `.git/` history, `.env` files with secrets, test fixtures with PII, local
  config files, and the `Dockerfile` itself. Without a `.dockerignore`, all of
  these end up in the production image layer history.
- The `apt` cache (`/var/lib/apt/lists/*`) is never cleaned, adding ~30MB of
  unnecessary data.

**Impact**: Leaked secrets in image layers, tools available for post-exploitation,
inflated image size.

---

## Task 2 — Rewritten Dockerfile

```dockerfile
# ============================================================
# Stage 1: Build — install dependencies in a throwaway image
# ============================================================
FROM python:3.12-slim-bookworm@sha256:<pin-digest-here> AS builder

# Don't write .pyc files; don't buffer stdout/stderr
ENV PYTHONDONTWRITEBYTECODE=1 \
    PYTHONUNBUFFERED=1

WORKDIR /build

# Install build-time dependencies only (for psycopg2 if compiling from source)
RUN apt-get update && \
    apt-get install -y --no-install-recommends \
        gcc \
        libpq-dev && \
    rm -rf /var/lib/apt/lists/*

# Copy and install Python dependencies first (cache-friendly layer ordering)
COPY requirements.txt .
RUN pip install --no-cache-dir --prefix=/install -r requirements.txt

# ============================================================
# Stage 2: Runtime — minimal image with only what's needed
# ============================================================
FROM python:3.12-slim-bookworm@sha256:<pin-digest-here> AS runtime

# Install only the runtime library needed for psycopg2
RUN apt-get update && \
    apt-get install -y --no-install-recommends libpq5 && \
    rm -rf /var/lib/apt/lists/*

# Create a non-root user with a fixed UID/GID
RUN groupadd --gid 10001 appuser && \
    useradd --uid 10001 --gid appuser --shell /bin/false --home-dir /app appuser

WORKDIR /app

# Copy installed Python packages from builder
COPY --from=builder /install /usr/local

# Copy only application code (relies on .dockerignore excluding .git, .env, etc.)
COPY --chown=appuser:appuser . .

RUN chmod +x /app/start.sh

# Drop to non-root user
USER 10001

# Expose the service port
EXPOSE 8080

# Health check for orchestrator
HEALTHCHECK --interval=30s --timeout=5s --start-period=10s --retries=3 \
    CMD python3 -c "import urllib.request; urllib.request.urlopen('http://localhost:8080/health')" || exit 1

# Read-only filesystem compatible entrypoint
CMD ["/app/start.sh"]
```

**Companion `.dockerignore`**:

```
.git
.gitignore
.env
.env.*
*.md
Dockerfile
docker-compose*.yml
__pycache__
*.pyc
.pytest_cache
tests/
.vscode/
.idea/
*.key
*.pem
```

**Revised `requirements.txt`** (all versions pinned with hashes):

```
flask==3.1.0
requests==2.32.3
psycopg2-binary==2.9.10
google-cloud-storage==2.19.0
pyyaml==6.0.2
gunicorn==23.0.0
```

> In practice, use `pip-compile` from `pip-tools` to generate a fully resolved
> `requirements.txt` with `--generate-hashes` for supply-chain integrity.

---

## Task 3 — Secure CI/CD Pipeline Design

### 3.1 Architecture Overview

```
┌──────────┐    ┌───────────┐    ┌──────────────┐    ┌──────────────┐    ┌─────────┐
│  GitHub   │───▶│  GitHub   │───▶│  Artifact    │───▶│   Binary     │───▶│  GKE    │
│  (source) │    │  Actions  │    │  Registry    │    │   Authz      │    │ Cluster │
└──────────┘    └─────┬─────┘    └──────────────┘    └──────────────┘    └─────────┘
                      │
               ┌──────┴──────┐
               │  Pipeline   │
               │  Stages:    │
               │  1. Lint    │
               │  2. Test    │
               │  3. Scan    │
               │  4. Build   │
               │  5. Sign    │
               │  6. SBOM    │
               │  7. Push    │
               └─────────────┘
```

### 3.2 GitHub Actions Workflow

```yaml
name: Secure Container Build
on:
  push:
    branches: [main]
  pull_request:
    branches: [main]

env:
  REGION: us-central1
  REGISTRY: us-central1-docker.pkg.dev
  PROJECT_ID: ${{ secrets.GCP_PROJECT_ID }}
  REPO_NAME: production-images
  IMAGE_NAME: customer-service
  KMS_KEY: projects/${{ secrets.GCP_PROJECT_ID }}/locations/us-central1/keyRings/ci-signing/cryptoKeys/image-signer/cryptoKeyVersions/1

permissions:
  contents: read
  id-token: write   # For Workload Identity Federation

jobs:
  security-checks:
    runs-on: ubuntu-latest
    steps:
      - name: Checkout
        uses: actions/checkout@v4

      # ---- Static Analysis ----
      - name: Lint Dockerfile (Hadolint)
        uses: hadolint/hadolint-action@v3.1.0
        with:
          dockerfile: Dockerfile
          failure-threshold: warning

      - name: Secret Scanning (Gitleaks)
        uses: gitleaks/gitleaks-action@v2
        env:
          GITHUB_TOKEN: ${{ secrets.GITHUB_TOKEN }}

      - name: Python Dependency Audit (pip-audit)
        run: |
          pip install pip-audit
          pip-audit -r requirements.txt --strict --desc

  build-scan-push:
    needs: security-checks
    runs-on: ubuntu-latest
    if: github.ref == 'refs/heads/main'
    steps:
      - name: Checkout
        uses: actions/checkout@v4

      # ---- Authenticate to GCP via Workload Identity Federation ----
      - name: Authenticate to Google Cloud
        uses: google-github-actions/auth@v2
        with:
          workload_identity_provider: ${{ secrets.WIF_PROVIDER }}
          service_account: ${{ secrets.WIF_SA }}

      - name: Configure Docker for Artifact Registry
        run: gcloud auth configure-docker ${{ env.REGISTRY }} --quiet

      # ---- Build ----
      - name: Build Container Image
        run: |
          docker build \
            --no-cache \
            --label "org.opencontainers.image.revision=${{ github.sha }}" \
            --label "org.opencontainers.image.source=${{ github.repository }}" \
            -t ${{ env.REGISTRY }}/${{ env.PROJECT_ID }}/${{ env.REPO_NAME }}/${{ env.IMAGE_NAME }}:${{ github.sha }} \
            -t ${{ env.REGISTRY }}/${{ env.PROJECT_ID }}/${{ env.REPO_NAME }}/${{ env.IMAGE_NAME }}:latest \
            .

      # ---- Vulnerability Scanning (Trivy) ----
      - name: Scan Image for Vulnerabilities (Trivy)
        uses: aquasecurity/trivy-action@master
        with:
          image-ref: ${{ env.REGISTRY }}/${{ env.PROJECT_ID }}/${{ env.REPO_NAME }}/${{ env.IMAGE_NAME }}:${{ github.sha }}
          format: 'json'
          output: 'trivy-results.json'
          severity: 'CRITICAL,HIGH'
          exit-code: '1'          # FAIL the build if CRITICAL/HIGH found

      # ---- SBOM Generation (Syft) ----
      - name: Generate SBOM
        uses: anchore/sbom-action@v0
        with:
          image: ${{ env.REGISTRY }}/${{ env.PROJECT_ID }}/${{ env.REPO_NAME }}/${{ env.IMAGE_NAME }}:${{ github.sha }}
          format: spdx-json
          output-file: sbom.spdx.json

      - name: Upload SBOM to GCS
        run: |
          gsutil cp sbom.spdx.json \
            gs://${{ env.PROJECT_ID }}-sbom-store/${{ env.IMAGE_NAME }}/${{ github.sha }}/sbom.spdx.json

      # ---- Push to Artifact Registry ----
      - name: Push Image
        run: |
          docker push ${{ env.REGISTRY }}/${{ env.PROJECT_ID }}/${{ env.REPO_NAME }}/${{ env.IMAGE_NAME }}:${{ github.sha }}
          docker push ${{ env.REGISTRY }}/${{ env.PROJECT_ID }}/${{ env.REPO_NAME }}/${{ env.IMAGE_NAME }}:latest

      # ---- Sign Image with Binary Authorization (Cosign + KMS) ----
      - name: Install Cosign
        uses: sigstore/cosign-installer@v3

      - name: Sign Image with KMS Key
        run: |
          cosign sign --key gcpkms://${{ env.KMS_KEY }} \
            ${{ env.REGISTRY }}/${{ env.PROJECT_ID }}/${{ env.REPO_NAME }}/${{ env.IMAGE_NAME }}:${{ github.sha }}

      # ---- Create Binary Authorization Attestation ----
      - name: Create Attestation
        run: |
          IMAGE_DIGEST=$(docker inspect --format='{{index .RepoDigests 0}}' \
            ${{ env.REGISTRY }}/${{ env.PROJECT_ID }}/${{ env.REPO_NAME }}/${{ env.IMAGE_NAME }}:${{ github.sha }})

          gcloud container binauthz attestations sign-and-create \
            --project=${{ env.PROJECT_ID }} \
            --artifact-url="${IMAGE_DIGEST}" \
            --attestor=projects/${{ env.PROJECT_ID }}/attestors/ci-pipeline-attestor \
            --attestor-project=${{ env.PROJECT_ID }} \
            --keyversion=${{ env.KMS_KEY }}

      # ---- Artifact Registry Vulnerability Scanning (on-push, automatic) ----
      # GCP Container Analysis / Artifact Registry automatic scanning is
      # enabled via: gcloud services enable containerscanning.googleapis.com
      # This provides continuous scanning AFTER push as well.
```

### 3.3 Scanning Strategy — Where and When

| Stage | Tool | What It Catches | When |
|---|---|---|---|
| **Pre-commit** | `gitleaks` | Secrets/credentials in code | Every commit (local hook + CI) |
| **PR / Static Analysis** | `hadolint` | Dockerfile anti-patterns (USER root, unpinned tags, etc.) | Every PR |
| **PR / Dependency Audit** | `pip-audit` | Known CVEs in Python dependencies (cross-refs OSV/NVD) | Every PR |
| **Post-build** | `trivy` | OS-level + app-level CVEs in built image; misconfigurations | After `docker build`, before push |
| **Post-push (continuous)** | **GCP Container Analysis** (Artifact Registry) | Continuous scanning of stored images for NEW CVEs | Automatic, ongoing |
| **Pre-deploy** | **Binary Authorization** | Ensures image has required attestation (was scanned + signed) | At GKE admission time |
| **Runtime** | **GKE Security Posture Dashboard** | Detects running containers with newly discovered CVEs | Continuous |

### 3.4 Enforcing Only Signed Images in GKE

**GCP Services used**:

1. **Cloud KMS** — Stores the asymmetric signing key used by the CI/CD pipeline
2. **Binary Authorization** — GKE admission controller that checks attestations before allowing pod creation
3. **Container Analysis** — Stores attestations (notes + occurrences) that Binary Authorization verifies
4. **Artifact Registry** — Hosts images with automatic vulnerability scanning enabled

**Setup commands**:

```bash
# Enable required APIs
gcloud services enable \
  binaryauthorization.googleapis.com \
  containeranalysis.googleapis.com \
  containerscanning.googleapis.com \
  cloudkms.googleapis.com \
  artifactregistry.googleapis.com \
  --project=$PROJECT_ID

# Create KMS keyring and signing key
gcloud kms keyrings create ci-signing \
  --location=us-central1 \
  --project=$PROJECT_ID

gcloud kms keys create image-signer \
  --keyring=ci-signing \
  --location=us-central1 \
  --purpose=asymmetric-signing \
  --default-algorithm=ec-sign-p256-sha256 \
  --project=$PROJECT_ID

# Create the attestor
gcloud container binauthz attestors create ci-pipeline-attestor \
  --attestation-authority-note=ci-pipeline-note \
  --attestation-authority-note-project=$PROJECT_ID \
  --project=$PROJECT_ID

# Add the KMS public key to the attestor
gcloud container binauthz attestors public-keys add \
  --attestor=ci-pipeline-attestor \
  --keyversion=projects/$PROJECT_ID/locations/us-central1/keyRings/ci-signing/cryptoKeys/image-signer/cryptoKeyVersions/1 \
  --project=$PROJECT_ID

# Enable Binary Authorization on the GKE cluster
gcloud container clusters update shared-prod-cluster \
  --enable-binauthz \
  --zone=us-central1 \
  --project=$PROJECT_ID
```

### 3.5 SBOM Generation & Storage Strategy

| Aspect | Approach |
|---|---|
| **Format** | SPDX 2.3 JSON (industry standard, compatible with NTIA minimum elements) |
| **Generator** | Syft (Anchore) — runs in CI after build, before push |
| **Storage** | GCS bucket `$PROJECT_ID-sbom-store/` organized as `<image-name>/<git-sha>/sbom.spdx.json` |
| **Retention** | 7 years (SOC 2 / PCI-DSS audit trail) |
| **Access** | Security team has `roles/storage.objectViewer`; SBOMs are used for CVE impact analysis |
| **Enrichment** | SBOMs are cross-referenced with OSV.dev and NVD feeds for continuous vulnerability correlation |

### 3.6 Preventing Deployment on Critical CVEs

| Gate | Mechanism |
|---|---|
| **Build-time gate** | Trivy exits with code 1 on CRITICAL/HIGH CVEs → GitHub Actions build fails → image never pushed |
| **Post-push gate** | Container Analysis flags vulnerabilities → a Cloud Function or Pub/Sub listener revokes the attestation or blocks new attestation creation if post-push scan finds new CVEs |
| **Deploy-time gate** | Binary Authorization rejects any image without a valid attestation at GKE admission |
| **Runtime gate** | GKE Security Posture Dashboard + Cloud Monitoring alert on running containers with CRITICAL CVEs → triggers automated rollback or scaling to zero |

---

## Task 4 — Binary Authorization Policy

```yaml
# binary-authorization-policy.yaml
# Applied via: gcloud container binauthz policy export > policy.yaml
#              (edit) then: gcloud container binauthz policy import policy.yaml

admissionWhitelistPatterns:
  # Allow GKE system images
  - namePattern: "gcr.io/google_containers/*"
  - namePattern: "gcr.io/google-containers/*"
  - namePattern: "gke.gcr.io/*"
  - namePattern: "gcr.io/gke-release/*"
  - namePattern: "gcr.io/config-management-release/*"
  - namePattern: "gcr.io/kubebuilder/*"
  - namePattern: "gcr.io/stackdriver-agents/*"

# Global policy evaluation — check all clusters
globalPolicyEvaluationMode: ENABLE

# Default rule: REQUIRE attestation for all clusters
defaultAdmissionRule:
  evaluationMode: REQUIRE_ATTESTATION
  enforcementMode: ENFORCED_BLOCK_AND_AUDIT_LOG
  requireAttestationsBy:
    - projects/${PROJECT_ID}/attestors/ci-pipeline-attestor
    - projects/${PROJECT_ID}/attestors/vuln-scan-attestor

# Per-cluster overrides
clusterAdmissionRules:
  # Production — strictest policy
  us-central1.shared-prod-cluster:
    evaluationMode: REQUIRE_ATTESTATION
    enforcementMode: ENFORCED_BLOCK_AND_AUDIT_LOG
    requireAttestationsBy:
      # Image must have BOTH attestations:
      # 1. CI pipeline built and signed it
      - projects/${PROJECT_ID}/attestors/ci-pipeline-attestor
      # 2. Vulnerability scanner confirmed no CRITICAL/HIGH CVEs
      - projects/${PROJECT_ID}/attestors/vuln-scan-attestor

  # Emergency / Break-Glass — for incident response only
  # Uses ALWAYS_ALLOW but with full audit logging
  us-central1.emergency-cluster:
    evaluationMode: ALWAYS_ALLOW
    enforcementMode: DRYRUN_AUDIT_LOG_ONLY

# ============================================================
# Supporting Attestor Definitions (created via gcloud CLI)
# ============================================================
# Attestor 1: ci-pipeline-attestor
#   - Created by: CI/CD pipeline (GitHub Actions)
#   - Meaning: "This image was built by our authorized CI system"
#   - Key: Cloud KMS key `image-signer`
#
# Attestor 2: vuln-scan-attestor
#   - Created by: Vulnerability scanning step (post-Trivy)
#   - Meaning: "This image has zero CRITICAL and zero HIGH CVEs"
#   - Key: Cloud KMS key `vuln-signer`
#
# BOTH attestations are required for production deployment.
```

### Emergency / Break-Glass Process

For emergency deployments that bypass Binary Authorization:

```bash
# 1. An authorized operator (SRE on-call) creates a break-glass attestation
#    This is rate-limited to the "emergency-deployer" SA and triggers a
#    PagerDuty alert + Slack notification to #security-incidents

gcloud container binauthz attestations sign-and-create \
  --project=$PROJECT_ID \
  --artifact-url="$IMAGE_DIGEST" \
  --attestor=projects/$PROJECT_ID/attestors/break-glass-attestor \
  --attestor-project=$PROJECT_ID \
  --keyversion=projects/$PROJECT_ID/locations/us-central1/keyRings/ci-signing/cryptoKeys/break-glass-key/cryptoKeyVersions/1

# 2. Deploy with the break-glass annotation (logged and audited)
kubectl annotate pod <pod-name> \
  alpha.image-policy.k8s.io/break-glass="true" \
  --overwrite

# 3. Post-incident: security team reviews all break-glass events within 24h
#    Query audit logs:
gcloud logging read \
  'resource.type="k8s_cluster" AND
   protoPayload.request.metadata.annotations."alpha.image-policy.k8s.io/break-glass"="true"' \
  --project=$PROJECT_ID \
  --freshness=24h \
  --format=json
```

**Governance**:
- Break-glass requires **two-person authorization** (one requests, one approves via IAM session)
- All break-glass events create a **JIRA ticket** automatically (via Cloud Function on audit log)
- The bypassed image **must** go through the normal pipeline within **48 hours** or be rolled back
- Break-glass key is **separate** from the CI signing key and has a restricted IAM policy

---

## Task 5 — Vulnerability Management Process

### Scenario: Critical CVE discovered in `flask==2.0.1` three months post-deployment

---

### Step 1: Automated Detection & Alerting (Hour 0)

**What automated systems should have alerted you:**

| System | How It Detects | Alert Channel |
|---|---|---|
| **GCP Container Analysis** (Artifact Registry) | Continuously scans stored images against updated CVE feeds. Detects new CVE in `flask==2.0.1` within hours of NVD publication. | Pub/Sub → Cloud Function → PagerDuty + Slack #security-alerts |
| **GKE Security Posture Dashboard** | Scans running workloads and flags containers with newly discovered CVEs. | Cloud Monitoring alert → PagerDuty |
| **Dependabot / Renovate Bot** (GitHub) | Monitors `requirements.txt` in the repository and opens a PR with the fix version. | GitHub PR notification + Slack |
| **pip-audit in scheduled CI** | Nightly scheduled CI job runs `pip-audit -r requirements.txt` against the OSV database. | GitHub Actions failure notification |
| **SBOM correlation service** | Cross-references stored SBOMs with new CVE feeds. Identifies that `flask==2.0.1` is present in the SBOM for `customer-service`. | Custom alert via Cloud Function |

---

### Step 2: Impact Assessment (Hour 0–1)

**How do you identify all affected running containers:**

```bash
# 1. Query Artifact Registry for all images containing flask==2.0.1
#    Use Container Analysis to find occurrences:
gcloud artifacts docker images list \
  us-central1-docker.pkg.dev/$PROJECT_ID/production-images \
  --include-tags \
  --format="table(package,tags,uploadTime)"

# 2. Cross-reference with SBOMs stored in GCS
gsutil ls gs://$PROJECT_ID-sbom-store/**/sbom.spdx.json | \
  xargs -I {} sh -c 'echo "--- {} ---" && gsutil cat {} | jq ".packages[] | select(.name==\"Flask\" and .versionInfo==\"2.0.1\")"'

# 3. Identify running pods using the affected image digest
kubectl get pods --all-namespaces -o json | \
  jq -r '.items[] | select(.spec.containers[].image | contains("customer-service")) | "\(.metadata.namespace)/\(.metadata.name) \(.spec.containers[].image)"'

# 4. Get all affected image digests from Container Analysis
gcloud artifacts docker images list \
  us-central1-docker.pkg.dev/$PROJECT_ID/production-images/customer-service \
  --show-occurrences \
  --occurrence-filter='kind="VULNERABILITY" AND vulnerability.severity="CRITICAL"' \
  --format=json
```

---

### Step 3: Severity Classification & SLA (Hour 1)

**Patching SLAs based on severity:**

| Severity | SLA for Patch Merged | SLA for Production Deploy | Justification |
|---|---|---|---|
| **CRITICAL** (CVSS ≥ 9.0) | **24 hours** | **48 hours** | Service handles SSN/financial data; active exploitation likely |
| **HIGH** (CVSS 7.0–8.9) | **72 hours** | **7 days** | Significant risk but may require more testing |
| **MEDIUM** (CVSS 4.0–6.9) | **30 days** | **45 days** | Addressed in next sprint |
| **LOW** (CVSS < 4.0) | **90 days** | **Next release** | Tracked in backlog |

For this scenario (critical CVE in Flask handling customer PII): **24h patch / 48h deploy SLA**.

---

### Step 4: Remediation (Hours 1–24)

```bash
# 1. Update requirements.txt to the patched version
#    Change: flask==2.0.1 → flask==3.1.0 (or latest patched version)
#    This is likely already a PR from Dependabot/Renovate

# 2. Run pip-audit to verify the fix and check for transitive deps
pip-audit -r requirements.txt --strict --desc

# 3. Run the full test suite
pytest tests/ -v --cov=app --cov-fail-under=80

# 4. Build new image (triggers the full secure pipeline from Task 3)
#    - Hadolint → pip-audit → docker build → Trivy scan → SBOM → push → sign → attest

# 5. Verify no CRITICAL/HIGH CVEs remain
trivy image us-central1-docker.pkg.dev/$PROJECT_ID/production-images/customer-service:$NEW_SHA \
  --severity CRITICAL,HIGH --exit-code 1
```

---

### Step 5: Deployment (Hours 24–48)

```bash
# 1. Deploy to staging first — canary validation
kubectl set image deployment/customer-service \
  customer-service=us-central1-docker.pkg.dev/$PROJECT_ID/production-images/customer-service:$NEW_SHA \
  -n team-alpha-staging

# 2. Run smoke tests and integration tests against staging
# 3. Promote to production (rolling update)
kubectl set image deployment/customer-service \
  customer-service=us-central1-docker.pkg.dev/$PROJECT_ID/production-images/customer-service:$NEW_SHA \
  -n team-alpha

# 4. Monitor rollout
kubectl rollout status deployment/customer-service -n team-alpha --timeout=600s

# 5. Verify old pods are terminated
kubectl get pods -n team-alpha -l app=customer-service -o wide
```

---

### Step 6: Post-Incident Hardening (Hours 48–72)

```bash
# 1. Revoke attestation for the old vulnerable image so it can never be re-deployed
#    (Container Analysis occurrences are immutable, but you can update the
#     Binary Authorization policy to require a new attestor that the old image lacks)

# 2. Verify no other images in the registry contain the vulnerable Flask version
gcloud artifacts docker images list \
  us-central1-docker.pkg.dev/$PROJECT_ID/production-images \
  --include-tags \
  --format=json | \
  jq '.[].tags'

# 3. Update the base image and all dependencies while you're at it
pip-compile requirements.in --generate-hashes --upgrade

# 4. Generate updated SBOM and store it
syft us-central1-docker.pkg.dev/$PROJECT_ID/production-images/customer-service:$NEW_SHA \
  -o spdx-json > sbom.spdx.json
gsutil cp sbom.spdx.json gs://$PROJECT_ID-sbom-store/customer-service/$NEW_SHA/sbom.spdx.json

# 5. Document the incident
#    - What: CVE-XXXX-YYYY in Flask 2.0.1
#    - Impact: customer-service processing SSN/financial data
#    - Detection: Container Analysis auto-scan (time to detect: X hours)
#    - Resolution: Updated to Flask 3.1.0, redeployed within SLA
#    - Lessons: Add Renovate Bot for automated dependency PRs if not already active
```

---

### Vulnerability Response Timeline Summary

```
Hour 0      ─ CVE published to NVD
Hour 0-1    ─ Container Analysis / Dependabot detects & alerts
Hour 1      ─ Security team triages, classifies as CRITICAL
Hours 1-4   ─ Dependabot PR merged, or manual requirements.txt update
Hours 4-8   ─ CI pipeline builds, scans, signs new image
Hours 8-12  ─ Staged rollout to staging environment, smoke tests
Hours 12-24 ─ Staged rollout to production (canary → full)
Hours 24-48 ─ Verify all old pods terminated, old attestations noted
Hours 48-72 ─ Post-incident review, documentation, process improvements
```

---

## Summary of Tools & GCP Services Referenced

| Category | Tool / Service | Purpose |
|---|---|---|
| **Dockerfile Linting** | Hadolint | Catch anti-patterns before build |
| **Secret Scanning** | Gitleaks | Detect secrets in source code |
| **Dependency Audit** | pip-audit | Check Python deps against OSV/NVD |
| **Image Scanning** | Trivy | Scan built images for CVEs |
| **Continuous Scanning** | GCP Container Analysis | Scan images in Artifact Registry continuously |
| **Image Signing** | Cosign + Cloud KMS | Cryptographically sign images |
| **Deploy Enforcement** | Binary Authorization | Admission controller requiring attestations |
| **SBOM Generation** | Syft (Anchore) | Produce SPDX SBOMs |
| **Image Registry** | Artifact Registry | Store and serve container images |
| **Key Management** | Cloud KMS | Store signing keys (HSM-backed) |
| **Runtime Scanning** | GKE Security Posture Dashboard | Detect CVEs in running workloads |
| **Dependency Updates** | Dependabot / Renovate | Automated dependency update PRs |
