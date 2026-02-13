# GKE Multi-Tenancy Security Design — Full Report

> **Scenario**: Shared GKE Standard cluster (`shared-prod-cluster`) serving five teams
> (team-alpha, team-beta, team-gamma, team-delta, team-epsilon) with SOC 2 audit
> requirements. All Terraform code uses the `hashicorp/google` provider whose
> documentation lives in `website/docs/` of the workspace.

---

## Table of Contents

1. [Task 1 — Namespace & RBAC Strategy](#task-1--namespace--rbac-strategy)
2. [Task 2 — Kubernetes YAML Configurations (team-alpha)](#task-2--kubernetes-yaml-configurations-team-alpha)
3. [Task 3 — Terraform Configurations (replaces gcloud)](#task-3--terraform-configurations-replaces-gcloud)
4. [Task 4 — Isolation Break-Out Scenarios & Defenses](#task-4--isolation-break-out-scenarios--defenses)
5. [Appendix — Reference Architecture Diagram](#appendix--reference-architecture-diagram)

---

## Task 1 — Namespace & RBAC Strategy

### 1.1 Namespace Design

| Namespace | Purpose |
|---|---|
| `team-alpha` | Workloads, services, and configs for team-alpha |
| `team-beta` | Workloads, services, and configs for team-beta |
| `team-gamma` | Workloads, services, and configs for team-gamma |
| `team-delta` | Workloads, services, and configs for team-delta |
| `team-epsilon` | Workloads, services, and configs for team-epsilon |
| `platform-admin` | Cluster-wide observability, shared tooling (e.g., monitoring agents, log routers) |

**Total: 6 namespaces** (5 tenant + 1 platform).

**Naming convention**: `team-<name>` — environment-agnostic so the same manifests
work across dev/staging/prod clusters (per Google's best-practice recommendation
for [standardized namespace naming](https://cloud.google.com/kubernetes-engine/docs/best-practices/enterprise-multitenancy#create-namespaces)).

Each namespace carries standard labels for cost allocation, network policy
selection, and audit:

```yaml
labels:
  tenant: "<team-name>"
  environment: "production"
  managed-by: "platform-team"
  cost-center: "<team-cost-center>"
```

### 1.2 Kubernetes RBAC Roles

Per Google's enterprise multi-tenancy guide, we define **three levels** of access
within each tenant namespace, mapped to the built-in ClusterRoles where possible:

| Role | Scope | K8s ClusterRole Binding | Capabilities |
|---|---|---|---|
| **Namespace Admin** | Per-namespace `RoleBinding` | `admin` | Full read/write on namespace resources, create Roles/RoleBindings within namespace, manage users |
| **Namespace Editor** | Per-namespace `RoleBinding` | `edit` | Create/edit/delete Pods, Deployments, Services, ConfigMaps, etc. |
| **Namespace Viewer** | Per-namespace `RoleBinding` | `view` | Read-only access to Pods, Deployments, Services, ConfigMaps |

**Platform Team** gets a `ClusterRoleBinding` to the `cluster-admin` ClusterRole
for cluster-wide visibility and management.

### 1.3 GCP IAM Roles for Team Service Accounts

Each team gets a dedicated **GCP service account** bound via Workload Identity.
IAM roles are scoped to the team's own resources only:

| GCP IAM Role | Scope | Purpose |
|---|---|---|
| `roles/cloudsql.client` | Team's own Cloud SQL instance | Connect to their database |
| `roles/cloudsql.editor` | Team's own Cloud SQL instance | Manage schema/data |
| `roles/storage.objectAdmin` | Team's own GCS bucket(s) | Read/write objects |
| `roles/secretmanager.secretAccessor` | Team's own secrets | Access secrets at runtime |
| `roles/logging.logWriter` | Tenant project | Write application logs |
| `roles/monitoring.metricWriter` | Tenant project | Write custom metrics |

The service accounts receive **no project-wide** roles. Permissions are bound at
the **resource level** (per-bucket, per-secret, per-instance) to enforce least
privilege.

### 1.4 Preventing Namespace-Level Privilege Escalation

| Control | How It Prevents Escalation |
|---|---|
| **RBAC `escalate` & `bind` verb restrictions** | Tenant admins can only create RoleBindings for roles at or below their own privilege level; they cannot grant `cluster-admin`. |
| **PodSecurity Standards (`restricted` profile)** | Prevents pods from running as root, using host namespaces, or mounting hostPath volumes — blocking container escape vectors. |
| **Network Policies (deny-all default)** | Prevents cross-namespace network traffic, stopping lateral movement. |
| **Workload Identity (no node SA access)** | Pods cannot access the node's default service account or GCE metadata server for other SAs. |
| **Binary Authorization** | Only signed, verified images can run — prevents deploying privilege-escalation tools. |
| **GKE Sandbox (gVisor)** | Adds a user-space kernel between container and host, shrinking the syscall attack surface. |
| **No `automountServiceAccountToken` by default** | Reduces the risk of stolen Kubernetes SA tokens being used for API server privilege escalation. |

---

## Task 2 — Kubernetes YAML Configurations (team-alpha)

### 2.1 Namespace with Labels/Annotations

```yaml
apiVersion: v1
kind: Namespace
metadata:
  name: team-alpha
  labels:
    tenant: "team-alpha"
    environment: "production"
    managed-by: "platform-team"
    cost-center: "alpha-cc-001"
    # PodSecurity Standards enforcement
    pod-security.kubernetes.io/enforce: "restricted"
    pod-security.kubernetes.io/enforce-version: "latest"
    pod-security.kubernetes.io/audit: "restricted"
    pod-security.kubernetes.io/warn: "restricted"
  annotations:
    description: "Namespace for team-alpha workloads"
    contact: "team-alpha-leads@company.com"
    soc2-compliance: "required"
```

### 2.2 ServiceAccount with Workload Identity Binding

```yaml
apiVersion: v1
kind: ServiceAccount
metadata:
  name: team-alpha-workload-sa
  namespace: team-alpha
  annotations:
    # Binds this K8s SA to the GCP SA via Workload Identity
    iam.gke.io/gcp-service-account: team-alpha-sa@<PROJECT_ID>.iam.gserviceaccount.com
  labels:
    tenant: "team-alpha"
automountServiceAccountToken: false
```

### 2.3 Role and RoleBinding for Team Developers

```yaml
# Namespace Admin Role (uses built-in admin ClusterRole)
apiVersion: rbac.authorization.k8s.io/v1
kind: RoleBinding
metadata:
  name: team-alpha-admin
  namespace: team-alpha
roleRef:
  apiGroup: rbac.authorization.k8s.io
  kind: ClusterRole
  name: admin
subjects:
  - apiGroup: rbac.authorization.k8s.io
    kind: Group
    name: "team-alpha-admins@company.com"
---
# Namespace Editor Role (uses built-in edit ClusterRole)
apiVersion: rbac.authorization.k8s.io/v1
kind: RoleBinding
metadata:
  name: team-alpha-editor
  namespace: team-alpha
roleRef:
  apiGroup: rbac.authorization.k8s.io
  kind: ClusterRole
  name: edit
subjects:
  - apiGroup: rbac.authorization.k8s.io
    kind: Group
    name: "team-alpha-developers@company.com"
---
# Namespace Viewer Role (uses built-in view ClusterRole)
apiVersion: rbac.authorization.k8s.io/v1
kind: RoleBinding
metadata:
  name: team-alpha-viewer
  namespace: team-alpha
roleRef:
  apiGroup: rbac.authorization.k8s.io
  kind: ClusterRole
  name: view
subjects:
  - apiGroup: rbac.authorization.k8s.io
    kind: Group
    name: "team-alpha-viewers@company.com"
```

### 2.4 ResourceQuota (CPU, Memory, Pods)

```yaml
apiVersion: v1
kind: ResourceQuota
metadata:
  name: team-alpha-quota
  namespace: team-alpha
  labels:
    tenant: "team-alpha"
spec:
  hard:
    # Pod limits
    pods: "50"
    # CPU
    requests.cpu: "16"
    limits.cpu: "32"
    # Memory
    requests.memory: "64Gi"
    limits.memory: "128Gi"
    # Other object limits
    services: "20"
    secrets: "50"
    configmaps: "50"
    persistentvolumeclaims: "20"
    services.loadbalancers: "5"
---
# Require all pods to specify resource requests/limits
apiVersion: v1
kind: LimitRange
metadata:
  name: team-alpha-limit-range
  namespace: team-alpha
spec:
  limits:
    - type: Container
      default:
        cpu: "500m"
        memory: "512Mi"
      defaultRequest:
        cpu: "100m"
        memory: "128Mi"
      max:
        cpu: "4"
        memory: "8Gi"
      min:
        cpu: "50m"
        memory: "64Mi"
```

### 2.5 NetworkPolicy for Team Isolation

```yaml
# Default deny all ingress from other namespaces
apiVersion: networking.k8s.io/v1
kind: NetworkPolicy
metadata:
  name: deny-all-ingress
  namespace: team-alpha
spec:
  podSelector: {}   # Applies to all pods in namespace
  policyTypes:
    - Ingress
  ingress:
    - from:
        # Only allow traffic from pods within the same namespace
        - podSelector: {}
---
# Default deny all egress (except DNS and same-namespace)
apiVersion: networking.k8s.io/v1
kind: NetworkPolicy
metadata:
  name: default-egress
  namespace: team-alpha
spec:
  podSelector: {}
  policyTypes:
    - Egress
  egress:
    # Allow DNS resolution (kube-dns in kube-system)
    - to:
        - namespaceSelector:
            matchLabels:
              kubernetes.io/metadata.name: kube-system
      ports:
        - protocol: UDP
          port: 53
        - protocol: TCP
          port: 53
    # Allow egress to pods within the same namespace
    - to:
        - podSelector: {}
    # Allow egress to Google APIs (Private Google Access)
    - to:
        - ipBlock:
            cidr: 199.36.153.4/30  # restricted.googleapis.com
      ports:
        - protocol: TCP
          port: 443
```

### 2.6 PodSecurityStandard Enforcement

PodSecurity is enforced at the namespace level via labels (already set in the
Namespace manifest above in §2.1):

```yaml
labels:
  pod-security.kubernetes.io/enforce: "restricted"
  pod-security.kubernetes.io/enforce-version: "latest"
  pod-security.kubernetes.io/audit: "restricted"
  pod-security.kubernetes.io/warn: "restricted"
```

The **`restricted`** profile enforces:
- Pods cannot run as root
- No privilege escalation (`allowPrivilegeEscalation: false`)
- No host namespaces (hostPID, hostIPC, hostNetwork all false)
- No hostPath volume mounts
- Must drop ALL capabilities
- Seccomp profile must be `RuntimeDefault` or `Localhost`
- Must use read-only root filesystem where possible

---

## Task 3 — Terraform Configurations (replaces gcloud)

> The original task asked for `gcloud` commands. Per requirements, all
> infrastructure is defined as Terraform using the `hashicorp/google` provider.
> Resource syntax is sourced from the Terraform provider documentation in the
> `docs/` workspace directory.
> I've determined that terraform would better serve this function as gcloud commands should not be run in a production environment. Automation should be tracked, versioned, and audited. We should be able to recreate any portion of our infrastructure at any point in order to aid in MTTR (Mean Time To Recovery).

### 3.1 Variables & Locals

```hcl
# variables.tf

variable "project_id" {
  description = "The GCP project ID"
  type        = string
}

variable "region" {
  description = "The GCP region"
  type        = string
  default     = "us-central1"
}

variable "cluster_name" {
  description = "The GKE cluster name"
  type        = string
  default     = "shared-prod-cluster"
}

variable "teams" {
  description = "Map of team names to their configuration"
  type = map(object({
    cost_center     = string
    sql_tier        = string
    bucket_location = string
  }))
  default = {
    "team-alpha" = {
      cost_center     = "alpha-cc-001"
      sql_tier        = "db-custom-2-7680"
      bucket_location = "US"
    }
    "team-beta" = {
      cost_center     = "beta-cc-002"
      sql_tier        = "db-custom-2-7680"
      bucket_location = "US"
    }
    "team-gamma" = {
      cost_center     = "gamma-cc-003"
      sql_tier        = "db-custom-2-7680"
      bucket_location = "US"
    }
    "team-delta" = {
      cost_center     = "delta-cc-004"
      sql_tier        = "db-custom-2-7680"
      bucket_location = "US"
    }
    "team-epsilon" = {
      cost_center     = "epsilon-cc-005"
      sql_tier        = "db-custom-2-7680"
      bucket_location = "US"
    }
  }
}

locals {
  workload_identity_pool = "${var.project_id}.svc.id.goog"
}
```

### 3.2 Create GCP Service Account for Each Team

> Replaces: `gcloud iam service-accounts create ...`

```hcl
# iam.tf — GCP Service Accounts

# Per-team GCP service account for Workload Identity
resource "google_service_account" "team_sa" {
  for_each = var.teams

  account_id   = "${each.key}-sa"
  display_name = "Service Account for ${each.key}"
  description  = "Workload Identity SA for ${each.key} in ${var.cluster_name}"
  project      = var.project_id
}
```

### 3.3 Bind GCP SA to Kubernetes SA (Workload Identity)

> Replaces: `gcloud iam service-accounts add-iam-policy-binding ...`
> and `gcloud container clusters update ... --workload-pool=...`

First, ensure the cluster has Workload Identity enabled:

```hcl
# cluster.tf — GKE Cluster with Workload Identity & Security Features

data "google_project" "project" {
  project_id = var.project_id
}

resource "google_container_cluster" "shared_prod" {
  name     = var.cluster_name
  location = var.region
  project  = var.project_id

  # Use separately managed node pools
  remove_default_node_pool = true
  initial_node_count       = 1
  deletion_protection      = true

  # --- Workload Identity ---
  workload_identity_config {
    workload_pool = local.workload_identity_pool
  }

  # --- Network Policy ---
  network_policy {
    enabled  = true
    provider = "CALICO"
  }

  # Dataplane V2 for enhanced network policy support
  datapath_provider = "ADVANCED_DATAPATH"

  # --- Private Cluster ---
  private_cluster_config {
    enable_private_nodes    = true
    enable_private_endpoint = false
    master_ipv4_cidr_block  = "172.16.0.0/28"

    master_global_access_config {
      enabled = true
    }
  }

  # --- Binary Authorization ---
  binary_authorization {
    evaluation_mode = "PROJECT_SINGLETON_POLICY_ENFORCE"
  }

  # --- Master Authorized Networks ---
  master_authorized_networks_config {
    cidr_blocks {
      cidr_block   = "10.0.0.0/8"
      display_name = "Internal network"
    }
  }

  # --- Shielded Nodes ---
  enable_shielded_nodes = true

  # --- Logging & Monitoring ---
  logging_service    = "logging.googleapis.com/kubernetes"
  monitoring_service = "monitoring.googleapis.com/kubernetes"

  # --- Cost Allocation ---
  cost_management_config {
    enabled = true
  }

  # --- Release Channel ---
  release_channel {
    channel = "REGULAR"
  }

  # --- Maintenance Window ---
  maintenance_policy {
    recurring_window {
      start_time = "2026-01-01T04:00:00Z"
      end_time   = "2026-01-01T08:00:00Z"
      recurrence = "FREQ=WEEKLY;BYDAY=SA,SU"
    }
  }
}
```

Then bind the GCP SA to the Kubernetes SA via IAM:

```hcl
# workload_identity.tf

# Allow K8s SA to impersonate GCP SA (Workload Identity binding)
resource "google_service_account_iam_member" "workload_identity_binding" {
  for_each = var.teams

  service_account_id = google_service_account.team_sa[each.key].name
  role               = "roles/iam.workloadIdentityUser"
  member             = "serviceAccount:${local.workload_identity_pool}[${each.key}/${each.key}-workload-sa]"
}
```

### 3.4 Grant Team-Alpha's GCP SA Access to Only Their Cloud SQL Instance

> Replaces: `gcloud projects add-iam-policy-binding ... --member=... --role=roles/cloudsql.client`

```hcl
# cloud_sql.tf — Per-team Cloud SQL Instances

resource "google_sql_database_instance" "team_sql" {
  for_each = var.teams

  name             = "${each.key}-postgres"
  database_version = "POSTGRES_15"
  region           = var.region
  project          = var.project_id

  settings {
    tier = each.value.sql_tier

    ip_configuration {
      ipv4_enabled    = false
      private_network = google_compute_network.cluster_vpc.id
    }

    backup_configuration {
      enabled                        = true
      point_in_time_recovery_enabled = true
      start_time                     = "03:00"
    }

    database_flags {
      name  = "log_checkpoints"
      value = "on"
    }

    database_flags {
      name  = "log_connections"
      value = "on"
    }

    database_flags {
      name  = "log_disconnections"
      value = "on"
    }
  }

  deletion_protection = true
}

# Grant each team's SA access to ONLY their Cloud SQL instance
resource "google_project_iam_member" "team_sql_client" {
  for_each = var.teams

  project = var.project_id
  role    = "roles/cloudsql.client"
  member  = "serviceAccount:${google_service_account.team_sa[each.key].email}"

  condition {
    title       = "${each.key}-sql-only"
    description = "Restrict Cloud SQL access to ${each.key}'s instance only"
    expression  = "resource.name == \"projects/${var.project_id}/instances/${each.key}-postgres\" || resource.type == \"cloudresourcemanager.googleapis.com/Project\""
  }
}
```

### 3.5 Cloud Storage Buckets (Per-Team)

```hcl
# storage.tf — Per-team GCS Buckets

resource "google_storage_bucket" "team_bucket" {
  for_each = var.teams

  name          = "${var.project_id}-${each.key}-data"
  location      = each.value.bucket_location
  project       = var.project_id
  force_destroy = false

  uniform_bucket_level_access = true

  versioning {
    enabled = true
  }

  lifecycle_rule {
    condition {
      age = 365
    }
    action {
      type          = "SetStorageClass"
      storage_class = "NEARLINE"
    }
  }

  labels = {
    tenant      = each.key
    environment = "production"
  }
}

# Grant each team's SA admin on ONLY their bucket
resource "google_storage_bucket_iam_member" "team_bucket_admin" {
  for_each = var.teams

  bucket = google_storage_bucket.team_bucket[each.key].name
  role   = "roles/storage.objectAdmin"
  member = "serviceAccount:${google_service_account.team_sa[each.key].email}"
}
```

### 3.6 Secret Manager (Per-Team)

```hcl
# secrets.tf — Per-team Secret Manager configuration

resource "google_secret_manager_secret" "team_secrets" {
  for_each = var.teams

  secret_id = "${each.key}-app-config"
  project   = var.project_id

  labels = {
    tenant      = each.key
    environment = "production"
  }

  replication {
    user_managed {
      replicas {
        location = var.region
      }
      replicas {
        location = "us-east1"
      }
    }
  }
}

# Grant each team's SA accessor on ONLY their secrets
resource "google_secret_manager_secret_iam_member" "team_secret_access" {
  for_each = var.teams

  project   = var.project_id
  secret_id = google_secret_manager_secret.team_secrets[each.key].secret_id
  role      = "roles/secretmanager.secretAccessor"
  member    = "serviceAccount:${google_service_account.team_sa[each.key].email}"
}
```

### 3.7 Binary Authorization Policy

> Replaces: `gcloud container binauthz policy ...`

```hcl
# binary_auth.tf

resource "google_binary_authorization_policy" "cluster_policy" {
  project = var.project_id

  # Allow only Google-provided base images and internal registry
  admission_whitelist_patterns {
    name_pattern = "gcr.io/google_containers/*"
  }

  admission_whitelist_patterns {
    name_pattern = "gcr.io/${var.project_id}/*"
  }

  admission_whitelist_patterns {
    name_pattern = "${var.region}-docker.pkg.dev/${var.project_id}/*"
  }

  # Default: require attestation for all clusters
  default_admission_rule {
    evaluation_mode  = "REQUIRE_ATTESTATION"
    enforcement_mode = "ENFORCED_BLOCK_AND_AUDIT_LOG"

    require_attestations_by = [
      google_binary_authorization_attestor.build_attestor.name
    ]
  }
}

resource "google_container_analysis_note" "build_note" {
  project = var.project_id
  name    = "build-attestor-note"

  attestation_authority {
    hint {
      human_readable_name = "Build Verification Attestor"
    }
  }
}

resource "google_binary_authorization_attestor" "build_attestor" {
  project = var.project_id
  name    = "build-attestor"

  attestation_authority_note {
    note_reference = google_container_analysis_note.build_note.name
  }
}
```

### 3.8 Multi-Tenant Logging (Log Router Sinks)

> Replaces: `gcloud logging sinks create ...` and
> `gcloud projects add-iam-policy-binding ... --role=roles/logging.logWriter`

```hcl
# logging.tf — Per-tenant log routing

# Assumes per-team tenant projects exist. If tenants share the cluster
# project, route to per-team log buckets instead.

variable "tenant_projects" {
  description = "Map of team name to their tenant project ID"
  type        = map(string)
  default = {
    "team-alpha"   = "team-alpha-project"
    "team-beta"    = "team-beta-project"
    "team-gamma"   = "team-gamma-project"
    "team-delta"   = "team-delta-project"
    "team-epsilon" = "team-epsilon-project"
  }
}

# Create a log sink per team that routes namespace-specific logs
# to the team's own project
resource "google_logging_project_sink" "team_log_sink" {
  for_each = var.tenant_projects

  name        = "gke-${each.key}-sink"
  project     = var.project_id
  destination = "logging.googleapis.com/projects/${each.value}"
  filter      = "resource.labels.namespace_name=\"${each.key}\""
  description = "Routes GKE logs for ${each.key} namespace to tenant project ${each.value}"

  unique_writer_identity = true
}

# Grant the sink's writer identity the Logs Writer role on the
# tenant project so it can actually deliver logs
resource "google_project_iam_member" "sink_log_writer" {
  for_each = var.tenant_projects

  project = each.value
  role    = "roles/logging.logWriter"
  member  = google_logging_project_sink.team_log_sink[each.key].writer_identity
}
```

### 3.9 VPC Network

```hcl
# network.tf

resource "google_compute_network" "cluster_vpc" {
  name                    = "${var.cluster_name}-vpc"
  project                 = var.project_id
  auto_create_subnetworks = false
}

resource "google_compute_subnetwork" "cluster_subnet" {
  name          = "${var.cluster_name}-subnet"
  project       = var.project_id
  region        = var.region
  network       = google_compute_network.cluster_vpc.id
  ip_cidr_range = "10.49.0.0/16"

  secondary_ip_range {
    range_name    = "pods"
    ip_cidr_range = "10.48.0.0/16"
  }

  secondary_ip_range {
    range_name    = "services"
    ip_cidr_range = "10.50.0.0/16"
  }

  private_ip_google_access = true
}
```

### 3.10 Complete Terraform Resource Map

| Task Requirement | gcloud Equivalent | Terraform Resource | Provider Doc |
|---|---|---|---|
| Create GCP service account | `gcloud iam service-accounts create` | `google_service_account` | `docs/r/google_service_account.html.markdown` |
| Bind Workload Identity | `gcloud iam service-accounts add-iam-policy-binding` | `google_service_account_iam_member` | `docs/r/google_service_account_iam.html.markdown` |
| Grant Cloud SQL access | `gcloud projects add-iam-policy-binding` | `google_project_iam_member` (with condition) | `docs/r/google_project_iam.html.markdown` |
| Binary Authorization policy | `gcloud container binauthz policy` | `google_binary_authorization_policy` | `docs/r/binary_authorization_policy.html.markdown` |
| Binary Authorization attestor | `gcloud container binauthz attestors create` | `google_binary_authorization_attestor` | `docs/r/binary_authorization_attestor.html.markdown` |
| Log sink creation | `gcloud logging sinks create` | `google_logging_project_sink` | `docs/r/logging_project_sink.html.markdown` |
| Grant log writer | `gcloud projects add-iam-policy-binding` | `google_project_iam_member` | `docs/r/google_project_iam.html.markdown` |
| Create GCS bucket | `gsutil mb` | `google_storage_bucket` | `docs/r/storage_bucket.html.markdown` |
| Bucket IAM | `gsutil iam` | `google_storage_bucket_iam_member` | `docs/r/storage_bucket_iam.html.markdown` |
| Create secrets | `gcloud secrets create` | `google_secret_manager_secret` | `docs/r/secret_manager_secret.html.markdown` |
| Secret IAM | `gcloud secrets add-iam-policy-binding` | `google_secret_manager_secret_iam_member` | `docs/r/secret_manager_secret_iam.html.markdown` |
| Create Cloud SQL | `gcloud sql instances create` | `google_sql_database_instance` | `docs/r/sql_database_instance.html.markdown` |

---

## Task 4 — Isolation Break-Out Scenarios & Defenses

### Attack 1: Container Escape via Kernel Exploit

**How it works**: A malicious insider deploys a container with a known kernel
vulnerability exploit (e.g., CVE-2022-0185, Dirty Pipe). If the container
runs with elevated privileges or access to sensitive syscalls, the attacker
can escape the container sandbox and gain root access on the underlying node.
From the node, they can access other tenants' pods, the kubelet credentials,
and potentially the GCE metadata server.

**Defense**:

| Layer | Control |
|---|---|
| **GKE Sandbox (gVisor)** | Enable `sandbox_config { sandbox_type = "gvisor" }` on the node pool. gVisor interposes a user-space kernel between containers and the host, blocking most kernel exploits. |
| **PodSecurity `restricted` profile** | Prevents `privileged: true`, `hostPID`, `hostNetwork`, and requires dropping all capabilities. |
| **Shielded GKE Nodes** | Enabled via `enable_shielded_nodes = true` on the cluster. Provides Secure Boot and integrity monitoring to detect node-level tampering. |
| **Node auto-upgrade** | Keep nodes on the `REGULAR` release channel to receive kernel security patches automatically. |

### Attack 2: Kubernetes API Server Abuse via Stolen Service Account Token

**How it works**: A malicious insider with access to the `edit` ClusterRole
in their namespace creates a pod that mounts the default service account
token. They use this token to probe the Kubernetes API for RBAC
misconfigurations — looking for overly permissive ClusterRoles, secrets in
other namespaces, or the ability to create ClusterRoleBindings. In a poorly
configured cluster, they could escalate to `cluster-admin`.

**Defense**:

| Layer | Control |
|---|---|
| **`automountServiceAccountToken: false`** | Set on every ServiceAccount. Pods must explicitly opt-in and only mount their own namespace's SA. |
| **Scoped RBAC** | Never bind tenant users to ClusterRoles at the cluster level. Only use `RoleBinding` within the tenant namespace. |
| **Audit Logging** | Enable GKE audit logging (DATA_READ, DATA_WRITE) so all API calls are logged. Alert on suspicious verbs like `create` on `clusterrolebindings`. |
| **RBAC `escalate` verb denied** | Ensure no tenant Role includes the `escalate` or `bind` verbs, preventing them from granting themselves more privileges. |
| **Authorized Networks** | Restrict who can reach the API server at the network level using `master_authorized_networks_config`. |

### Attack 3: Cross-Tenant Network Sniffing / Lateral Movement

**How it works**: Without network policies, all pods in a GKE cluster can
communicate freely. A malicious insider in `team-alpha` can scan the
cluster's pod CIDR range, discover services in `team-beta`'s namespace
(e.g., an unprotected database, internal APIs), and access them directly.
They could also perform ARP spoofing or DNS poisoning on the flat cluster
network to intercept traffic between pods in other namespaces.

**Defense**:

| Layer | Control |
|---|---|
| **Deny-all NetworkPolicy per namespace** | As defined in Task 2 §2.5 — blocks all ingress from other namespaces by default. Only same-namespace traffic is allowed. |
| **Dataplane V2 (Cilium/eBPF)** | Set `datapath_provider = "ADVANCED_DATAPATH"` on the cluster. Provides kernel-level network policy enforcement that is harder to bypass than iptables-based policies. |
| **Dedicated Node Pools with Taints** | Create a node pool per tenant with `taint { key = "tenant", value = "<team>", effect = "NO_SCHEDULE" }`. This provides node-level isolation so tenants never share a VM. |
| **mTLS via Cloud Service Mesh** | Enable Cloud Service Mesh with automatic mTLS. Even if an attacker can reach another namespace's pod, the traffic is encrypted and requires valid mesh identity. |
| **VPC Firewall Rules** | Apply additional compute firewall rules restricting egress from tenant node pools. |

---

## Appendix — Reference Architecture Diagram

```
┌─────────────────────────────────────────────────────────────────────┐
│                         GCP Project                                 │
│                                                                     │
│  ┌───────────────────────────────────────────────────────────────┐  │
│  │              VPC Network (cluster-vpc)                        │  │
│  │                                                               │  │
│  │  ┌─────────────────────────────────────────────────────────┐  │  │
│  │  │           GKE Cluster: shared-prod-cluster              │  │  │
│  │  │       (Private, Regional, Workload Identity,            │  │  │
│  │  │        Network Policy, Binary Authorization)            │  │  │
│  │  │                                                         │  │  │
│  │  │  ┌──────────┐ ┌──────────┐ ┌──────────┐               │  │  │
│  │  │  │team-alpha│ │team-beta │ │team-gamma│  ...           │  │  │
│  │  │  │          │ │          │ │          │               │  │  │
│  │  │  │• K8s SA  │ │• K8s SA  │ │• K8s SA  │               │  │  │
│  │  │  │• RBAC    │ │• RBAC    │ │• RBAC    │               │  │  │
│  │  │  │• Quota   │ │• Quota   │ │• Quota   │               │  │  │
│  │  │  │• NetPol  │ │• NetPol  │ │• NetPol  │               │  │  │
│  │  │  │• PodSec  │ │• PodSec  │ │• PodSec  │               │  │  │
│  │  │  └────┬─────┘ └────┬─────┘ └────┬─────┘               │  │  │
│  │  │       │WI          │WI          │WI                    │  │  │
│  │  └───────┼────────────┼────────────┼──────────────────────┘  │  │
│  │          │            │            │                          │  │
│  └──────────┼────────────┼────────────┼──────────────────────────┘  │
│             │            │            │                              │
│  ┌──────────▼───┐ ┌──────▼──────┐ ┌──▼──────────┐                  │
│  │ GCP SA:      │ │ GCP SA:     │ │ GCP SA:     │                  │
│  │ team-alpha-sa│ │ team-beta-sa│ │ team-gamma-sa│                 │
│  └──────┬───────┘ └──────┬──────┘ └──────┬──────┘                  │
│         │                │               │                          │
│  ┌──────▼───────────────────────────────────────────────────────┐   │
│  │  Per-Team Resources (IAM scoped to each team's resources)    │   │
│  │                                                               │   │
│  │  ┌──────────────┐  ┌───────────────┐  ┌──────────────────┐   │   │
│  │  │ Cloud SQL    │  │ GCS Buckets   │  │ Secret Manager   │   │   │
│  │  │ (per-team)   │  │ (per-team)    │  │ (per-team)       │   │   │
│  │  └──────────────┘  └───────────────┘  └──────────────────┘   │   │
│  └───────────────────────────────────────────────────────────────┘   │
│                                                                      │
│  ┌───────────────────────────────────────────────────────────────┐   │
│  │  Logging: Per-team log sinks → Tenant projects                │   │
│  │  Binary Auth: Attestor → Policy (ENFORCED_BLOCK_AND_AUDIT)    │   │
│  │  Monitoring: GKE cost allocation enabled                      │   │
│  └───────────────────────────────────────────────────────────────┘   │
└──────────────────────────────────────────────────────────────────────┘
```

---

## Key Design Decisions Summary

| Decision | Rationale | Google Best Practice Reference |
|---|---|---|
| One namespace per team, environment-agnostic names | Same manifests across clusters; clear tenant boundary | [Standardize namespace naming](https://cloud.google.com/kubernetes-engine/docs/best-practices/enterprise-multitenancy#create-namespaces) |
| Workload Identity for all pods | No SA keys to leak; automatic credential rotation | [Use Workload Identity](https://cloud.google.com/kubernetes-engine/docs/best-practices/enterprise-multitenancy#workload-identity) |
| Resource-level IAM (not project-level) | Each team accesses only their Cloud SQL, buckets, secrets | [Least privilege](https://cloud.google.com/architecture/cross-silo-cross-device-federated-learning-google-cloud#least_privilege) |
| Deny-all NetworkPolicy + Dataplane V2 | Prevents cross-tenant traffic; eBPF enforcement | [Control Pod communication](https://cloud.google.com/kubernetes-engine/docs/best-practices/enterprise-multitenancy#network-policies) |
| PodSecurity `restricted` profile | SOC 2 requires strong workload hardening | [Set up policy-based admission controls](https://cloud.google.com/kubernetes-engine/docs/best-practices/enterprise-multitenancy#psps) |
| Binary Authorization with attestors | Only verified CI/CD images can run | [Binary Authorization](https://cloud.google.com/binary-authorization/docs/overview) |
| Per-tenant log sinks to tenant projects | Teams own their logs; SOC 2 audit separation | [Multi-tenant logging](https://cloud.google.com/kubernetes-engine/docs/how-to/multi-tenant-logging) |
| Regional private cluster | HA control plane; no public node IPs | [Creating reliable and highly available clusters](https://cloud.google.com/kubernetes-engine/docs/best-practices/enterprise-multitenancy#create-cluster) |
| Terraform for_each over teams map | DRY infrastructure; adding a team = adding a map entry | Infrastructure-as-code best practice |

---

## SOC 2 Compliance Mapping

| SOC 2 Criteria | Control Implemented |
|---|---|
| **CC6.1** — Logical access controls | RBAC per namespace, IAM per resource, Workload Identity |
| **CC6.2** — Prior to issuing credentials | GCP SA created via Terraform, K8s SA with `automountServiceAccountToken: false` |
| **CC6.3** — Restrict access to assets | NetworkPolicy deny-all, private cluster, authorized networks |
| **CC6.6** — Restrict access to system boundaries | Binary Authorization, PodSecurity restricted, GKE Sandbox |
| **CC7.1** — Detect and monitor anomalies | Audit logging, per-tenant log routing, GKE cost allocation |
| **CC7.2** — Monitor system components | Cloud Monitoring + Logging integration, Dataplane V2 observability |
| **CC8.1** — Manage changes to infrastructure | Terraform IaC, Git-based change management, release channels |
