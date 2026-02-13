# Task 2: Secure OAuth 2.0 Implementation Design

## Executive Summary

This document presents a secure OAuth 2.0 implementation design for the partner integration platform, addressing every vulnerability identified in [Task 1](./task1.md). The design covers five core areas:

1. **Authorization Code Flow with PKCE** — Cryptographic binding of authorization requests to code redemption
2. **Token Storage Security** — Application-level encryption at rest with GCP Cloud KMS
3. **Refresh Token Rotation** — Automatic rotation with token family tracking and theft detection
4. **Scope-Based Access Control** — Hierarchical scope model with per-partner scope restrictions
5. **Token Revocation** — Multi-level revocation with cascading invalidation

All designs target the GCP stack specified in the original requirements: **Cloud Run** (API), **Cloud SQL** (storage), **Cloud KMS / Secret Manager** (key management).

---

## Table of Contents

- [1. Authorization Code Flow with PKCE](#1-authorization-code-flow-with-pkce)
- [2. Token Storage Security — Encryption at Rest](#2-token-storage-security--encryption-at-rest)
- [3. Refresh Token Rotation Strategy](#3-refresh-token-rotation-strategy)
- [4. Scope-Based Access Control](#4-scope-based-access-control)
- [5. Token Revocation Mechanism](#5-token-revocation-mechanism)
- [6. Complete Database Schema](#6-complete-database-schema)
- [7. Security Configuration Summary](#7-security-configuration-summary)
- [References](#references)

---

## 1. Authorization Code Flow with PKCE

### 1.1 Overview

The authorization code flow with PKCE (RFC 7636) ensures that only the entity that initiated the authorization request can redeem the resulting authorization code. This is achieved by generating a cryptographic secret (`code_verifier`) on the client side, sending a derived challenge (`code_challenge`) with the authorization request, and proving knowledge of the original secret at token redemption.

### 1.2 Flow Sequence

```
┌──────────┐     ┌──────────────┐     ┌─────────────────┐     ┌─────────────┐
│  Partner  │     │   User       │     │  Authorization   │     │   Token     │
│  Client   │     │   Browser    │     │  Server (Cloud   │     │   Endpoint  │
│           │     │              │     │  Run)            │     │  (Cloud Run)│
└─────┬─────┘     └──────┬───────┘     └────────┬─────────┘     └──────┬──────┘
      │                  │                      │                      │
      │ 1. Generate      │                      │                      │
      │    code_verifier  │                      │                      │
      │    + code_challenge                      │                      │
      │    + state        │                      │                      │
      │                  │                      │                      │
      │ 2. Redirect ────►│                      │                      │
      │                  │ 3. GET /oauth/authorize                     │
      │                  │─────────────────────►│                      │
      │                  │                      │                      │
      │                  │ 4. Authenticate User │                      │
      │                  │◄────────────────────►│                      │
      │                  │                      │                      │
      │                  │ 5. Consent Screen    │                      │
      │                  │◄─────────────────────│                      │
      │                  │                      │                      │
      │                  │ 6. User Approves     │                      │
      │                  │─────────────────────►│                      │
      │                  │                      │                      │
      │                  │ 7. 302 Redirect with │                      │
      │                  │    code + state      │                      │
      │                  │◄─────────────────────│                      │
      │                  │                      │                      │
      │ 8. Receive code ◄│                      │                      │
      │    + validate state                     │                      │
      │                  │                      │                      │
      │ 9. POST /oauth/token ──────────────────────────────────────────►
      │    (code + code_verifier + client_secret)                      │
      │                  │                      │                      │
      │                  │                      │  10. Validate:       │
      │                  │                      │   - client_secret    │
      │                  │                      │   - code_verifier    │
      │                  │                      │     vs code_challenge│
      │                  │                      │   - redirect_uri     │
      │                  │                      │   - code expiry      │
      │                  │                      │   - code single-use  │
      │                  │                      │                      │
      │ 11. Token Response ◄───────────────────────────────────────────│
      │     (access_token, refresh_token, id_token, expires_in, scope) │
      │                  │                      │                      │
```

### 1.3 Step-by-Step Detail

#### Step 1: Client Generates PKCE Values

Before initiating the flow, the partner client generates:

```
code_verifier  = cryptographically random string, 43-128 characters
                 (RFC 7636 §4.1: [A-Z] / [a-z] / [0-9] / "-" / "." / "_" / "~")

code_challenge = BASE64URL(SHA256(code_verifier))

state          = cryptographically random string, stored in client session
                 (CSRF protection per RFC 6749 §10.12)
```

**Example:**

```
code_verifier:  dBjftJeZ4CVP-mB92K27uhbUJU1p1r_wW1gFWFOEjXk
code_challenge: E9Melhoa2OwvFrEMTJguCHaoeK1t8URWbuGJSstw-cM
state:          af0ifjsldkj
```

#### Step 2–3: Authorization Request

The partner redirects the user's browser to the authorization endpoint:

```http
GET /oauth/authorize?
  response_type=code
  &client_id=partner_abc_id
  &redirect_uri=https://partner.com/callback
  &scope=verification:read documents:read
  &state=af0ifjsldkj
  &code_challenge=E9Melhoa2OwvFrEMTJguCHaoeK1t8URWbuGJSstw-cM
  &code_challenge_method=S256
HTTP/1.1
Host: auth.idme.com
```

**Required parameters:**

| Parameter | Required | Purpose |
|---|---|---|
| `response_type` | ✅ | Must be `code` |
| `client_id` | ✅ | Registered partner identifier |
| `redirect_uri` | ✅ | Must exactly match a pre-registered URI |
| `scope` | ✅ | Space-delimited permissions requested |
| `state` | ✅ | CSRF protection — opaque, client-generated |
| `code_challenge` | ✅ | PKCE challenge derived from `code_verifier` |
| `code_challenge_method` | ✅ | Must be `S256` (plain is rejected) |

#### Steps 4–6: Authentication and Consent

The authorization server:

1. **Validates `redirect_uri`** — exact string match against pre-registered URIs for this `client_id`
2. **Validates `client_id`** — must exist and be in `active` status
3. **Validates `scope`** — requested scopes must be a subset of scopes registered for this partner
4. **Authenticates the user** — redirects to ID.me authentication if not already signed in
5. **Displays consent screen** — shows the partner name, requested scopes in human-readable form
6. **Records consent** — user approves or denies

#### Step 7: Authorization Response

On approval, the authorization server generates a single-use authorization code and redirects:

```http
HTTP/1.1 302 Found
Location: https://partner.com/callback?
  code=SplxlOBeZQQYbYS6WxSbIA
  &state=af0ifjsldkj
```

**Authorization code properties:**

| Property | Value |
|---|---|
| Format | Cryptographically random, 128-bit minimum entropy |
| Lifetime | **10 minutes** maximum (RFC 6749 §4.1.2) |
| Usage | **Single-use** — invalidated immediately upon redemption |
| Storage | Stored server-side with `code_challenge`, `client_id`, `redirect_uri`, `scope`, `user_id` |

**Server-side authorization code record:**

```json
{
  "code_hash": "SHA256(SplxlOBeZQQYbYS6WxSbIA)",
  "client_id": "partner_abc_id",
  "redirect_uri": "https://partner.com/callback",
  "code_challenge": "E9Melhoa2OwvFrEMTJguCHaoeK1t8URWbuGJSstw-cM",
  "code_challenge_method": "S256",
  "scope": "verification:read documents:read",
  "user_id": "user_12345",
  "expires_at": "2026-02-13T10:10:00Z",
  "used": false
}
```

#### Step 8: Client Receives Code

The partner client:
1. Receives the callback with `code` and `state`
2. **Validates `state`** — compares to the value stored in session before the request; rejects if mismatch (CSRF check)
3. Proceeds to token exchange

#### Step 9: Token Request

The partner exchanges the authorization code for tokens:

```http
POST /oauth/token HTTP/1.1
Host: auth.idme.com
Content-Type: application/x-www-form-urlencoded
Authorization: Basic base64(client_id:client_secret)

grant_type=authorization_code
&code=SplxlOBeZQQYbYS6WxSbIA
&redirect_uri=https://partner.com/callback
&code_verifier=dBjftJeZ4CVP-mB92K27uhbUJU1p1r_wW1gFWFOEjXk
```

**Authentication:** Partners authenticate via HTTP Basic (RFC 6749 §2.3.1) with their `client_id` and `client_secret`. Alternatively, `client_id` and `client_secret` may be included in the POST body, but the `Authorization` header is preferred.

#### Step 10: Server-Side Validation

The authorization server performs the following validations **in order** — failing at any step returns an error and does not proceed:

```
 ✅ 1. Authenticate the client (client_id + client_secret)
 ✅ 2. Verify authorization code exists and has not been used
 ✅ 3. Verify authorization code has not expired (< 10 minutes)
 ✅ 4. Verify client_id matches the code's original client_id
 ✅ 5. Verify redirect_uri matches the code's original redirect_uri
 ✅ 6. Verify PKCE:
        computed = BASE64URL(SHA256(code_verifier))
        assert computed == stored code_challenge
 ✅ 7. Mark authorization code as used (single-use enforcement)
 ✅ 8. If code was already used → REVOKE all tokens issued from that code
        (authorization code replay detection)
```

**PKCE verification pseudocode:**

```python
import hashlib, base64

def verify_pkce(code_verifier: str, stored_code_challenge: str) -> bool:
    """Verify PKCE code_verifier against stored code_challenge (S256)."""
    digest = hashlib.sha256(code_verifier.encode('ascii')).digest()
    computed_challenge = base64.urlsafe_b64encode(digest).rstrip(b'=').decode('ascii')
    return hmac.compare_digest(computed_challenge, stored_code_challenge)
```

**Authorization code replay detection:**

If a code that has already been redeemed is presented again, the server MUST:
1. Reject the request with error `invalid_grant`
2. Revoke ALL tokens (access + refresh) that were issued from the original code redemption
3. Log the event as a potential token theft incident

> *Per RFC 6749 §4.1.2: "If the authorization code is used more than once, the authorization server MUST deny the request and SHOULD revoke (when possible) all tokens previously issued based on that authorization code."*

#### Step 11: Token Response

```http
HTTP/1.1 200 OK
Content-Type: application/json
Cache-Control: no-store
Pragma: no-cache

{
  "access_token": "eyJhbGciOiJSUzI1NiIsInR5cCI6ImF0K2p3dCJ9...",
  "token_type": "Bearer",
  "expires_in": 900,
  "refresh_token": "v1.MjQ1NjM4OTcxMjM0NTY3ODkw.a3F2b...",
  "scope": "verification:read documents:read"
}
```

| Field | Value | Notes |
|---|---|---|
| `access_token` | Signed JWT (RS256) | 15-minute lifetime, contains `sub`, `client_id`, `scope`, `aud`, `iss`, `exp`, `iat`, `jti` |
| `token_type` | `Bearer` | Per RFC 6750 |
| `expires_in` | `900` | 15 minutes in seconds |
| `refresh_token` | Opaque string | 90-day absolute lifetime, 14-day idle timeout, subject to rotation |
| `scope` | Granted scopes | May be a subset of requested scopes |

### 1.4 Access Token Format (JWT)

Access tokens are signed JWTs (following the JWT Profile for OAuth 2.0 Access Tokens — RFC 9068):

```json
// Header
{
  "alg": "RS256",
  "typ": "at+jwt",
  "kid": "2026-02-key-1"
}

// Payload
{
  "iss": "https://auth.idme.com",
  "sub": "user_12345",
  "aud": "https://api.idme.com",
  "client_id": "partner_abc_id",
  "scope": "verification:read documents:read",
  "iat": 1739462400,
  "exp": 1739463300,
  "jti": "unique-token-id-uuid"
}

// Signature
RS256(header + "." + payload, private_key)
```

**Why JWT instead of opaque UUID v4:**

- **Self-contained validation** — Resource servers can validate tokens locally without calling the authorization server, reducing latency and single points of failure
- **Cryptographic integrity** — RS256 signature ensures tokens cannot be tampered with
- **Standard claims** — `aud`, `scope`, `exp`, `client_id` enable resource servers to enforce access control without shared memory with the authorization server
- **Interoperability** — Per the professional guide: *"The use of JWT as a format for access tokens is so common that it led me to drive a standardization effort to define an interoperable profile for it"* (Chapter 4)

**Signing key management:**

- RSA-2048 key pairs stored in **GCP Cloud KMS**
- Keys are rotated every 90 days
- The `kid` (key ID) in the JWT header allows resource servers to select the correct public key
- Public keys are published at `/.well-known/jwks.json` for resource server validation

---

## 2. Token Storage Security — Encryption at Rest

### 2.1 Encryption Strategy

All sensitive token data is encrypted **at the application level** before being written to Cloud SQL, using **AES-256-GCM** with keys managed by **GCP Cloud KMS**.

This provides defense-in-depth beyond Cloud SQL's built-in transparent disk encryption (TDE), which does not protect against:
- SQL injection attacks
- Compromised application service accounts
- Database admin access
- Database backup theft
- Query log / slow query log exposure

### 2.2 Encryption Architecture

```
┌─────────────────────────────────────────────────────────────────────┐
│                        Application Layer (Cloud Run)                │
│                                                                     │
│  ┌──────────────┐    ┌─────────────────┐    ┌───────────────────┐  │
│  │  Token        │    │  Encryption     │    │  GCP Cloud KMS    │  │
│  │  Service      │───►│  Service        │───►│  (Key Management) │  │
│  │              │    │                 │    │                   │  │
│  │  Generates   │    │  AES-256-GCM    │    │  Key: idme-oauth  │  │
│  │  tokens      │    │  encrypt/decrypt│    │  -token-key       │  │
│  └──────────────┘    └────────┬────────┘    └───────────────────┘  │
│                               │                                     │
└───────────────────────────────┼─────────────────────────────────────┘
                                │
                    ┌───────────▼───────────┐
                    │     Cloud SQL          │
                    │  (PostgreSQL)          │
                    │                        │
                    │  Stores:               │
                    │  - Encrypted tokens    │
                    │  - SHA-256 hashes      │
                    │  - Key version IDs     │
                    │                        │
                    │  Does NOT store:       │
                    │  - Plaintext tokens    │
                    │  - Encryption keys     │
                    └────────────────────────┘
```

### 2.3 Token Storage Patterns

#### Access Tokens (JWT)

Since access tokens are signed JWTs validated by resource servers using public keys, they do **not** need to be stored in the database at all. The authorization server:

1. Signs the JWT at issuance time
2. Returns it to the client
3. Does not persist it

This eliminates an entire class of storage-related attack vectors for access tokens. Revocation is handled via a lightweight revocation list (see [Section 5](#5-token-revocation-mechanism)).

#### Refresh Tokens (Opaque)

Refresh tokens are opaque strings that must be stored server-side. The storage pattern:

```
Refresh Token Value: "v1.MjQ1NjM4OTcxMjM0NTY3ODkw.a3F2b..."
                          │
                          ▼
               ┌──────────────────────┐
               │                      │
    ┌──────────┴──────┐    ┌──────────┴──────────┐
    │  SHA-256 Hash   │    │  AES-256-GCM        │
    │  (for lookup)   │    │  Encrypted           │
    │                 │    │  (for recovery)      │
    ▼                 │    ▼                      │
  Stored in:          │  Stored in:               │
  refresh_token_hash  │  refresh_token_encrypted  │
  (indexed column)    │  (BYTEA column)           │
  └───────────────────┘  └────────────────────────┘
```

- **Lookup:** The server hashes the incoming refresh token with SHA-256 and queries the `refresh_token_hash` index
- **Verification:** After lookup, the server decrypts `refresh_token_encrypted` using Cloud KMS and performs a constant-time comparison with the presented token
- **No plaintext storage:** The raw token value never exists in the database

#### Authorization Codes

Authorization codes are short-lived (10 minutes) and stored as SHA-256 hashes only:

```
code_hash = SHA256(authorization_code)
```

The raw code is returned to the client and never stored. At redemption, the server hashes the presented code and looks it up.

### 2.4 GCP Cloud KMS Configuration

```
Project:         idme-oauth-prod
Key Ring:        oauth-token-keyring
Key:             oauth-token-encryption-key
Algorithm:       AES-256-GCM (symmetric)
Purpose:         ENCRYPT_DECRYPT
Rotation:        Automatic, every 90 days
Protection:      HSM (Cloud HSM) for production
```

**Key rotation:**
- Cloud KMS automatically manages key versions
- New tokens are encrypted with the latest key version
- Old tokens remain decryptable — Cloud KMS retains previous versions
- The `encryption_key_version` column in the database tracks which key version encrypted each token
- Periodic background job re-encrypts old tokens with the latest key version

**IAM permissions (least privilege):**

| Principal | Role | Scope |
|---|---|---|
| Cloud Run service account | `roles/cloudkms.cryptoKeyEncrypterDecrypter` | `oauth-token-encryption-key` only |
| CI/CD service account | No KMS access | — |
| Database admin | No KMS access | Cannot decrypt tokens even with DB access |
| Key admin (security team only) | `roles/cloudkms.admin` | Key ring level |

---

## 3. Refresh Token Rotation Strategy

### 3.1 Overview

Refresh token rotation ensures that every refresh token is **single-use**. Each time a refresh token is redeemed, the server invalidates it and issues a new one. This limits the window of exposure for a compromised refresh token and enables automatic theft detection.

### 3.2 Token Family Model

All refresh tokens issued from a single authorization grant form a **token family**, tracked by a `token_family_id`:

```
Authorization Code Grant
  │
  ▼
Token Family: "family_abc_123"
  │
  ├── Refresh Token v1 (issued at grant)        → USED, invalidated
  │     └── Access Token A1 (15 min)
  │
  ├── Refresh Token v2 (issued when v1 redeemed) → USED, invalidated
  │     └── Access Token A2 (15 min)
  │
  ├── Refresh Token v3 (issued when v2 redeemed) → ACTIVE (current)
  │     └── Access Token A3 (15 min)
  │
  └── (continues...)
```

### 3.3 Rotation Flow

```http
POST /oauth/token HTTP/1.1
Host: auth.idme.com
Content-Type: application/x-www-form-urlencoded
Authorization: Basic base64(client_id:client_secret)

grant_type=refresh_token
&refresh_token=v1.MjQ1NjM4OTcxMjM0NTY3ODkw.a3F2b...
```

**Server-side processing:**

```
1. Authenticate client (client_id + client_secret)
2. Hash incoming refresh token → lookup in refresh_token_hash index
3. Decrypt and verify refresh token
4. Validate token is not revoked
5. Validate token has not already been used (rotation check)
   ├── If already used → THEFT DETECTED (see §3.4)
   └── If not used → continue
6. Validate absolute expiration (90 days from original grant)
7. Validate idle expiration (14 days since last use)
8. Mark current refresh token as USED (set used_at timestamp)
9. Generate new refresh token
10. Store new token in same token_family_id
11. Return new access_token + new refresh_token
```

**Response:**

```json
{
  "access_token": "eyJhbGciOiJSUzI1NiIs...",
  "token_type": "Bearer",
  "expires_in": 900,
  "refresh_token": "v1.NEW_ROTATED_TOKEN.xyz...",
  "scope": "verification:read documents:read"
}
```

### 3.4 Theft Detection and Response

If a refresh token that has already been marked as **USED** is presented again, it indicates that either:

1. The legitimate client and an attacker both have the same token (the token was stolen before the legitimate client used it), or
2. An attacker is replaying a previously captured token

**Response to detected theft:**

```
┌──────────────────────────────────────────────────┐
│         Refresh Token Replay Detected!           │
│                                                  │
│  1. REJECT the current request                   │
│  2. REVOKE the entire token family:              │
│     - All refresh tokens with this family_id     │
│     - All active access tokens (add to           │
│       revocation list via jti)                   │
│  3. LOG security event with:                     │
│     - client_id, user_id, token_family_id        │
│     - source IP, timestamp                       │
│     - the used_at timestamp vs current attempt   │
│  4. ALERT security team (Cloud Monitoring)       │
│  5. User must re-authenticate to obtain          │
│     new tokens                                   │
│                                                  │
└──────────────────────────────────────────────────┘
```

### 3.5 Expiration Policy

| Parameter | Value | Purpose |
|---|---|---|
| **Absolute lifetime** | 90 days | Hard limit from original grant — forces re-authorization |
| **Idle timeout** | 14 days | Invalidates if not used within window — detects abandoned sessions |
| **Access token lifetime** | 15 minutes | Limits bearer token exposure window |
| **Authorization code lifetime** | 10 minutes | Prevents delayed code redemption attacks |

**Expiration check order:**

```python
def validate_refresh_token(token_record) -> bool:
    now = datetime.utcnow()

    # 1. Is it revoked?
    if token_record.revoked_at is not None:
        raise TokenRevokedError()

    # 2. Has it already been used? (rotation violation)
    if token_record.used_at is not None:
        revoke_token_family(token_record.token_family_id)
        raise TokenReplayError()  # THEFT DETECTED

    # 3. Has absolute lifetime expired?
    if now > token_record.absolute_expires_at:
        raise TokenExpiredError("absolute")

    # 4. Has idle timeout expired?
    if now > token_record.idle_expires_at:
        raise TokenExpiredError("idle")

    return True
```

---

## 4. Scope-Based Access Control

### 4.1 Scope Hierarchy

Scopes follow a `resource:action` naming convention, providing fine-grained access control over the platform's customer data:

```
Scopes for the Partner Integration Platform
═══════════════════════════════════════════

verification:read       Read customer verification status and history
verification:read.basic Read only verification status (pass/fail), no details
documents:read          Read customer uploaded documents
documents:list          List document metadata only (no content)
profile:read            Read basic user profile information
profile:email           Read user email address

(Future expansion)
verification:write      Update verification records (admin partners only)
webhooks:manage         Register and manage webhook subscriptions
```

### 4.2 Partner Scope Registration

Each partner is registered with a maximum set of allowed scopes. Partners cannot request scopes beyond their registration, regardless of user consent.

```sql
-- Example: Partner registration with allowed scopes
INSERT INTO oauth_clients (client_id, client_name, allowed_scopes)
VALUES (
  'partner_abc_id',
  'Acme SaaS Corp',
  ARRAY['verification:read', 'documents:list', 'profile:read']
);
```

**Scope validation at authorization:**

```
Requested scopes: verification:read documents:read profile:read
Partner allowed:  verification:read documents:list profile:read
                                    ▲
                                    │
                          documents:read is NOT in allowed scopes
                          → Request is rejected OR
                          → Scope is silently downgraded to documents:list
                            (configurable policy)
```

### 4.3 Scope Enforcement Points

Scopes are enforced at **three levels**:

```
Level 1: Authorization Server (at grant time)
├── Validates requested scopes ⊆ partner's allowed_scopes
├── Presents only valid scopes in consent screen
└── Issues access token with granted scopes only

Level 2: API Gateway / Middleware (at request time)
├── Extracts scope claim from JWT access token
├── Compares required scope for the endpoint vs. token scopes
└── Returns 403 Forbidden if insufficient scope

Level 3: Resource Server / Application Logic (at data access)
├── Evaluates scope + user identity for fine-grained decisions
├── e.g., documents:list allows metadata but NOT document content
└── Applies row-level filtering based on user_id in token
```

### 4.4 API Endpoint Scope Requirements

| Endpoint | Method | Required Scope | Description |
|---|---|---|---|
| `/api/v1/verifications` | GET | `verification:read` | Full verification history |
| `/api/v1/verifications/status` | GET | `verification:read.basic` | Status only (pass/fail) |
| `/api/v1/documents` | GET | `documents:list` | Document metadata listing |
| `/api/v1/documents/{id}` | GET | `documents:read` | Document content download |
| `/api/v1/profile` | GET | `profile:read` | User profile info |
| `/api/v1/profile/email` | GET | `profile:email` | User email address |

### 4.5 Scope Enforcement Middleware (Pseudocode)

```python
from functools import wraps

def require_scope(*required_scopes):
    """Decorator that enforces scope requirements on API endpoints."""
    def decorator(f):
        @wraps(f)
        def wrapper(request, *args, **kwargs):
            # Extract and validate JWT access token
            token = validate_access_token(request.headers.get('Authorization'))

            # Parse scope claim from validated JWT
            token_scopes = set(token.claims.get('scope', '').split())

            # Check that ALL required scopes are present
            missing = set(required_scopes) - token_scopes
            if missing:
                return Response(
                    status=403,
                    body={
                        "error": "insufficient_scope",
                        "error_description": f"Missing required scopes: {', '.join(missing)}",
                        "required_scopes": list(required_scopes)
                    }
                )

            # Scopes satisfied — proceed to handler
            return f(request, *args, **kwargs)
        return wrapper
    return decorator

# Usage
@require_scope('verification:read')
def get_verifications(request):
    user_id = request.token.claims['sub']
    return verification_service.get_history(user_id)

@require_scope('documents:read')
def get_document(request, document_id):
    user_id = request.token.claims['sub']
    # Additional check: user owns this document
    return document_service.get_document(document_id, owner_id=user_id)
```

---

## 5. Token Revocation Mechanism

### 5.1 Revocation Endpoint

Per **RFC 7009** (OAuth 2.0 Token Revocation), the platform exposes a revocation endpoint:

```
POST /oauth/revoke
```

### 5.2 Revocation Request

Partners can revoke their own tokens:

```http
POST /oauth/revoke HTTP/1.1
Host: auth.idme.com
Content-Type: application/x-www-form-urlencoded
Authorization: Basic base64(client_id:client_secret)

token=v1.MjQ1NjM4OTcxMjM0NTY3ODkw.a3F2b...
&token_type_hint=refresh_token
```

| Parameter | Required | Description |
|---|---|---|
| `token` | ✅ | The token to revoke |
| `token_type_hint` | Optional | `access_token` or `refresh_token` — helps server locate token faster |

**Response:** Always `200 OK` (per RFC 7009 §2.2 — the response is always successful to prevent token fishing).

### 5.3 Revocation Cascading

Revocation follows cascading rules depending on what is revoked:

```
Revoke a Refresh Token
  │
  ├── Mark refresh token as revoked (set revoked_at)
  ├── Revoke ALL other refresh tokens in the same token_family_id
  └── Add all access token JTIs from this family to the revocation list
      (access tokens are JWTs — they can't be "deleted" but can be
       blocklisted by jti)

Revoke an Access Token (by jti)
  │
  └── Add jti to the access token revocation list
      (does NOT cascade to refresh tokens — partner may still refresh)

Revoke by User (user-initiated "disconnect partner")
  │
  ├── Revoke ALL token families for this user + client_id
  ├── Revoke ALL refresh tokens for this user + client_id
  └── Add ALL access token JTIs for this user + client_id to revocation list

Revoke by Partner (admin action — disable a partner)
  │
  ├── Set partner status to SUSPENDED in oauth_clients
  ├── Revoke ALL token families for this client_id (all users)
  └── Add ALL access token JTIs for this client_id to revocation list
```

### 5.4 Access Token Revocation List

Since access tokens are self-contained JWTs, they cannot be "invalidated" at the database level. Instead, the resource server checks a lightweight revocation list:

```
┌──────────────────────────────────────────────────────────┐
│                Access Token Revocation Check              │
│                                                          │
│  On every API request:                                   │
│                                                          │
│  1. Validate JWT signature (RS256 public key)            │
│  2. Validate exp, iss, aud claims                        │
│  3. Extract jti from JWT                                 │
│  4. CHECK jti against revocation list:                   │
│     ├── Primary: Redis / Memorystore (in-memory, fast)   │
│     └── Fallback: Cloud SQL revoked_tokens table         │
│  5. If jti found → reject with 401                       │
│  6. If jti NOT found → allow request                     │
│                                                          │
│  Revocation list entries auto-expire after 15 minutes    │
│  (matching access token lifetime — no need to track      │
│   revoked tokens beyond their natural expiration)        │
└──────────────────────────────────────────────────────────┘
```

**GCP implementation:** Use **Memorystore (Redis)** for the revocation list with a TTL of 15 minutes (matching access token lifetime). After 15 minutes, the access token would have expired naturally, so the revocation entry can be evicted.

### 5.5 User-Facing Revocation

Users can revoke partner access via the ID.me dashboard:

```
GET /account/connected-apps           → List all partners with active tokens
DELETE /account/connected-apps/{id}   → Revoke all tokens for a partner
```

This triggers the "Revoke by User" cascade described in §5.3.

---

## 6. Complete Database Schema

The following schema replaces the original insecure design:

```sql
-- ============================================================
-- Table: oauth_clients (Partner Registration)
-- ============================================================
CREATE TABLE oauth_clients (
    client_id           VARCHAR(255) PRIMARY KEY,
    client_name         VARCHAR(255) NOT NULL,
    client_secret_hash  VARCHAR(128) NOT NULL,       -- bcrypt hash of client_secret
    redirect_uris       TEXT[] NOT NULL,              -- array of pre-registered URIs (exact match)
    allowed_scopes      TEXT[] NOT NULL,              -- max scopes this partner can request
    status              VARCHAR(20) NOT NULL DEFAULT 'active',
                                                     -- active | suspended | revoked
    created_at          TIMESTAMP NOT NULL DEFAULT NOW(),
    updated_at          TIMESTAMP NOT NULL DEFAULT NOW(),

    CONSTRAINT chk_status CHECK (status IN ('active', 'suspended', 'revoked'))
);

-- ============================================================
-- Table: oauth_authorization_codes (Short-Lived, Single-Use)
-- ============================================================
CREATE TABLE oauth_authorization_codes (
    id                      UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    code_hash               VARCHAR(64) NOT NULL UNIQUE,    -- SHA-256 of the authorization code
    client_id               VARCHAR(255) NOT NULL,
    redirect_uri            TEXT NOT NULL,
    user_id                 VARCHAR(255) NOT NULL,
    scope                   TEXT NOT NULL,
    code_challenge          VARCHAR(128) NOT NULL,           -- PKCE code_challenge
    code_challenge_method   VARCHAR(10) NOT NULL DEFAULT 'S256',
    expires_at              TIMESTAMP NOT NULL,              -- 10 minutes from creation
    used_at                 TIMESTAMP,                       -- NULL = not yet used
    created_at              TIMESTAMP NOT NULL DEFAULT NOW(),

    CONSTRAINT fk_auth_code_client FOREIGN KEY (client_id)
        REFERENCES oauth_clients(client_id)
);

CREATE INDEX idx_auth_code_hash ON oauth_authorization_codes(code_hash);
CREATE INDEX idx_auth_code_expires ON oauth_authorization_codes(expires_at);

-- ============================================================
-- Table: oauth_refresh_tokens (Encrypted, Rotatable)
-- ============================================================
CREATE TABLE oauth_refresh_tokens (
    id                          UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    refresh_token_hash          VARCHAR(64) NOT NULL UNIQUE, -- SHA-256 hash for lookup
    refresh_token_encrypted     BYTEA NOT NULL,              -- AES-256-GCM encrypted value
    encryption_key_version      INT NOT NULL,                -- Cloud KMS key version
    client_id                   VARCHAR(255) NOT NULL,
    user_id                     VARCHAR(255) NOT NULL,
    scope                       TEXT NOT NULL,
    token_family_id             UUID NOT NULL,               -- groups all tokens from one grant
    absolute_expires_at         TIMESTAMP NOT NULL,          -- 90 days from original grant
    idle_expires_at             TIMESTAMP NOT NULL,          -- 14 days from last use
    used_at                     TIMESTAMP,                   -- set when rotated (single-use)
    revoked_at                  TIMESTAMP,                   -- set when explicitly revoked
    created_at                  TIMESTAMP NOT NULL DEFAULT NOW(),

    CONSTRAINT fk_refresh_client FOREIGN KEY (client_id)
        REFERENCES oauth_clients(client_id)
);

CREATE INDEX idx_refresh_hash ON oauth_refresh_tokens(refresh_token_hash);
CREATE INDEX idx_refresh_family ON oauth_refresh_tokens(token_family_id);
CREATE INDEX idx_refresh_client_user ON oauth_refresh_tokens(client_id, user_id);
CREATE INDEX idx_refresh_expires ON oauth_refresh_tokens(absolute_expires_at);

-- ============================================================
-- Table: oauth_access_token_revocations (JTI Blocklist)
-- ============================================================
CREATE TABLE oauth_access_token_revocations (
    jti                 VARCHAR(255) PRIMARY KEY,       -- JWT ID from access token
    client_id           VARCHAR(255) NOT NULL,
    user_id             VARCHAR(255) NOT NULL,
    revoked_at          TIMESTAMP NOT NULL DEFAULT NOW(),
    expires_at          TIMESTAMP NOT NULL,             -- matches access token expiry
                                                        -- (auto-cleanup after this time)

    CONSTRAINT fk_revocation_client FOREIGN KEY (client_id)
        REFERENCES oauth_clients(client_id)
);

CREATE INDEX idx_revocation_expires ON oauth_access_token_revocations(expires_at);

-- ============================================================
-- Table: oauth_consent_records (Audit Trail)
-- ============================================================
CREATE TABLE oauth_consent_records (
    id                  UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    client_id           VARCHAR(255) NOT NULL,
    user_id             VARCHAR(255) NOT NULL,
    scope               TEXT NOT NULL,
    granted_at          TIMESTAMP NOT NULL DEFAULT NOW(),
    revoked_at          TIMESTAMP,

    CONSTRAINT fk_consent_client FOREIGN KEY (client_id)
        REFERENCES oauth_clients(client_id)
);

CREATE INDEX idx_consent_client_user ON oauth_consent_records(client_id, user_id);

-- ============================================================
-- Scheduled Cleanup Jobs
-- ============================================================
-- Run via Cloud Scheduler → Cloud Run job

-- 1. Purge expired authorization codes (older than 10 minutes)
-- DELETE FROM oauth_authorization_codes WHERE expires_at < NOW();

-- 2. Purge expired refresh tokens
-- DELETE FROM oauth_refresh_tokens WHERE absolute_expires_at < NOW();

-- 3. Purge expired revocation entries (access tokens already expired naturally)
-- DELETE FROM oauth_access_token_revocations WHERE expires_at < NOW();
```

### Schema Comparison: Before vs. After

| Aspect | Original Design | Secure Design |
|---|---|---|
| **Tables** | 1 (`oauth_tokens`) | 5 (clients, codes, refresh tokens, revocations, consent) |
| **Token storage** | Plaintext VARCHAR | AES-256-GCM encrypted + SHA-256 hash |
| **Access tokens** | Stored in DB | Not stored — signed JWT, validated locally |
| **Refresh tokens** | Plaintext, never expire | Encrypted, 90-day absolute / 14-day idle, rotated |
| **Auth codes** | Not modeled | SHA-256 hashed, 10-min expiry, single-use, PKCE bound |
| **Client secrets** | Not modeled | bcrypt hashed |
| **Revocation** | Not possible | Multi-level: token, family, user, partner |
| **Key management** | None | GCP Cloud KMS with automatic rotation |
| **Redirect URIs** | Not validated | Pre-registered array, exact-match enforced |
| **Scopes** | Unvalidated TEXT | Array of allowed scopes per partner |

---

## 7. Security Configuration Summary

| Parameter | Value | Rationale |
|---|---|---|
| Access token format | Signed JWT (RS256) | Self-contained validation, no DB lookup needed |
| Access token lifetime | **15 minutes** | Minimizes bearer token exposure window |
| Refresh token format | Opaque string | Not inspectable by client; server-side lookup |
| Refresh token absolute lifetime | **90 days** | Forces periodic re-authorization |
| Refresh token idle timeout | **14 days** | Detects abandoned sessions |
| Refresh token rotation | **Mandatory** | Every use issues new token, old one invalidated |
| Authorization code lifetime | **10 minutes** | RFC 6749 §4.1.2 recommendation |
| Authorization code usage | **Single-use** | Replay triggers family revocation |
| PKCE | **Required (S256)** | Prevents code interception attacks |
| `state` parameter | **Required** | CSRF protection (RFC 6749 §10.12) |
| `redirect_uri` validation | **Exact match** | Pre-registered URIs only |
| Client authentication | **client_secret** (bcrypt hashed) | Confidential client — HTTP Basic or POST body |
| Token encryption at rest | **AES-256-GCM** via Cloud KMS | Application-level encryption beyond TDE |
| Signing key rotation | **90 days** (Cloud KMS) | Limits key compromise exposure |
| Encryption key rotation | **90 days** (Cloud KMS auto-rotate) | Automatic, transparent to application |

---

## References

1. **RFC 6749** — The OAuth 2.0 Authorization Framework
2. **RFC 6750** — OAuth 2.0 Bearer Token Usage
3. **RFC 6819** — OAuth 2.0 Threat Model and Security Considerations
4. **RFC 7009** — OAuth 2.0 Token Revocation
5. **RFC 7636** — Proof Key for Code Exchange (PKCE)
6. **RFC 9068** — JSON Web Token (JWT) Profile for OAuth 2.0 Access Tokens
7. **RFC 9449** — OAuth 2.0 Demonstrating Proof of Possession (DPoP)
8. **OAuth 2.0 Security BCP** — draft-ietf-oauth-security-topics
9. **OAuth 2.1 (draft)** — draft-ietf-oauth-v2-1
10. Bertocci, V. & Chiarelli, A. — *OAuth 2.0 and OpenID Connect: The Professional Guide* (2025)
