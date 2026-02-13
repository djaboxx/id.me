# Task 1: OAuth 2.0 Implementation Security Review — Vulnerability Analysis

## Executive Summary

This report identifies **three critical vulnerabilities** in the proposed OAuth 2.0 partner integration platform design. The analysis is grounded in OAuth 2.0 security best practices as defined by [RFC 6749](https://tools.ietf.org/html/rfc6749), [RFC 6819](https://tools.ietf.org/html/rfc6819) (OAuth 2.0 Threat Model), the [OAuth 2.0 Security Best Current Practice (BCP)](https://datatracker.ietf.org/doc/html/draft-ietf-oauth-security-topics), [RFC 7636](https://tools.ietf.org/html/rfc7636) (PKCE), and the professional guidance from *OAuth 2.0 and OpenID Connect: The Professional Guide* by Vittorio Bertocci.

---

## Proposed Design Under Review

| Component | Value |
|---|---|
| Authorization Endpoint | `/oauth/authorize` |
| Token Endpoint | `/oauth/token` |
| Access Token Lifetime | 30 days |
| Refresh Token Lifetime | Never expires |
| Token Format | Random UUID v4 |
| Token Storage | Cloud SQL — plaintext `VARCHAR(255)` columns |
| Infrastructure | GCP (Cloud Run, Cloud SQL) |

### Authorization Flow (as proposed)

```
1. Partner → /oauth/authorize?client_id=ABC&redirect_uri=https://partner.com/callback
2. User approves access
3. Redirect → https://partner.com/callback?code=AUTH_CODE_123
4. Partner exchanges code for tokens at /oauth/token
```

### Token Storage Schema (as proposed)

```sql
CREATE TABLE oauth_tokens (
  id SERIAL PRIMARY KEY,
  client_id VARCHAR(255),
  access_token VARCHAR(255),
  refresh_token VARCHAR(255),
  user_id VARCHAR(255),
  scope TEXT,
  expires_at TIMESTAMP,
  created_at TIMESTAMP
);
```

---

## Vulnerability 1: Missing PKCE — Authorization Code Interception Attack

### Severity: **CRITICAL**

### Description

The proposed authorization flow lacks **Proof Key for Code Exchange (PKCE)** as defined in [RFC 7636](https://tools.ietf.org/html/rfc7636). The authorization request contains only `client_id` and `redirect_uri` — there is no `code_challenge` or `code_verifier` parameter.

Without PKCE, the authorization code is vulnerable to interception during transit between the authorization server and the client application. An attacker who intercepts the authorization code (e.g., via an open redirect, a compromised redirect URI, browser history exposure, or referrer header leakage) can exchange it for valid access and refresh tokens at the `/oauth/token` endpoint.

### Why This Matters for This Platform

The platform will support **100+ third-party integrations**. Each partner registers its own `redirect_uri`. The larger the number of partners, the greater the attack surface for:

- **Redirect URI manipulation** — A partner with a misconfigured or overly permissive redirect URI pattern creates an opening for code theft.
- **Authorization code replay** — Without PKCE, there is no cryptographic binding between the entity that *requested* the code and the entity that *redeems* it.

### Professional Guide Reference

> *"The application must demonstrate knowledge of that secret at code redemption time. As a result, if anyone steals the code in transit, they will not be able to use it without knowledge of this secret."*
> — Chapter 5: Meet the PKCE

> *"The latest OAuth 2.0 Security Best Current Practice (BCP) documents suggest that every Authorization Code flow should leverage Proof Key for Code Exchange (RFC 7636)."*
> — Chapter 4: Authorization Code Grant and PKCE

> *"OAuth 2.1 recommends using PKCE with confidential clients, too."*
> — Chapter 4: ID Tokens and the Back Channel

### RFC References

- **RFC 7636** — Proof Key for Code Exchange by OAuth Public Clients
- **OAuth 2.0 Security BCP** — Section 2.1.1: Recommends PKCE for ALL clients (confidential and public)
- **OAuth 2.1 (draft)** — Mandates PKCE for every authorization code flow

### Remediation

The authorization request must include PKCE parameters:

```
/oauth/authorize?
  client_id=ABC
  &redirect_uri=https://partner.com/callback
  &response_type=code
  &code_challenge=E9Melhoa2OwvFrEMTJguCHaoeK1t8URWbuGJSstw-cM
  &code_challenge_method=S256
  &state=xyz123
```

At the token endpoint, the partner must present the `code_verifier`:

```
POST /oauth/token
  grant_type=authorization_code
  &code=AUTH_CODE_123
  &redirect_uri=https://partner.com/callback
  &client_id=ABC
  &client_secret=<secret>
  &code_verifier=dBjftJeZ4CVP-mB92K27uhbUJU1p1r_wW1gFWFOEjXk
```

The authorization server must:
1. Reject any authorization code request that does not include `code_challenge`
2. Validate `code_verifier` against the stored `code_challenge` at token redemption
3. Use `S256` as the code challenge method (do not allow `plain`)

---

## Vulnerability 2: Non-Expiring Refresh Tokens with No Rotation Strategy

### Severity: **CRITICAL**

### Description

The proposed design specifies:

- **Access token lifetime: 30 days**
- **Refresh token lifetime: Never expires**

Both values violate OAuth 2.0 security best practices:

**30-day access tokens** are excessively long-lived. Access tokens are bearer tokens — anyone in possession of the token bits can use them. Per the professional guide: *"If you have the bits of a token in your possession, you are entitled to use the token"* (Chapter 3: Subject Confirmation). A 30-day window provides an attacker an enormous exploitation window if a token is compromised.

**Non-expiring refresh tokens** are the more severe issue. A single compromised refresh token grants an attacker **permanent, indefinite access** to a user's data. There is no natural point at which the token becomes invalid, meaning the only remediation is manual detection and revocation — which may never happen.

### Why This Matters for This Platform

The platform handles **customer verification history and documents** — highly sensitive PII data. A leaked refresh token from any of 100+ partner integrations grants perpetual access to this data with no expiration forcing re-authorization.

### Professional Guide Reference

> *"Tokens typically have an expiration time. They have an expiration time because a token caches a number of facts and user attributes, and those facts might change after the token has been issued."*
> — Chapter 4: The Refresh Token Grant

> *"The shorter the token validity interval, the more up-to-date the issued information will be."*
> — Chapter 4: The Refresh Token Grant

> *"Token rotation guarantees that whenever you use a refresh token, the bits of that particular refresh token will no longer work for any future redemption attempts. Every use of a refresh token will cause the authorization server to invalidate it and issue a new one... Any attempt to use an old refresh token will cause the authorization server to conclude that the request originator stole it."*
> — Chapter 4: Token Rotation

> *"Persisting refresh tokens (and tokens in general) requires caution."*
> — Chapter 4: Some Considerations on Refresh Tokens

### RFC References

- **RFC 6749 §10.4** — Refresh tokens MUST be bound to the client and SHOULD have a limited lifetime
- **RFC 6819 §4.5.2** — Threat: Obtaining Refresh Tokens (recommends rotation and lifetime limits)
- **OAuth 2.0 Security BCP §4.13** — Recommends refresh token rotation for every client type

### Remediation

| Token | Current | Recommended |
|---|---|---|
| Access Token Lifetime | 30 days | **15 minutes to 1 hour** |
| Refresh Token Lifetime | Never expires | **Absolute: 30-90 days, Idle: 7-14 days** |
| Refresh Token Rotation | Not implemented | **Mandatory — issue new refresh token on every use** |

Implement **refresh token rotation**:
- On every refresh token redemption, invalidate the old refresh token and issue a new one
- If a previously invalidated refresh token is presented, treat it as a **token theft signal** and revoke the entire token family (all tokens issued in that grant session)
- Store a `token_family_id` to track lineage and enable family-wide revocation

Updated schema should include:

```sql
refresh_token_family_id UUID,          -- tracks token lineage for rotation
refresh_token_used_at TIMESTAMP,       -- detect replay of rotated tokens
absolute_expires_at TIMESTAMP,         -- hard expiration regardless of activity
idle_expires_at TIMESTAMP              -- expiration if not used within window
```

---

## Vulnerability 3: Plaintext Token Storage — No Encryption at Rest

### Severity: **HIGH**

### Description

The proposed schema stores `access_token` and `refresh_token` as **plaintext `VARCHAR(255)`** columns in Cloud SQL:

```sql
access_token VARCHAR(255),
refresh_token VARCHAR(255),
```

This means that anyone with database read access — whether through a SQL injection vulnerability, a compromised database backup, an insider threat, or a misconfigured IAM policy on GCP — can directly read and use every token in the system.

Since tokens are **bearer tokens** (per the professional guide: *"If you have the bits of a token in your possession, you are entitled to use the token"*), a database breach immediately becomes a mass credential compromise across all 100+ partner integrations and all users.

### Why This Matters for This Platform

- **100+ third-party integrations** — a single database breach compromises tokens for every partner and every user simultaneously
- **GCP Cloud SQL** — while Cloud SQL supports encryption at rest at the storage layer (transparent disk encryption), this does NOT protect against application-level database access (e.g., SQL injection, compromised service accounts, or admin access)
- **Customer verification history and documents** — the data accessible via these tokens is highly sensitive identity verification data

### Professional Guide Reference

> *"It's important to make sure that tokens are stored per user to prevent the possibility of a user ending up accessing and using the refresh tokens associated with another user. That's just the same basic hygiene required to enforce session separation, but when it comes to tokens, following best practices is all the more critical."*
> — Chapter 4: Some Considerations on Refresh Tokens

> *"Once a client requests and obtains an access token, it should keep it around (stored with all the safety measures the task requires) for the duration of its useful lifetime."*
> — Chapter 4: Client Credentials Grant — Important Note

### RFC References

- **RFC 6749 §10.3** — Access tokens MUST be kept confidential in storage and transit
- **RFC 6749 §10.4** — Refresh tokens MUST be kept confidential in storage and transit; authorization server MUST maintain binding between refresh token and client
- **RFC 6819 §5.1.4.1** — Recommends encryption of token storage

### Remediation

**1. Application-Level Encryption (Required)**

Encrypt tokens before writing to the database using **AES-256-GCM** with keys managed by **GCP Secret Manager** or **Cloud KMS**:

```sql
CREATE TABLE oauth_tokens (
  id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
  client_id VARCHAR(255) NOT NULL,
  access_token_encrypted BYTEA NOT NULL,       -- AES-256-GCM encrypted
  refresh_token_hash VARCHAR(64) NOT NULL,      -- SHA-256 hash for lookup
  refresh_token_encrypted BYTEA NOT NULL,       -- AES-256-GCM encrypted
  encryption_key_version INT NOT NULL,          -- for key rotation support
  user_id VARCHAR(255) NOT NULL,
  scope TEXT NOT NULL,
  token_family_id UUID,                         -- for refresh token rotation
  expires_at TIMESTAMP NOT NULL,
  refresh_expires_at TIMESTAMP,
  created_at TIMESTAMP DEFAULT NOW(),
  revoked_at TIMESTAMP,                         -- for token revocation
  CONSTRAINT fk_client FOREIGN KEY (client_id) REFERENCES oauth_clients(client_id)
);

CREATE INDEX idx_refresh_token_hash ON oauth_tokens(refresh_token_hash);
CREATE INDEX idx_client_user ON oauth_tokens(client_id, user_id);
CREATE INDEX idx_token_family ON oauth_tokens(token_family_id);
```

**2. Hash-Based Lookup for Refresh Tokens**

Store a **SHA-256 hash** of the refresh token for lookup purposes. The actual token value is encrypted. This prevents token exposure even in query logs or slow query analysis.

**3. Key Management via GCP Cloud KMS**

- Use Cloud KMS for encryption key lifecycle management
- Implement key rotation with `encryption_key_version` tracking
- Separate encryption keys per environment (dev/staging/prod)
- Restrict Cloud KMS IAM roles to the minimum required service accounts

---

## Additional Observations (Beyond the Three Required)

While the task requires identifying three vulnerabilities, the following issues were also observed and are worth noting:

| Issue | Description | Best Practice |
|---|---|---|
| **No `state` parameter** | Authorization request lacks CSRF protection via the `state` parameter | RFC 6749 §10.12 requires `state` for CSRF mitigation |
| **No `redirect_uri` validation** | No mention of strict `redirect_uri` registration and exact-match validation | *"The redirect URI you specify in the request must be an exact match"* (Professional Guide Ch. 3) |
| **No authorization code expiration** | No mention of code lifetime or single-use enforcement | RFC 6749 §4.1.2: codes MUST expire shortly (recommend ≤ 10 minutes) and MUST be single-use |
| **No `nonce` parameter** | Missing token injection prevention mechanism | OpenID Connect Core §3.1.2.1 |
| **No token revocation endpoint** | No mechanism for partners or users to revoke tokens | RFC 7009: Token Revocation |
| **`VARCHAR(255)` for tokens** | UUID v4 tokens fit, but encrypted tokens or JWTs will exceed 255 characters | Use `BYTEA` or `TEXT` depending on storage format |
| **No `scope` validation** | No mention of validating requested scopes against registered partner permissions | RFC 6749 §3.3 |

---

## Summary Matrix

| # | Vulnerability | Severity | RFC Violation | Attack Vector |
|---|---|---|---|---|
| 1 | Missing PKCE | **CRITICAL** | RFC 7636, OAuth 2.0 BCP, OAuth 2.1 | Authorization code interception and replay |
| 2 | Non-expiring refresh tokens / no rotation | **CRITICAL** | RFC 6749 §10.4, RFC 6819 §4.5.2, OAuth BCP §4.13 | Permanent access via stolen refresh token |
| 3 | Plaintext token storage | **HIGH** | RFC 6749 §10.3, §10.4, RFC 6819 §5.1.4.1 | Mass credential theft via database breach |

---

## References

1. **RFC 6749** — The OAuth 2.0 Authorization Framework
2. **RFC 6819** — OAuth 2.0 Threat Model and Security Considerations
3. **RFC 7636** — Proof Key for Code Exchange (PKCE)
4. **RFC 7009** — OAuth 2.0 Token Revocation
5. **RFC 9449** — OAuth 2.0 Demonstrating Proof of Possession (DPoP)
6. **OAuth 2.0 Security Best Current Practice** — draft-ietf-oauth-security-topics
7. **OAuth 2.1 (draft)** — draft-ietf-oauth-v2-1
8. Bertocci, V. & Chiarelli, A. — *OAuth 2.0 and OpenID Connect: The Professional Guide* (2025)
