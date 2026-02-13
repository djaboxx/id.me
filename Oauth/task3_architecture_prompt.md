# Task 3: Architecture Diagram — Image Generation Prompt

> **Purpose:** This file contains a comprehensive prompt designed to guide an image-generating LLM (e.g., GPT-4o with image generation, Gemini, DALL·E 3, Midjourney) to produce a detailed, professional architecture diagram for the secure OAuth 2.0 partner integration platform.

---

## Prompt

Create a detailed, professional **architecture diagram** in a clean technical illustration style (similar to Google Cloud architecture diagrams or AWS reference architectures). The diagram should use a white background with clearly labeled components, directional arrows showing data flow, and color-coded zones for different security boundaries. Use a landscape orientation. The style should be flat/modern with rounded rectangles for services, shield icons for security checks, and lock icons for encryption points.

### Overall Layout — Three Horizontal Swim Lanes

The diagram has **three horizontal swim lanes** (top to bottom):

1. **Partner / External Zone** (light red/coral background band) — contains the Partner SaaS Application and the User's Browser
2. **Apigee API Gateway Zone** (light blue background band) — contains the Apigee API proxy layer sitting between external and internal traffic
3. **GCP Internal Zone** (light green background band) — contains Cloud Run services, Cloud SQL, Cloud KMS, Secret Manager, and Memorystore (Redis)

---

### Components to Draw

#### Partner / External Zone (top lane)

- **Partner SaaS Application** — a rounded rectangle labeled "Partner SaaS App" with a small server icon. Show a callout: "Generates PKCE code_verifier + code_challenge, stores state parameter in session"
- **User Browser** — a rounded rectangle with a browser icon, labeled "User Browser"

#### Apigee API Gateway Zone (middle lane)

- **Apigee API Proxy** — a large rounded rectangle labeled "Apigee API Gateway" with the Google Cloud Apigee logo. Inside this box, show **five stacked policy blocks** (small rectangles inside the Apigee box):
  1. **Spike Arrest / Rate Limiting** — labeled "Rate Limit: 60 req/min per client_id"
  2. **OAuthV2 Policy — Token Verification** — labeled "OAuthV2 VerifyAccessToken" with a small shield icon
  3. **IP Allowlist / mTLS** — labeled "IP Allowlist + mTLS Termination"
  4. **Scope Enforcement** — labeled "Scope Check: token.scope ⊇ endpoint.required_scope"
  5. **Threat Protection** — labeled "JSON/XML Threat Protection, Input Validation"
- Show a callout outside the Apigee box: "All external API traffic passes through Apigee before reaching Cloud Run"
- Show **two entry arrows** into Apigee from the top lane: one from Partner SaaS App, one from User Browser

#### GCP Internal Zone (bottom lane)

- **Cloud Run — Authorization Server** — a rounded rectangle with the Cloud Run logo, labeled "Authorization Server (Cloud Run)". Show callouts: "Handles /oauth/authorize, /oauth/token, /oauth/revoke"
- **Cloud Run — Resource Server** — a separate rounded rectangle with Cloud Run logo, labeled "Resource API Server (Cloud Run)". Show callout: "Serves /api/v1/* endpoints, validates JWT locally"
- **Cloud SQL (PostgreSQL)** — a database cylinder icon labeled "Cloud SQL (PostgreSQL)". Inside or next to it, list the tables: "oauth_clients, oauth_authorization_codes, oauth_refresh_tokens, oauth_access_token_revocations, oauth_consent_records"
- **GCP Cloud KMS** — a key icon with a rounded rectangle, labeled "Cloud KMS". Show callouts: "AES-256-GCM token encryption, RS256 JWT signing keys, Auto-rotation every 90 days"
- **GCP Secret Manager** — a lock icon with rounded rectangle, labeled "Secret Manager". Callout: "Stores client_secrets, DB credentials, API keys"
- **Memorystore (Redis)** — a rounded rectangle with Redis icon, labeled "Memorystore (Redis)". Callout: "Access token revocation list (JTI blocklist), TTL = 15 min"

---

### The OAuth Flow — Numbered Arrows

Draw the following **numbered arrows** across the swim lanes to show the complete authorization code flow with PKCE. Each arrow should have a number and a short label:

**Arrow 1:** Partner SaaS App → User Browser  
Label: "1. Redirect to /oauth/authorize with client_id, redirect_uri, scope, state, code_challenge (S256)"

**Arrow 2:** User Browser → Apigee API Gateway  
Label: "2. GET /oauth/authorize (passes through Apigee)"

**Arrow 3:** Apigee API Gateway → Cloud Run Authorization Server  
Label: "3. Forward to Authorization Server (rate-limited, threat-protected)"

**Arrow 4:** Cloud Run Authorization Server → User Browser  
Label: "4. Display consent screen (shows partner name + requested scopes)"

**Arrow 5:** User Browser → Cloud Run Authorization Server (via Apigee)  
Label: "5. User approves — server generates single-use auth code (10-min expiry)"

**Arrow 6:** Cloud Run Authorization Server → Cloud SQL  
Label: "6. Store SHA-256(code) + code_challenge + client_id + redirect_uri + scope + user_id"  
Add a **shield icon** with label: "🛡 Auth Code Replay Prevention: code stored as hash, marked single-use, 10-min TTL"

**Arrow 7:** Cloud Run Authorization Server → User Browser → Partner SaaS App  
Label: "7. 302 Redirect to redirect_uri?code=AUTH_CODE&state=STATE"  
Add a **shield icon** with label: "🛡 redirect_uri Validation: exact string match against pre-registered URIs for this client_id"

**Arrow 8:** Partner SaaS App → Apigee API Gateway  
Label: "8. POST /oauth/token with code, code_verifier, client_id, client_secret, redirect_uri"

**Arrow 9:** Apigee API Gateway → Cloud Run Authorization Server  
Label: "9. Forward token request (client authenticated via HTTP Basic)"

**Arrow 10:** Cloud Run Authorization Server → Cloud SQL  
Label: "10. Lookup code_hash, verify single-use, verify expiry"

**Arrow 11:** Cloud Run Authorization Server (internal process)  
Label: "11. PKCE Verification: BASE64URL(SHA256(code_verifier)) == stored code_challenge"  
Add a **shield icon** with label: "🛡 PKCE (S256): Proves the entity redeeming the code is the same one that initiated the request"

**Arrow 12:** Cloud Run Authorization Server → Cloud KMS  
Label: "12. Encrypt refresh token with AES-256-GCM, sign access token JWT with RS256"

**Arrow 13:** Cloud Run Authorization Server → Cloud SQL  
Label: "13. Store encrypted refresh token + SHA-256 hash + token_family_id. Mark auth code as USED."

**Arrow 14:** Cloud Run Authorization Server → Partner SaaS App (via Apigee)  
Label: "14. Return { access_token (JWT, 15-min), refresh_token (opaque, 90-day), scope, expires_in }"

**Arrow 15:** Partner SaaS App → Apigee API Gateway  
Label: "15. API Request: GET /api/v1/verifications with Authorization: Bearer <JWT>"

**Arrow 16:** Apigee API Gateway (internal)  
Label: "16. Apigee validates: rate limit → OAuthV2 verify → scope check → threat protection"

**Arrow 17:** Apigee API Gateway → Cloud Run Resource Server  
Label: "17. Forward validated request to Resource API"

**Arrow 18:** Cloud Run Resource Server → Memorystore (Redis)  
Label: "18. Check JTI against revocation blocklist (fast in-memory lookup)"

**Arrow 19:** Cloud Run Resource Server → Partner SaaS App (via Apigee)  
Label: "19. Return API response (200 OK with data scoped to user_id from JWT sub claim)"

---

### Security Checkpoints — Call Out Boxes

Place these **five security callout boxes** at appropriate positions on the diagram, connected to the relevant arrows with dotted lines. Each box should have a shield icon and a colored border (red for critical):

#### Callout Box 1: PKCE Protection (near Arrows 1, 8, 11)
```
🛡 PKCE (Proof Key for Code Exchange)
━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━
• Client generates code_verifier (43-128 chars, cryptographic random)
• Sends code_challenge = BASE64URL(SHA256(code_verifier)) at /authorize
• Proves possession of code_verifier at /token
• Prevents authorization code interception (RFC 7636)
• S256 method REQUIRED — plain method is rejected
```

#### Callout Box 2: Authorization Code Replay Prevention (near Arrow 6, 10)
```
🛡 Auth Code Replay Prevention
━━━━━━━━━━━━━━━━━━━━━━━━━━━━━
• Code stored as SHA-256 hash (not plaintext)
• Single-use enforcement: used_at timestamp set on first redemption
• 10-minute maximum lifetime (RFC 6749 §4.1.2)
• If replayed: REJECT + REVOKE all tokens from that code
• Bound to: client_id, redirect_uri, user_id, code_challenge
```

#### Callout Box 3: redirect_uri Validation (near Arrow 7)
```
🛡 redirect_uri Validation
━━━━━━━━━━━━━━━━━━━━━━━━━
• Pre-registered in oauth_clients.redirect_uris array
• EXACT string match — no wildcard, no subdirectory matching
• Validated at BOTH /authorize (initial request) AND /token (redemption)
• Mismatch → immediate rejection (400 Bad Request)
• Prevents authorization code hijacking via open redirectors
```

#### Callout Box 4: Refresh Token Rotation & Theft Detection (between Cloud SQL and Auth Server)
```
🛡 Refresh Token Rotation
━━━━━━━━━━━━━━━━━━━━━━━━
• Every refresh: old token invalidated, new token issued
• Token family tracking: all tokens from one grant share family_id
• THEFT DETECTION: replayed used token → revoke ENTIRE family
• Absolute lifetime: 90 days | Idle timeout: 14 days
• AES-256-GCM encrypted at rest (Cloud KMS)
```

#### Callout Box 5: Token Storage Security (near Cloud SQL and Cloud KMS)
```
🔒 Token Storage Security
━━━━━━━━━━━━━━━━━━━━━━━━━
• Refresh tokens: AES-256-GCM encrypted + SHA-256 hashed
• Access tokens (JWT): NOT stored in DB — signed & validated locally
• Auth codes: SHA-256 hashed only (short-lived)
• Client secrets: bcrypt hashed
• Encryption keys in Cloud KMS (HSM-backed, auto-rotated)
• DB admin cannot read tokens without KMS access
```

---

### Visual Style Notes

- Use **Google Cloud product icons** for Cloud Run, Cloud SQL, Cloud KMS, Secret Manager, and Memorystore
- Use the **Apigee logo** (hexagonal) for the API Gateway
- Color scheme: 
  - External zone: light coral/red (#FFE0E0)
  - Apigee zone: light blue (#E0F0FF)  
  - GCP internal zone: light green (#E0FFE0)
  - Security callout borders: red (#D32F2F) with shield icon
  - Encryption operations: gold/amber (#FFA000) with lock icon
  - Normal flow arrows: dark blue (#1565C0)
  - Security check arrows: red (#D32F2F) with dashed lines
- All text should be legible at standard document zoom level
- Include a **legend** in the bottom-right corner explaining:
  - Solid blue arrows = data flow
  - Dashed red arrows = security verification
  - Shield icons = security checkpoint
  - Lock icons = encryption operation
  - Key icons = key management
- Include a **title** at the top: "Secure OAuth 2.0 Partner Integration Platform — Architecture Diagram"
- Include a **subtitle**: "Authorization Code Flow with PKCE | GCP + Apigee | Defense in Depth"

---

### Diagram Dimensions & Quality

- Target resolution: 4000×2500 pixels minimum (high-res for printing/presentation)
- Landscape orientation
- Leave adequate whitespace between components for readability
- Ensure all arrow labels are readable and not overlapping
- Group related components visually (e.g., Cloud KMS and Secret Manager near each other)

---

## Summary of What This Diagram Must Show

| Requirement (from Task 3) | Where It Appears in the Diagram |
|---|---|
| **OAuth flow with all security checks** | Arrows 1–19 with PKCE, state, scope validation at each step |
| **Where Apigee fits** | Middle swim lane — all external traffic passes through Apigee before reaching Cloud Run; five policy blocks shown |
| **GCP services involved** | Bottom lane: Cloud Run (x2), Cloud SQL, Cloud KMS, Secret Manager, Memorystore (Redis) |
| **How you'd prevent authorization code replay attacks** | Arrow 6 + Callout Box 2: SHA-256 hashed, single-use, 10-min TTL, replay triggers full family revocation |
| **How you'd validate redirect_uri** | Arrow 7 + Callout Box 3: exact string match against pre-registered URIs, validated at both /authorize and /token |
