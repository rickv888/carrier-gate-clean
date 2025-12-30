# CARRIERGATE MASTER CONTRACT v1.0

**MODEL A, LOCKED**

This document is the sole source of truth. All reasoning, schema, code, and decisions must conform to it. If a conflict or gap exists, execution stops and the gap is reported. Do not invent. Do not merge. Do not "minimum field" anything.

---

## 0) Objective

Build CarrierGate as a broker-side carrier verification and document intake gate with:

1. Broker creates a Doc Request for a carrier
2. System issues a one-time expiring token link to carrier
3. Carrier uploads required documents using signed upload flow
4. Broker reviews and decides accept or reject per document
5. Full audit trail for every action

---

## 1) Stack Lock

- **Backend:** Next.js (App Router) or Express. Pick one and stay consistent.
- **Database:** Supabase Postgres.
- **Storage:** Supabase Storage private buckets.
- **Deploy:** Render or Railway. Do not mix deploy surfaces for MVP.
- No external workflow tools for MVP.

---

## 2) Canonical Data Model

All tables are in `public` schema.

### 2.1 Enums (LOCKED)

**public.doc_request_status:**
- OPEN
- SUBMITTED
- EXPIRED
- CANCELED

**public.upload_status:**
- RECEIVED
- QUARANTINED
- REJECTED
- ACCEPTED

**public.upload_event_type:**
- CREATED
- FILE_UPLOADED
- STATUS_CHANGED
- NOTE_ADDED

### 2.2 Tables (LOCKED)

#### A) api_clients

| Column | Type | Constraints |
|--------|------|-------------|
| id | uuid | PK default gen_random_uuid() |
| name | text | not null |
| is_active | boolean | not null default true |
| created_at | timestamptz | not null default now() |

#### B) gate_runs

| Column | Type | Constraints |
|--------|------|-------------|
| id | uuid | PK default gen_random_uuid() |
| api_client_id | uuid | not null references api_clients(id) |
| gate_name | text | not null |
| result | text | not null check (result in ('PASS','FAIL')) |
| reason | text | |
| created_at | timestamptz | not null default now() |

#### C) doc_requests

| Column | Type | Constraints |
|--------|------|-------------|
| id | uuid | PK default gen_random_uuid() |
| broker_org_id | uuid | not null |
| carrier_org_id | uuid | |
| verification_id | uuid | not null |
| required_docs | jsonb | not null |
| status | public.doc_request_status | not null default 'OPEN' |
| expires_at | timestamptz | not null |
| submitted_at | timestamptz | |
| created_at | timestamptz | not null default now() |
| updated_at | timestamptz | not null default now() |

**Rules:**
- `required_docs` is a JSON array of objects with at least: `{ "doc_type": "cab_card", "required": true }`. Doc types are free text but must be stable across UI and DB.
- `expires_at` is server authoritative.
- Status transitions are enforced by functions only.

#### D) doc_request_tokens

| Column | Type | Constraints |
|--------|------|-------------|
| id | uuid | PK default gen_random_uuid() |
| doc_request_id | uuid | not null references doc_requests(id) on delete cascade |
| token_hash | text | not null unique |
| expires_at | timestamptz | not null |
| used_at | timestamptz | |
| is_revoked | boolean | not null default false |
| created_at | timestamptz | not null default now() |

**Rules:**
- One active token per doc_request at a time.
- `used_at` set once when first successful token resolution happens.

#### E) uploads

| Column | Type | Constraints |
|--------|------|-------------|
| id | uuid | PK default gen_random_uuid() |
| doc_request_id | uuid | not null references doc_requests(id) on delete cascade |
| doc_type | text | not null |
| storage_bucket | text | not null |
| storage_path | text | not null |
| file_name | text | |
| content_type | text | |
| byte_size | bigint | |
| sha256 | text | |
| status | public.upload_status | not null default 'RECEIVED' |
| created_at | timestamptz | not null default now() |
| updated_at | timestamptz | not null default now() |

**Constraints:**
- `unique (doc_request_id, doc_type)` — one latest upload per doc_type per doc_request.

#### F) upload_events

| Column | Type | Constraints |
|--------|------|-------------|
| id | uuid | PK default gen_random_uuid() |
| upload_id | uuid | not null references uploads(id) on delete cascade |
| event_type | public.upload_event_type | not null |
| actor_type | text | not null check (actor_type in ('BROKER','CARRIER','SYSTEM','API')) |
| actor_id | uuid | |
| note | text | |
| created_at | timestamptz | not null default now() |

---

## 3) Storage Lock

**Buckets (private):**
- carrier-uploads
- audit-artifacts

**Path convention (LOCKED):**
```
carrier-uploads/doc_requests/{doc_request_id}/{doc_type}/{upload_id}/{original_filename}
```

No other path formats.

No public objects. No public URLs. All access is via signed URLs or server proxy.

---

## 4) Token Hashing Lock

Token format returned to broker: raw token string. Only hashed token is stored.

**Hash algorithm (LOCKED):**
- `token_hash = lower(hex(sha256(utf8(raw_token))))`
- No salt. No HMAC for v1.0. Keep deterministic and testable.
- Raw token is generated server side using 32 random bytes base64url.

If Supabase SQL cannot do sha256 directly, hashing happens in server code. But hashing method must match exactly.

---

## 5) Status Transition Rules

### Doc Request lifecycle

| Status | Description |
|--------|-------------|
| OPEN | Broker created and still collecting uploads |
| SUBMITTED | Carrier indicates done uploading |
| EXPIRED | System sets when now() > expires_at |
| CANCELED | Broker cancels |

**Allowed transitions (LOCKED):**
- OPEN → SUBMITTED
- OPEN → CANCELED
- OPEN → EXPIRED (system only)
- SUBMITTED → EXPIRED (system only)

No other transitions.

### Upload status lifecycle

| Status | Description |
|--------|-------------|
| RECEIVED | Default on create or file upload |
| QUARANTINED | Optional if automated scan flags |
| ACCEPTED | Broker decision |
| REJECTED | Broker decision |

**Allowed transitions (LOCKED):**
- RECEIVED → ACCEPTED
- RECEIVED → REJECTED
- RECEIVED → QUARANTINED
- QUARANTINED → ACCEPTED
- QUARANTINED → REJECTED

No direct ACCEPTED ↔ REJECTED switches.

Every status change must write an `upload_events` row.

---

## 6) Required DB Functions

All functions are SECURITY DEFINER where appropriate. All must hard fail on invalid state.

### F1) get_doc_request_by_token(raw_token text)

**Returns:** doc_request fields needed for carrier upload page, token metadata for validity check

**Rules:**
- Compute token_hash from raw_token using locked method.
- Fail if token not found, revoked, used, or expired.
- On success, set used_at if null and return doc_request.

### F2) create_doc_request_and_token(broker_org_id uuid, carrier_org_id uuid, verification_id uuid, required_docs jsonb, ttl_minutes int)

**Returns:** doc_request_id, raw_token, expires_at

**Rules:**
- ttl_minutes bounds enforced server side. Default 60. Max 1440.
- Create doc_requests row with expires_at.
- Create doc_request_tokens row with token_hash and same expires_at.

### F3) register_upload(doc_request_id uuid, doc_type text, file_name text, content_type text, byte_size bigint, storage_bucket text, storage_path text, sha256 text)

**Returns:** upload_id

**Rules:**
- Enforce doc_request.status in (OPEN, SUBMITTED) but if SUBMITTED then reject new uploads.
- Upsert by (doc_request_id, doc_type) allowed only if prior status is RECEIVED.
- Create upload_events CREATED or FILE_UPLOADED as needed.

### F4) set_upload_status(upload_id uuid, next_status public.upload_status, note text)

**Returns:** upload

**Rules:**
- Enforce allowed transitions.
- Write upload_events STATUS_CHANGED with note.

### F5) submit_doc_request(doc_request_id uuid)

**Returns:** doc_request

**Rules:**
- Hard fail unless status is OPEN.
- Require that required docs are present as uploads rows.
- Set status SUBMITTED and submitted_at now().

### F6) expire_doc_requests()

**Scheduled job (optional)**

**Rules:**
- Set EXPIRED where now() > expires_at and status not in (EXPIRED, CANCELED).

---

## 7) RLS Lock

RLS enabled on all public tables.

**MVP policy model (LOCKED):**
- Service role performs all writes.
- Anon can only read doc_request via valid token function return.
- Broker authenticated role can read doc_requests and uploads scoped by broker_org_id.
- Carrier never gets direct table access. Carrier uses token function only.

**If auth is not implemented in v1.0:**
- Use server-only access with service_role key.
- No client direct reads of tables.
- All broker views served by server endpoints.

---

## 8) Minimal HTTP Endpoints

| Endpoint | Method | Description |
|----------|--------|-------------|
| /api/doc-requests | POST | Creates doc request and returns broker share link |
| /r/{token} | GET | Carrier upload page. Uses get_doc_request_by_token |
| /api/uploads/signed-url | POST | Returns signed upload URL. Server validates token and doc_type first |
| /api/uploads/complete | POST | Registers upload metadata and sha256, writes uploads row and event |
| /api/doc-requests/{id}/submit | POST | Calls submit_doc_request |
| /api/uploads/{id}/status | POST | Calls set_upload_status |

---

## 9) UI Surfaces

### Broker Portal MVP
- Create doc request form
- View doc request detail
- See required docs checklist
- See upload list with status
- Accept or reject each upload with note
- Submit doc request locked after carrier submits

### Carrier Portal MVP
- Token entry via link
- Upload required docs
- Show per doc_type upload success
- Submit done button triggers submit_doc_request

---

## 10) Smoke Tests Required

| Test | Description |
|------|-------------|
| T1 | Create doc request returns token and link |
| T2 | Token resolves once, then used token blocks |
| T3 | Upload file via signed URL and complete registers upload row |
| T4 | Submit fails if any required doc missing |
| T5 | Broker accept or reject changes upload status and logs event |
| T6 | Expired token blocks |
| T7 | Doc request expires when past expires_at |
| T8 | Canceled doc request blocks carrier actions |

---

## 11) Stop Conditions

Stop when:
- DDL applies cleanly in new Supabase project
- RLS enabled and policies consistent with this contract
- Broker can create and review doc requests
- Carrier can upload and submit via token link
- Audit trail is complete via upload_events
- All smoke tests pass

---

**End of contract.**
