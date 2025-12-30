-- CarrierGate Schema DDL
-- Source: CarrierGate_MasterContract_v1_3_2025-12-29.md
-- Run order: 1 of 3 (schema.sql → functions.sql → rls_policies.sql)
--
-- RERUNNABLE: Uses IF NOT EXISTS / CREATE OR REPLACE where possible

-- =============================================================================
-- EXTENSIONS
-- =============================================================================
CREATE EXTENSION IF NOT EXISTS pgcrypto;

-- =============================================================================
-- ENUMS (Section 2.1 - LOCKED)
-- =============================================================================

-- Drop and recreate pattern for enums (safe for fresh install)
DO $$
BEGIN
    IF NOT EXISTS (SELECT 1 FROM pg_type WHERE typname = 'doc_request_status') THEN
        CREATE TYPE public.doc_request_status AS ENUM (
            'OPEN',
            'SUBMITTED',
            'EXPIRED',
            'CANCELED'
        );
    END IF;
END
$$;

DO $$
BEGIN
    IF NOT EXISTS (SELECT 1 FROM pg_type WHERE typname = 'upload_status') THEN
        CREATE TYPE public.upload_status AS ENUM (
            'RECEIVED',
            'QUARANTINED',
            'REJECTED',
            'ACCEPTED'
        );
    END IF;
END
$$;

DO $$
BEGIN
    IF NOT EXISTS (SELECT 1 FROM pg_type WHERE typname = 'upload_event_type') THEN
        CREATE TYPE public.upload_event_type AS ENUM (
            'CREATED',
            'FILE_UPLOADED',
            'STATUS_CHANGED',
            'NOTE_ADDED'
        );
    END IF;
END
$$;

-- =============================================================================
-- TABLES (Section 2.2 - LOCKED)
-- =============================================================================

-- A) api_clients
CREATE TABLE IF NOT EXISTS public.api_clients (
    id uuid PRIMARY KEY DEFAULT gen_random_uuid(),
    name text NOT NULL,
    is_active boolean NOT NULL DEFAULT true,
    created_at timestamptz NOT NULL DEFAULT now()
);

-- B) gate_runs
CREATE TABLE IF NOT EXISTS public.gate_runs (
    id uuid PRIMARY KEY DEFAULT gen_random_uuid(),
    api_client_id uuid NOT NULL REFERENCES public.api_clients(id),
    gate_name text NOT NULL,
    result text NOT NULL CHECK (result IN ('PASS', 'FAIL')),
    reason text,
    created_at timestamptz NOT NULL DEFAULT now()
);

-- C) doc_requests
CREATE TABLE IF NOT EXISTS public.doc_requests (
    id uuid PRIMARY KEY DEFAULT gen_random_uuid(),
    broker_org_id uuid NOT NULL,
    carrier_org_id uuid,
    verification_id uuid NOT NULL,
    required_docs jsonb NOT NULL,
    status public.doc_request_status NOT NULL DEFAULT 'OPEN',
    expires_at timestamptz NOT NULL,
    submitted_at timestamptz,
    created_at timestamptz NOT NULL DEFAULT now(),
    updated_at timestamptz NOT NULL DEFAULT now()
);

-- D) doc_request_tokens
CREATE TABLE IF NOT EXISTS public.doc_request_tokens (
    id uuid PRIMARY KEY DEFAULT gen_random_uuid(),
    doc_request_id uuid NOT NULL REFERENCES public.doc_requests(id) ON DELETE CASCADE,
    token_hash text NOT NULL UNIQUE,
    expires_at timestamptz NOT NULL,
    used_at timestamptz,
    is_revoked boolean NOT NULL DEFAULT false,
    created_at timestamptz NOT NULL DEFAULT now()
);

-- E) uploads
CREATE TABLE IF NOT EXISTS public.uploads (
    id uuid PRIMARY KEY DEFAULT gen_random_uuid(),
    doc_request_id uuid NOT NULL REFERENCES public.doc_requests(id) ON DELETE CASCADE,
    doc_type text NOT NULL,
    storage_bucket text NOT NULL,
    storage_path text NOT NULL,
    file_name text,
    content_type text,
    byte_size bigint,
    sha256 text,
    status public.upload_status NOT NULL DEFAULT 'RECEIVED',
    created_at timestamptz NOT NULL DEFAULT now(),
    updated_at timestamptz NOT NULL DEFAULT now(),
    CONSTRAINT uploads_doc_request_doc_type_key UNIQUE (doc_request_id, doc_type)
);

-- F) upload_events
CREATE TABLE IF NOT EXISTS public.upload_events (
    id uuid PRIMARY KEY DEFAULT gen_random_uuid(),
    upload_id uuid NOT NULL REFERENCES public.uploads(id) ON DELETE CASCADE,
    event_type public.upload_event_type NOT NULL,
    actor_type text NOT NULL CHECK (actor_type IN ('BROKER', 'CARRIER', 'SYSTEM', 'API')),
    actor_id uuid,
    note text,
    created_at timestamptz NOT NULL DEFAULT now()
);

-- =============================================================================
-- INDEXES (for common query patterns)
-- =============================================================================

CREATE INDEX IF NOT EXISTS idx_doc_requests_broker_org_id ON public.doc_requests(broker_org_id);
CREATE INDEX IF NOT EXISTS idx_doc_requests_status ON public.doc_requests(status);
CREATE INDEX IF NOT EXISTS idx_doc_requests_expires_at ON public.doc_requests(expires_at);
CREATE INDEX IF NOT EXISTS idx_doc_request_tokens_doc_request_id ON public.doc_request_tokens(doc_request_id);
CREATE INDEX IF NOT EXISTS idx_uploads_doc_request_id ON public.uploads(doc_request_id);
CREATE INDEX IF NOT EXISTS idx_upload_events_upload_id ON public.upload_events(upload_id);

-- =============================================================================
-- TRIGGERS: updated_at auto-update
-- =============================================================================

CREATE OR REPLACE FUNCTION public.set_updated_at()
RETURNS TRIGGER AS $$
BEGIN
    NEW.updated_at = now();
    RETURN NEW;
END;
$$ LANGUAGE plpgsql;

DROP TRIGGER IF EXISTS set_doc_requests_updated_at ON public.doc_requests;
CREATE TRIGGER set_doc_requests_updated_at
    BEFORE UPDATE ON public.doc_requests
    FOR EACH ROW
    EXECUTE FUNCTION public.set_updated_at();

DROP TRIGGER IF EXISTS set_uploads_updated_at ON public.uploads;
CREATE TRIGGER set_uploads_updated_at
    BEFORE UPDATE ON public.uploads
    FOR EACH ROW
    EXECUTE FUNCTION public.set_updated_at();
