-- CarrierGate RLS Policies
-- Source: CarrierGate_MasterContract_v1_3_2025-12-29.md
-- Run order: 3 of 3 (schema.sql → functions.sql → rls_policies.sql)
--
-- Section 7 - RLS Lock:
-- MVP policy model (LOCKED):
-- - Service role performs all writes (service_role bypasses RLS automatically)
-- - Anon can only read doc_request via valid token function return
-- - Broker authenticated role can read doc_requests and uploads scoped by broker_org_id
-- - Carrier never gets direct table access. Carrier uses token function only.
--
-- If auth is not implemented in v1.0:
-- - Use server-only access with service_role key
-- - No client direct reads of tables
-- - All broker views served by server endpoints

-- =============================================================================
-- ENABLE RLS ON ALL TABLES
-- =============================================================================

ALTER TABLE public.api_clients ENABLE ROW LEVEL SECURITY;
ALTER TABLE public.gate_runs ENABLE ROW LEVEL SECURITY;
ALTER TABLE public.doc_requests ENABLE ROW LEVEL SECURITY;
ALTER TABLE public.doc_request_tokens ENABLE ROW LEVEL SECURITY;
ALTER TABLE public.uploads ENABLE ROW LEVEL SECURITY;
ALTER TABLE public.upload_events ENABLE ROW LEVEL SECURITY;

-- =============================================================================
-- DROP EXISTING POLICIES (for rerunnable script)
-- =============================================================================

DROP POLICY IF EXISTS "api_clients_service_role_all" ON public.api_clients;
DROP POLICY IF EXISTS "gate_runs_service_role_all" ON public.gate_runs;
DROP POLICY IF EXISTS "doc_requests_service_role_all" ON public.doc_requests;
DROP POLICY IF EXISTS "doc_request_tokens_service_role_all" ON public.doc_request_tokens;
DROP POLICY IF EXISTS "uploads_service_role_all" ON public.uploads;
DROP POLICY IF EXISTS "upload_events_service_role_all" ON public.upload_events;

-- =============================================================================
-- MVP v1.0 POLICIES
-- =============================================================================
-- For MVP, all access is via server endpoints using service_role key.
-- Service role bypasses RLS automatically.
-- These policies ensure no direct access from anon or authenticated roles.
--
-- Note: The SECURITY DEFINER functions (F1-F6) execute with the definer's
-- privileges and can access tables regardless of RLS policies.

-- api_clients: No direct access (service_role only)
CREATE POLICY "api_clients_deny_all"
ON public.api_clients
FOR ALL
TO anon, authenticated
USING (false)
WITH CHECK (false);

-- gate_runs: No direct access (service_role only)
CREATE POLICY "gate_runs_deny_all"
ON public.gate_runs
FOR ALL
TO anon, authenticated
USING (false)
WITH CHECK (false);

-- doc_requests: No direct access (service_role only)
-- Carrier access is via get_doc_request_by_token function
-- Broker access is via server endpoints
CREATE POLICY "doc_requests_deny_all"
ON public.doc_requests
FOR ALL
TO anon, authenticated
USING (false)
WITH CHECK (false);

-- doc_request_tokens: No direct access (service_role only)
CREATE POLICY "doc_request_tokens_deny_all"
ON public.doc_request_tokens
FOR ALL
TO anon, authenticated
USING (false)
WITH CHECK (false);

-- uploads: No direct access (service_role only)
-- Broker access is via server endpoints
CREATE POLICY "uploads_deny_all"
ON public.uploads
FOR ALL
TO anon, authenticated
USING (false)
WITH CHECK (false);

-- upload_events: No direct access (service_role only)
CREATE POLICY "upload_events_deny_all"
ON public.upload_events
FOR ALL
TO anon, authenticated
USING (false)
WITH CHECK (false);

-- =============================================================================
-- FUTURE: Broker-scoped read policies (when auth is implemented)
-- =============================================================================
-- Uncomment and modify when broker authentication is added:
--
-- CREATE POLICY "doc_requests_broker_select"
-- ON public.doc_requests
-- FOR SELECT
-- TO authenticated
-- USING (broker_org_id = auth.uid());
--
-- CREATE POLICY "uploads_broker_select"
-- ON public.uploads
-- FOR SELECT
-- TO authenticated
-- USING (
--     doc_request_id IN (
--         SELECT id FROM public.doc_requests
--         WHERE broker_org_id = auth.uid()
--     )
-- );
