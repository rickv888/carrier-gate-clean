-- CarrierGate rls.sql
-- Master Contract v1.0 (MODEL A, LOCKED)
-- Rerunnable and safe for Supabase Postgres

-- ============================================================
-- ROW LEVEL SECURITY (Section 7 LOCKED)
-- ============================================================
--
-- MVP policy model (v1.0 server-only access):
-- - RLS enabled on all tables (deny by default for non-service-role)
-- - Service role performs all writes (bypasses RLS by default)
-- - Anon reads doc_request via SECURITY DEFINER function only
-- - Carrier uses token function only (no direct table access)
-- - All broker views served by server endpoints using service_role
--
-- NOTE: Broker authenticated role policies are deferred until auth
-- is implemented. When implemented, will require specification of
-- how broker_org_id is determined for the authenticated user.
-- ============================================================

-- Enable RLS on all public tables
-- When RLS is enabled with no policies, access is denied by default
-- for all roles except service_role (which bypasses RLS)

ALTER TABLE public.api_clients ENABLE ROW LEVEL SECURITY;
ALTER TABLE public.gate_runs ENABLE ROW LEVEL SECURITY;
ALTER TABLE public.doc_requests ENABLE ROW LEVEL SECURITY;
ALTER TABLE public.doc_request_tokens ENABLE ROW LEVEL SECURITY;
ALTER TABLE public.uploads ENABLE ROW LEVEL SECURITY;
ALTER TABLE public.upload_events ENABLE ROW LEVEL SECURITY;

-- ============================================================
-- POLICY NOTES (per contract Section 7)
-- ============================================================
--
-- For v1.0 with server-only access (service_role key):
-- - No explicit policies required
-- - service_role bypasses RLS entirely
-- - anon/authenticated roles are denied by default (RLS enabled, no policies)
-- - All data access goes through API endpoints using service_role
-- - SECURITY DEFINER functions (e.g., get_doc_request_by_token) bypass RLS
--
-- Future auth implementation will require:
-- 1. Specification of how broker_org_id maps to authenticated users
-- 2. SELECT policy on doc_requests for authenticated WHERE broker_org_id = <user's org>
-- 3. SELECT policy on uploads for authenticated via doc_requests join
-- ============================================================
