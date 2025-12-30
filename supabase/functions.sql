-- CarrierGate Functions DDL
-- Source: CarrierGate_MasterContract_v1_3_2025-12-29.md
-- Run order: 2 of 3 (schema.sql → functions.sql → rls_policies.sql)
--
-- All functions are SECURITY DEFINER where appropriate.
-- All must hard fail on invalid state.

-- =============================================================================
-- HELPER: Token hash computation (Section 4 - LOCKED)
-- token_hash = lower(hex(sha256(utf8(raw_token))))
-- =============================================================================

CREATE OR REPLACE FUNCTION public.compute_token_hash(raw_token text)
RETURNS text
LANGUAGE sql
IMMUTABLE
AS $$
    SELECT lower(encode(digest(raw_token, 'sha256'), 'hex'));
$$;

-- =============================================================================
-- HELPER: Generate base64url token (32 random bytes)
-- =============================================================================

CREATE OR REPLACE FUNCTION public.generate_raw_token()
RETURNS text
LANGUAGE sql
VOLATILE
AS $$
    SELECT replace(replace(replace(
        encode(gen_random_bytes(32), 'base64'),
        '+', '-'),
        '/', '_'),
        '=', '');
$$;

-- =============================================================================
-- F1) get_doc_request_by_token(raw_token text)
-- =============================================================================
-- Returns: doc_request fields needed for carrier upload page, token metadata
-- Rules:
-- - Compute token_hash from raw_token using locked method
-- - Fail if token not found, revoked, used, or expired
-- - On success, set used_at if null and return doc_request

CREATE OR REPLACE FUNCTION public.get_doc_request_by_token(p_raw_token text)
RETURNS TABLE (
    doc_request_id uuid,
    broker_org_id uuid,
    carrier_org_id uuid,
    verification_id uuid,
    required_docs jsonb,
    status public.doc_request_status,
    expires_at timestamptz,
    submitted_at timestamptz,
    created_at timestamptz,
    token_id uuid,
    token_used_at timestamptz
)
LANGUAGE plpgsql
SECURITY DEFINER
AS $$
DECLARE
    v_token_hash text;
    v_token record;
    v_doc_request record;
BEGIN
    -- Compute hash
    v_token_hash := public.compute_token_hash(p_raw_token);

    -- Find token
    SELECT * INTO v_token
    FROM public.doc_request_tokens t
    WHERE t.token_hash = v_token_hash;

    IF NOT FOUND THEN
        RAISE EXCEPTION 'Token not found';
    END IF;

    -- Check if revoked
    IF v_token.is_revoked THEN
        RAISE EXCEPTION 'Token has been revoked';
    END IF;

    -- Check if expired
    IF v_token.expires_at < now() THEN
        RAISE EXCEPTION 'Token has expired';
    END IF;

    -- Check if already used
    IF v_token.used_at IS NOT NULL THEN
        RAISE EXCEPTION 'Token has already been used';
    END IF;

    -- Get doc_request
    SELECT * INTO v_doc_request
    FROM public.doc_requests dr
    WHERE dr.id = v_token.doc_request_id;

    IF NOT FOUND THEN
        RAISE EXCEPTION 'Doc request not found';
    END IF;

    -- Check doc_request not expired or canceled
    IF v_doc_request.status IN ('EXPIRED', 'CANCELED') THEN
        RAISE EXCEPTION 'Doc request is %', v_doc_request.status;
    END IF;

    -- Mark token as used (first successful resolution)
    UPDATE public.doc_request_tokens
    SET used_at = now()
    WHERE id = v_token.id;

    -- Return result
    RETURN QUERY
    SELECT
        v_doc_request.id,
        v_doc_request.broker_org_id,
        v_doc_request.carrier_org_id,
        v_doc_request.verification_id,
        v_doc_request.required_docs,
        v_doc_request.status,
        v_doc_request.expires_at,
        v_doc_request.submitted_at,
        v_doc_request.created_at,
        v_token.id,
        now();  -- token_used_at is now
END;
$$;

-- =============================================================================
-- F2) create_doc_request_and_token(...)
-- =============================================================================
-- Returns: doc_request_id, raw_token, expires_at
-- Rules:
-- - ttl_minutes bounds: default 60, max 1440
-- - Create doc_requests row with expires_at
-- - Create doc_request_tokens row with token_hash and same expires_at

CREATE OR REPLACE FUNCTION public.create_doc_request_and_token(
    p_broker_org_id uuid,
    p_carrier_org_id uuid,
    p_verification_id uuid,
    p_required_docs jsonb,
    p_ttl_minutes int DEFAULT 60
)
RETURNS TABLE (
    doc_request_id uuid,
    raw_token text,
    expires_at timestamptz
)
LANGUAGE plpgsql
SECURITY DEFINER
AS $$
DECLARE
    v_ttl_minutes int;
    v_expires_at timestamptz;
    v_doc_request_id uuid;
    v_raw_token text;
    v_token_hash text;
BEGIN
    -- Enforce ttl_minutes bounds
    v_ttl_minutes := COALESCE(p_ttl_minutes, 60);
    IF v_ttl_minutes < 1 THEN
        v_ttl_minutes := 60;
    END IF;
    IF v_ttl_minutes > 1440 THEN
        v_ttl_minutes := 1440;
    END IF;

    -- Calculate expiration
    v_expires_at := now() + (v_ttl_minutes || ' minutes')::interval;

    -- Generate raw token
    v_raw_token := public.generate_raw_token();
    v_token_hash := public.compute_token_hash(v_raw_token);

    -- Create doc_request
    INSERT INTO public.doc_requests (
        broker_org_id,
        carrier_org_id,
        verification_id,
        required_docs,
        expires_at
    ) VALUES (
        p_broker_org_id,
        p_carrier_org_id,
        p_verification_id,
        p_required_docs,
        v_expires_at
    )
    RETURNING id INTO v_doc_request_id;

    -- Create token
    INSERT INTO public.doc_request_tokens (
        doc_request_id,
        token_hash,
        expires_at
    ) VALUES (
        v_doc_request_id,
        v_token_hash,
        v_expires_at
    );

    -- Return result
    RETURN QUERY SELECT v_doc_request_id, v_raw_token, v_expires_at;
END;
$$;

-- =============================================================================
-- F3) register_upload(...)
-- =============================================================================
-- Returns: upload_id
-- Rules:
-- - Enforce doc_request.status = OPEN (reject if SUBMITTED)
-- - Upsert by (doc_request_id, doc_type) only if prior status is RECEIVED
-- - Create upload_events CREATED or FILE_UPLOADED as needed

CREATE OR REPLACE FUNCTION public.register_upload(
    p_doc_request_id uuid,
    p_doc_type text,
    p_file_name text,
    p_content_type text,
    p_byte_size bigint,
    p_storage_bucket text,
    p_storage_path text,
    p_sha256 text
)
RETURNS uuid
LANGUAGE plpgsql
SECURITY DEFINER
AS $$
DECLARE
    v_doc_request record;
    v_existing_upload record;
    v_upload_id uuid;
    v_event_type public.upload_event_type;
BEGIN
    -- Get doc_request and validate status
    SELECT * INTO v_doc_request
    FROM public.doc_requests
    WHERE id = p_doc_request_id;

    IF NOT FOUND THEN
        RAISE EXCEPTION 'Doc request not found';
    END IF;

    -- Contract: "Enforce doc_request.status in (OPEN, SUBMITTED) but if SUBMITTED then reject new uploads"
    IF v_doc_request.status = 'SUBMITTED' THEN
        RAISE EXCEPTION 'Doc request already submitted, cannot upload';
    END IF;

    IF v_doc_request.status NOT IN ('OPEN') THEN
        RAISE EXCEPTION 'Doc request status is %, cannot upload', v_doc_request.status;
    END IF;

    -- Check for existing upload
    SELECT * INTO v_existing_upload
    FROM public.uploads
    WHERE doc_request_id = p_doc_request_id
      AND doc_type = p_doc_type;

    IF FOUND THEN
        -- Upsert only allowed if prior status is RECEIVED
        IF v_existing_upload.status != 'RECEIVED' THEN
            RAISE EXCEPTION 'Cannot replace upload with status %', v_existing_upload.status;
        END IF;

        -- Update existing upload
        UPDATE public.uploads
        SET
            storage_bucket = p_storage_bucket,
            storage_path = p_storage_path,
            file_name = p_file_name,
            content_type = p_content_type,
            byte_size = p_byte_size,
            sha256 = p_sha256,
            status = 'RECEIVED',
            updated_at = now()
        WHERE id = v_existing_upload.id
        RETURNING id INTO v_upload_id;

        v_event_type := 'FILE_UPLOADED';
    ELSE
        -- Create new upload
        INSERT INTO public.uploads (
            doc_request_id,
            doc_type,
            storage_bucket,
            storage_path,
            file_name,
            content_type,
            byte_size,
            sha256
        ) VALUES (
            p_doc_request_id,
            p_doc_type,
            p_storage_bucket,
            p_storage_path,
            p_file_name,
            p_content_type,
            p_byte_size,
            p_sha256
        )
        RETURNING id INTO v_upload_id;

        v_event_type := 'CREATED';
    END IF;

    -- Create upload event
    INSERT INTO public.upload_events (
        upload_id,
        event_type,
        actor_type
    ) VALUES (
        v_upload_id,
        v_event_type,
        'CARRIER'
    );

    RETURN v_upload_id;
END;
$$;

-- =============================================================================
-- F4) set_upload_status(upload_id uuid, next_status, note text)
-- =============================================================================
-- Returns: upload row
-- Rules:
-- - Enforce allowed transitions (Section 5)
-- - Write upload_events STATUS_CHANGED with note
--
-- Allowed transitions:
-- - RECEIVED → ACCEPTED
-- - RECEIVED → REJECTED
-- - RECEIVED → QUARANTINED
-- - QUARANTINED → ACCEPTED
-- - QUARANTINED → REJECTED

CREATE OR REPLACE FUNCTION public.set_upload_status(
    p_upload_id uuid,
    p_next_status public.upload_status,
    p_note text DEFAULT NULL
)
RETURNS public.uploads
LANGUAGE plpgsql
SECURITY DEFINER
AS $$
DECLARE
    v_upload public.uploads;
    v_current_status public.upload_status;
    v_valid_transition boolean := false;
BEGIN
    -- Get current upload
    SELECT * INTO v_upload
    FROM public.uploads
    WHERE id = p_upload_id;

    IF NOT FOUND THEN
        RAISE EXCEPTION 'Upload not found';
    END IF;

    v_current_status := v_upload.status;

    -- Validate transition
    IF v_current_status = 'RECEIVED' AND p_next_status IN ('ACCEPTED', 'REJECTED', 'QUARANTINED') THEN
        v_valid_transition := true;
    ELSIF v_current_status = 'QUARANTINED' AND p_next_status IN ('ACCEPTED', 'REJECTED') THEN
        v_valid_transition := true;
    END IF;

    IF NOT v_valid_transition THEN
        RAISE EXCEPTION 'Invalid status transition from % to %', v_current_status, p_next_status;
    END IF;

    -- Update status
    UPDATE public.uploads
    SET status = p_next_status, updated_at = now()
    WHERE id = p_upload_id
    RETURNING * INTO v_upload;

    -- Write event
    INSERT INTO public.upload_events (
        upload_id,
        event_type,
        actor_type,
        note
    ) VALUES (
        p_upload_id,
        'STATUS_CHANGED',
        'BROKER',
        p_note
    );

    RETURN v_upload;
END;
$$;

-- =============================================================================
-- F5) submit_doc_request(doc_request_id uuid)
-- =============================================================================
-- Returns: doc_request row
-- Rules:
-- - Hard fail unless status is OPEN
-- - Require that required docs are present as uploads rows
-- - Set status SUBMITTED and submitted_at now()

CREATE OR REPLACE FUNCTION public.submit_doc_request(p_doc_request_id uuid)
RETURNS public.doc_requests
LANGUAGE plpgsql
SECURITY DEFINER
AS $$
DECLARE
    v_doc_request public.doc_requests;
    v_required_doc record;
    v_upload_exists boolean;
BEGIN
    -- Get doc_request
    SELECT * INTO v_doc_request
    FROM public.doc_requests
    WHERE id = p_doc_request_id;

    IF NOT FOUND THEN
        RAISE EXCEPTION 'Doc request not found';
    END IF;

    -- Hard fail unless status is OPEN
    IF v_doc_request.status != 'OPEN' THEN
        RAISE EXCEPTION 'Doc request status is %, must be OPEN to submit', v_doc_request.status;
    END IF;

    -- Check all required docs are present
    FOR v_required_doc IN
        SELECT
            (elem->>'doc_type') as doc_type,
            COALESCE((elem->>'required')::boolean, true) as required
        FROM jsonb_array_elements(v_doc_request.required_docs) as elem
    LOOP
        IF v_required_doc.required THEN
            SELECT EXISTS (
                SELECT 1 FROM public.uploads
                WHERE doc_request_id = p_doc_request_id
                  AND doc_type = v_required_doc.doc_type
            ) INTO v_upload_exists;

            IF NOT v_upload_exists THEN
                RAISE EXCEPTION 'Missing required document: %', v_required_doc.doc_type;
            END IF;
        END IF;
    END LOOP;

    -- Update status to SUBMITTED
    UPDATE public.doc_requests
    SET
        status = 'SUBMITTED',
        submitted_at = now(),
        updated_at = now()
    WHERE id = p_doc_request_id
    RETURNING * INTO v_doc_request;

    RETURN v_doc_request;
END;
$$;

-- =============================================================================
-- F6) expire_doc_requests()
-- =============================================================================
-- Scheduled job (optional)
-- Rules:
-- - Set EXPIRED where now() > expires_at and status not in (EXPIRED, CANCELED)

CREATE OR REPLACE FUNCTION public.expire_doc_requests()
RETURNS int
LANGUAGE plpgsql
SECURITY DEFINER
AS $$
DECLARE
    v_count int;
BEGIN
    UPDATE public.doc_requests
    SET
        status = 'EXPIRED',
        updated_at = now()
    WHERE expires_at < now()
      AND status NOT IN ('EXPIRED', 'CANCELED');

    GET DIAGNOSTICS v_count = ROW_COUNT;

    RETURN v_count;
END;
$$;
