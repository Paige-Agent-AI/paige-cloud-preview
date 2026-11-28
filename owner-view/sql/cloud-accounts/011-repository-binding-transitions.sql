BEGIN;

CREATE TABLE cloud_accounts.repository_binding_operations (
  id uuid PRIMARY KEY,
  organization_id uuid NOT NULL,
  project_id text NOT NULL,
  application_id text NOT NULL,
  environment_id text NOT NULL,
  requester uuid NOT NULL REFERENCES cloud_accounts.accounts(id),
  authorization_receipt uuid NOT NULL UNIQUE,
  evidence_sha256 text NOT NULL CHECK (evidence_sha256 ~ '^[a-f0-9]{64}$'),
  intent jsonb NOT NULL,
  result_binding_id uuid REFERENCES cloud_accounts.repository_bindings(id),
  recorded_at timestamptz NOT NULL DEFAULT clock_timestamp(),
  FOREIGN KEY (organization_id, project_id, application_id, environment_id) REFERENCES cloud_accounts.registry_targets
);

REVOKE ALL ON cloud_accounts.repository_binding_operations FROM PUBLIC, paige_cloud_account_runtime;

-- The existing reviewed infrastructure operator is the executor. The requester
-- must still have a current project owner grant, and the proof must be carried
-- from the reviewed operation. This function does not redeem a Trust approval.
CREATE FUNCTION cloud_accounts.record_repository_binding_operation(
  operation_id uuid, actor uuid, org uuid, project text, app text, environment text,
  expected_binding uuid, approval_receipt_id uuid, evidence text,
  source_id text, source_name text, source_ref text, source_connection text, reviewed_commit text
) RETURNS jsonb
LANGUAGE plpgsql SECURITY INVOKER SET search_path = pg_catalog, pg_temp
AS $$
DECLARE
  registered_source text;
  prior cloud_accounts.repository_binding_operations%ROWTYPE;
  current_binding cloud_accounts.repository_bindings%ROWTYPE;
  recorded_binding uuid;
  intent_data jsonb;
  revoking boolean := source_id IS NULL;
BEGIN
  IF operation_id IS NULL OR approval_receipt_id IS NULL OR evidence IS NULL OR evidence !~ '^[a-f0-9]{64}$' OR
     (revoking AND (expected_binding IS NULL OR num_nonnulls(source_name, source_ref, source_connection, reviewed_commit) <> 0)) OR
     (NOT revoking AND (num_nonnulls(source_name, source_ref, source_connection, reviewed_commit) <> 4 OR
       reviewed_commit !~ '^[a-f0-9]{40}$')) THEN
    RETURN jsonb_build_object('error', 'invalid_binding_operation');
  END IF;

  PERFORM 1 FROM cloud_accounts.registry_grants g JOIN cloud_accounts.memberships m
    ON m.organization_id = g.organization_id AND m.account_id = g.account_id
    WHERE g.organization_id = org AND g.project_id = project AND g.account_id = actor
      AND g.role = 'owner' AND m.revoked_at IS NULL FOR SHARE OF g, m;
  IF NOT FOUND THEN RETURN NULL; END IF;

  SELECT a.source_repository INTO registered_source FROM cloud_accounts.registry_targets t
    JOIN cloud_accounts.registry_applications a
      ON a.organization_id = t.organization_id AND a.project_id = t.project_id AND a.id = t.application_id
    WHERE t.organization_id = org AND t.project_id = project AND t.application_id = app
      AND t.environment_id = environment FOR UPDATE OF t;
  IF NOT FOUND THEN RETURN NULL; END IF;

  intent_data := jsonb_build_object('expectedBinding', expected_binding, 'repositoryId', source_id,
    'repository', source_name, 'ref', source_ref, 'connection', source_connection, 'reviewedCommit', reviewed_commit);
  SELECT * INTO prior FROM cloud_accounts.repository_binding_operations r WHERE r.id = operation_id;
  IF FOUND THEN
    IF (prior.organization_id, prior.project_id, prior.application_id, prior.environment_id, prior.requester,
        prior.authorization_receipt, prior.evidence_sha256, prior.intent)
       IS DISTINCT FROM (org, project, app, environment, actor, approval_receipt_id, evidence, intent_data) THEN
      RETURN jsonb_build_object('error', 'binding_operation_conflict');
    END IF;
    RETURN jsonb_build_object('operationId', operation_id, 'bindingId', prior.result_binding_id, 'replayed', true);
  END IF;

  SELECT * INTO current_binding FROM cloud_accounts.repository_bindings b WHERE b.organization_id = org
    AND b.project_id = project AND b.application_id = app AND b.environment_id = environment AND b.revoked_at IS NULL;
  IF current_binding.id IS DISTINCT FROM expected_binding THEN
    RETURN jsonb_build_object('error', 'binding_changed');
  END IF;
  IF NOT revoking AND (registered_source IS NULL OR lower(registered_source) <> lower(source_name) OR
    EXISTS (SELECT 1 FROM cloud_accounts.repository_bindings b
      WHERE b.organization_id = org AND b.project_id = project AND b.application_id = app
        AND b.environment_id = environment AND lower(b.repository) = lower(source_name) AND b.repository_id <> source_id)) THEN
    RETURN jsonb_build_object('error', 'repository_identity_conflict');
  END IF;

  IF expected_binding IS NOT NULL THEN
    UPDATE cloud_accounts.repository_bindings SET revoked_at = clock_timestamp() WHERE id = expected_binding;
  END IF;
  IF NOT revoking THEN
    INSERT INTO cloud_accounts.repository_bindings (
      organization_id, project_id, application_id, environment_id, repository_id, repository, ref, connection_arn
    ) VALUES (org, project, app, environment, source_id, source_name, source_ref, source_connection)
    RETURNING id INTO recorded_binding;
  END IF;
  INSERT INTO cloud_accounts.repository_binding_operations (
    id, organization_id, project_id, application_id, environment_id, requester,
    authorization_receipt, evidence_sha256, intent, result_binding_id
  ) VALUES (operation_id, org, project, app, environment, actor, approval_receipt_id, evidence, intent_data, recorded_binding);
  RETURN jsonb_build_object('operationId', operation_id, 'bindingId', recorded_binding, 'replayed', false);
EXCEPTION WHEN unique_violation THEN
  -- Conflicting operation or approval reuse rolls back the entire transition.
  RETURN jsonb_build_object('error', 'binding_operation_conflict');
END
$$;

REVOKE EXECUTE ON FUNCTION cloud_accounts.record_repository_binding_operation(
  uuid, uuid, uuid, text, text, text, uuid, uuid, text, text, text, text, text, text
) FROM PUBLIC, paige_cloud_account_runtime;

COMMIT;
