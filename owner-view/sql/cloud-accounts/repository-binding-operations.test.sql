BEGIN;

SELECT set_config('paige.binding.owner', cloud_accounts.record_verified_identity('binding', 'owner', 'binding@example.test')::text, true);
SELECT set_config('paige.binding.foreign', cloud_accounts.record_verified_identity('binding', 'another', 'binding-other@example.test')::text, true);
SELECT set_config('paige.binding.org', cloud_accounts.onboard_organization(
  current_setting('paige.binding.owner')::uuid, 'Binding test')->>'id', true);
SELECT cloud_accounts.registry_create_project(current_setting('paige.binding.owner')::uuid,
  current_setting('paige.binding.org')::uuid, 'workspace', 'Workspace');
SELECT cloud_accounts.registry_register_application(current_setting('paige.binding.owner')::uuid,
  current_setting('paige.binding.org')::uuid, 'workspace', 'application', 'Application', 'application', 'Example/Source', 'development');
SELECT cloud_accounts.registry_register_application(current_setting('paige.binding.owner')::uuid,
  current_setting('paige.binding.org')::uuid, 'workspace', 'application', 'Application', 'application', 'Example/Source', 'preview');

CREATE FUNCTION pg_temp.binding_change(operation uuid, approval uuid, expected uuid, branch text,
  source text DEFAULT '123', actor uuid DEFAULT current_setting('paige.binding.owner')::uuid,
  environment text DEFAULT 'development')
RETURNS jsonb LANGUAGE sql AS $$
  SELECT cloud_accounts.record_repository_binding_operation(operation, actor,
    current_setting('paige.binding.org')::uuid, 'workspace', 'application', environment,
    expected, approval, repeat('a', 64), source,
    CASE WHEN source IS NOT NULL THEN 'Example/Source' END,
    branch,
    CASE WHEN source IS NOT NULL
      THEN 'arn:aws:codeconnections:us-east-2:111111111111:connection/11111111-1111-4111-8111-111111111111' END,
    CASE WHEN source IS NOT NULL THEN repeat('b', 40) END);
$$;

SET LOCAL ROLE paige_cloud_account_runtime;
DO $$
BEGIN
  IF has_table_privilege(current_user, 'cloud_accounts.repository_binding_operations', 'SELECT, INSERT, UPDATE, DELETE') THEN
    RAISE EXCEPTION 'the account role has binding operation table access';
  END IF;
  BEGIN
    PERFORM pg_temp.binding_change(gen_random_uuid(), gen_random_uuid(), NULL, 'refs/heads/main');
    RAISE EXCEPTION 'the account role executed a binding change';
  EXCEPTION WHEN insufficient_privilege THEN NULL;
  END;
END
$$;
RESET ROLE;

DO $$
DECLARE
  actor uuid := current_setting('paige.binding.owner')::uuid;
  org uuid := current_setting('paige.binding.org')::uuid;
  operation uuid := gen_random_uuid();
  approval uuid := gen_random_uuid();
  replacement uuid := gen_random_uuid();
  replacement_approval uuid := gen_random_uuid();
  revocation uuid := gen_random_uuid();
  revocation_approval uuid := gen_random_uuid();
  original_binding uuid;
  new_binding uuid;
  outcome jsonb;
BEGIN
  IF pg_temp.binding_change(operation, approval, NULL, 'refs/heads/main', '123',
    current_setting('paige.binding.foreign')::uuid) IS NOT NULL
  OR pg_temp.binding_change(operation, approval, NULL, 'refs/heads/main', '123', actor, 'missing') IS NOT NULL THEN
    RAISE EXCEPTION 'foreign ownership or missing environment was accepted';
  END IF;

  outcome := pg_temp.binding_change(operation, approval, NULL, 'refs/heads/main');
  original_binding := (outcome->>'bindingId')::uuid;
  IF original_binding IS NULL OR outcome->>'replayed' IS DISTINCT FROM 'false' THEN
    RAISE EXCEPTION 'binding creation failed';
  END IF;
  IF pg_temp.binding_change(operation, approval, NULL, 'refs/heads/main')->>'bindingId' IS DISTINCT FROM original_binding::text
  OR pg_temp.binding_change(operation, approval, NULL, 'refs/heads/changed')->>'error' IS DISTINCT FROM 'binding_operation_conflict'
  OR pg_temp.binding_change(gen_random_uuid(), approval, NULL, 'refs/heads/main', '123', actor, 'preview')->>'error'
    IS DISTINCT FROM 'binding_operation_conflict'
  OR pg_temp.binding_change(gen_random_uuid(), gen_random_uuid(), original_binding, 'refs/heads/main', '999')->>'error'
    IS DISTINCT FROM 'repository_identity_conflict' THEN
    RAISE EXCEPTION 'receipt reuse, exact replay, or repository identity drift was mishandled';
  END IF;
  IF cloud_accounts.read_repository_binding(actor, org, 'workspace', 'application', 'preview')
     IS DISTINCT FROM '{"binding":null}'::jsonb THEN
    RAISE EXCEPTION 'a conflicting operation left a sibling binding';
  END IF;

  outcome := pg_temp.binding_change(replacement, replacement_approval, original_binding, 'refs/heads/release');
  new_binding := (outcome->>'bindingId')::uuid;
  IF new_binding IS NULL OR new_binding = original_binding
  OR cloud_accounts.read_repository_binding(actor, org, 'workspace', 'application', 'development')->'binding'->>'ref'
    IS DISTINCT FROM 'refs/heads/release'
  OR pg_temp.binding_change(gen_random_uuid(), gen_random_uuid(), original_binding, NULL, NULL)->>'error'
    IS DISTINCT FROM 'binding_changed' THEN
    RAISE EXCEPTION 'replacement, readback or stale write verification failed';
  END IF;

  outcome := pg_temp.binding_change(revocation, revocation_approval, new_binding, NULL, NULL);
  IF outcome->'bindingId' IS DISTINCT FROM 'null'::jsonb OR outcome->>'replayed' IS DISTINCT FROM 'false'
  OR pg_temp.binding_change(revocation, revocation_approval, new_binding, NULL, NULL)->>'replayed' IS DISTINCT FROM 'true'
  OR cloud_accounts.read_repository_binding(actor, org, 'workspace', 'application', 'development')
    IS DISTINCT FROM '{"binding":null}'::jsonb
  OR (SELECT count(*) FROM cloud_accounts.repository_bindings WHERE organization_id = org AND revoked_at IS NOT NULL) <> 2
  OR (SELECT count(*) FROM cloud_accounts.repository_binding_operations WHERE organization_id = org) <> 3 THEN
    RAISE EXCEPTION 'revocation did not preserve the exact binding and operation history';
  END IF;
END
$$;

ROLLBACK;
