-- Run against a new disposable database after the account migrations.
CREATE ROLE untrusted_account_test NOLOGIN;
GRANT USAGE ON SCHEMA cloud_accounts TO untrusted_account_test;
SET ROLE untrusted_account_test;
DO $$
BEGIN
  PERFORM cloud_accounts.account_details(gen_random_uuid());
  RAISE EXCEPTION 'untrusted role could query the account API';
EXCEPTION WHEN insufficient_privilege THEN NULL;
END
$$;
RESET ROLE;

DO $$
DECLARE
  operator_binding regprocedure := 'cloud_accounts.record_repository_binding_operation(uuid, uuid, uuid, text, text, text, uuid, uuid, text, text, text, text, text, text)'::regprocedure;
  internal_configuration regprocedure := 'cloud_accounts.save_workload_configuration_revision(uuid, uuid, text, text, text, integer, text, integer, boolean)'::regprocedure;
BEGIN
  IF EXISTS (
    SELECT 1
    FROM pg_proc AS proc
    JOIN pg_namespace AS schema ON schema.oid = proc.pronamespace
    WHERE schema.nspname = 'cloud_accounts'
      AND (proc.prosecdef <> (proc.oid <> operator_binding)
           OR NOT COALESCE('search_path=pg_catalog, pg_temp' = ANY(proc.proconfig), false)
           OR has_function_privilege('untrusted_account_test', proc.oid, 'EXECUTE')
           OR has_function_privilege('paige_cloud_account_runtime', proc.oid, 'EXECUTE') <>
             (proc.oid NOT IN (internal_configuration, operator_binding)))
  ) THEN
    RAISE EXCEPTION 'unexpected execution authority or function search path';
  END IF;
END
$$;

SET ROLE paige_cloud_account_runtime;
DO $$
DECLARE
  first_account uuid;
  second_account uuid;
  first_org uuid;
  second_org uuid;
  first_number text;
BEGIN
  IF EXISTS (
    SELECT 1 FROM pg_class AS relation
    JOIN pg_namespace AS schema ON schema.oid = relation.relnamespace
    WHERE schema.nspname = 'cloud_accounts'
      AND (pg_has_role(current_user, relation.relowner, 'MEMBER')
           OR (relation.relkind = 'r' AND has_table_privilege(
             current_user, relation.oid, 'SELECT, INSERT, UPDATE, DELETE, TRUNCATE, REFERENCES, TRIGGER'
           )))
  ) THEN
    RAISE EXCEPTION 'runtime should only access the functions';
  END IF;

  first_account := cloud_accounts.record_verified_identity('test-issuer', 'a', 'a@example.test');
  second_account := cloud_accounts.record_verified_identity('test-issuer', 'b', 'b@example.test');
  IF first_account IS NULL OR second_account IS NULL OR first_account = second_account THEN
    RAISE EXCEPTION 'identity persistence did not create separate accounts';
  END IF;
  IF cloud_accounts.record_verified_identity('different-issuer', 'a', 'a@example.test') = first_account THEN
    RAISE EXCEPTION 'identity lookup ignored issuer';
  END IF;
  IF cloud_accounts.find_verified_identity('test-issuer', 'a') IS DISTINCT FROM first_account OR
     cloud_accounts.find_verified_identity('test-issuer', 'missing') IS NOT NULL THEN
    RAISE EXCEPTION 'sign-in identity lookup returned an unexpected account';
  END IF;
  first_number := cloud_accounts.account_details(first_account)->>'number';
  IF first_number IS NULL OR first_number !~ '^[1-9][0-9]{11}$' OR
     first_number = (cloud_accounts.account_details(second_account)->>'number') THEN
    RAISE EXCEPTION 'account number is invalid or reused';
  END IF;
  IF cloud_accounts.account_details(first_account)->'organizations' IS DISTINCT FROM '[]'::jsonb THEN
    RAISE EXCEPTION 'initial account has unexpected memberships';
  END IF;

  first_org := (cloud_accounts.onboard_organization(first_account, ' Alpha ')->>'id')::uuid;
  second_org := (cloud_accounts.onboard_organization(second_account, 'Beta')->>'id')::uuid;
  IF first_org IS NULL OR second_org IS NULL OR first_org = second_org THEN
    RAISE EXCEPTION 'onboarding did not create separate organizations';
  END IF;
  IF (cloud_accounts.onboard_organization(first_account, 'Alpha')->>'id')::uuid IS DISTINCT FROM first_org THEN
    RAISE EXCEPTION 'onboarding retry changed the organization';
  END IF;
  IF cloud_accounts.onboard_organization(first_account, 'Another alpha')->>'error' IS DISTINCT FROM 'organization_exists' THEN
    RAISE EXCEPTION 'onboarding accepted different inputs for an existing initial organization';
  END IF;
  IF cloud_accounts.organization_details(first_account, second_org) IS NOT NULL OR
     cloud_accounts.organization_details(second_account, first_org) IS NOT NULL THEN
    RAISE EXCEPTION 'organization isolation failed';
  END IF;
  IF cloud_accounts.organization_details(first_account, first_org)->>'role' IS DISTINCT FROM 'owner' THEN
    RAISE EXCEPTION 'account owner could not access its organization';
  END IF;
  IF cloud_accounts.rename_organization(second_account, first_org, 'Alpha', 'Wrong scope') IS NOT NULL
     OR cloud_accounts.rename_organization(first_account, second_org, 'Beta', 'Wrong scope') IS NOT NULL THEN
    RAISE EXCEPTION 'organization rename crossed scope';
  END IF;
  IF (cloud_accounts.rename_organization(first_account, first_org, 'Alpha', ' Alpha Holdings ')->>'id')::uuid
       IS DISTINCT FROM first_org THEN
    RAISE EXCEPTION 'organization rename changed its ID';
  END IF;
  IF cloud_accounts.rename_organization(first_account, first_org, 'Alpha', 'Alpha Holdings')->>'name'
       IS DISTINCT FROM 'Alpha Holdings' THEN
    RAISE EXCEPTION 'same-name retry failed';
  END IF;
  IF cloud_accounts.rename_organization(first_account, first_org, 'Alpha', 'Stale')->>'error'
       IS DISTINCT FROM 'organization_changed' THEN
    RAISE EXCEPTION 'stale organization rename was accepted';
  END IF;
  IF cloud_accounts.account_details(first_account)->'organizations'->0->>'name' IS DISTINCT FROM 'Alpha Holdings' THEN
    RAISE EXCEPTION 'renamed organization was not persisted';
  END IF;

  IF cloud_accounts.update_display_name(first_account, ' Alpha Owner ')->>'displayName' IS DISTINCT FROM 'Alpha Owner'
     OR cloud_accounts.account_details(second_account)->>'displayName' IS NOT NULL THEN
    RAISE EXCEPTION 'account profile update was not scoped';
  END IF;
  IF cloud_accounts.record_verified_identity('test-issuer', 'a', 'a-new@example.test') IS DISTINCT FROM first_account OR
     cloud_accounts.account_details(first_account)->>'number' IS DISTINCT FROM first_number THEN
    RAISE EXCEPTION 'later sign-in changed the account identity';
  END IF;
  PERFORM set_config('paige_test.first_organization', first_org::text, false);
END
$$;
RESET ROLE;

INSERT INTO cloud_accounts.memberships (organization_id, account_id, role)
SELECT current_setting('paige_test.first_organization')::uuid, id, 'member'
FROM cloud_accounts.accounts WHERE identity_issuer = 'test-issuer' AND identity_subject = 'b';

UPDATE cloud_accounts.memberships
SET revoked_at = now()
WHERE account_id = (SELECT id FROM cloud_accounts.accounts WHERE identity_issuer = 'test-issuer' AND identity_subject = 'a');

SET ROLE paige_cloud_account_runtime;
DO $$
DECLARE
  actor uuid := cloud_accounts.record_verified_identity('test-issuer', 'a', 'a-new@example.test');
  member uuid := cloud_accounts.find_verified_identity('test-issuer', 'b');
  organization uuid := current_setting('paige_test.first_organization')::uuid;
BEGIN
  IF cloud_accounts.account_details(actor)->'organizations' IS DISTINCT FROM '[]'::jsonb OR
     cloud_accounts.onboard_organization(actor, 'Alpha Holdings') IS NOT NULL OR
     cloud_accounts.rename_organization(actor, organization, 'Alpha Holdings', 'Revoked') IS NOT NULL THEN
    RAISE EXCEPTION 'revoked membership remained visible or was reinstated';
  END IF;
  IF cloud_accounts.organization_details(member, organization)->>'role' IS DISTINCT FROM 'member'
     OR cloud_accounts.rename_organization(member, organization, 'Alpha Holdings', 'Member') IS NOT NULL THEN
    RAISE EXCEPTION 'read-only member could rename the organization';
  END IF;
END
$$;
RESET ROLE;
