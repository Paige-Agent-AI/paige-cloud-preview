#!/usr/bin/env bash
set -eu

dir="$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")" && pwd)"
container="paige-cloud-accounts-check-$$"
image="postgres:16.14-alpine@sha256:57c72fd2a128e416c7fcc499958864df5301e940bca0a56f58fddf30ffc07777"
docker run -d --rm --network none --name "$container" -e POSTGRES_HOST_AUTH_METHOD=trust "$image"
trap 'docker rm --force "$container" >/dev/null' EXIT

ready=false
for _ in {1..30}; do
  if docker exec "$container" pg_isready -h 127.0.0.1 -U postgres >/dev/null 2>&1; then
    ready=true
    break
  fi
  sleep 1
done
test "$ready" = true

verify_db() {
  docker exec -i "$container" psql -X -U postgres -v ON_ERROR_STOP=1 "$@"
}

verify_db -c 'CREATE ROLE paige_cloud_account_runtime NOLOGIN'
verify_db < "$dir/001-accounts.sql"
verify_db < "$dir/002-registry.sql"
verify_db < "$dir/003-workload-observation.sql"
verify_db < "$dir/004-organization-name.sql"
verify_db < "$dir/005-workload-configuration.sql"
verify_db < "$dir/006-configuration-history.sql"
verify_db < "$dir/007-account-email-admission.sql"
verify_db < "$dir/008-account-email-capacity.sql"
verify_db < "$dir/009-account-email-provider-window.sql"
verify_db < "$dir/010-repository-binding.sql"
verify_db < "$dir/011-repository-binding-transitions.sql"
verify_db < "$dir/account-records.test.sql"
verify_db < "$dir/registry.test.sql"
verify_db < "$dir/repository-binding-operations.test.sql"
verify_db < "$dir/workload-configuration.test.sql"
verify_db < "$dir/account-email-admission.test.sql"
verify_db < "$dir/account-email-provider-window.test.sql"

verify_db -c "SET ROLE paige_cloud_account_runtime;
  SELECT cloud_accounts.record_verified_identity('test-issuer', 'concurrent', 'parallel@example.test');"

first=$(mktemp)
second=$(mktemp)
trap 'rm -f "$first" "$second"; docker rm --force "$container" >/dev/null' EXIT

docker exec -i -e PGAPPNAME=onboarding_first "$container" psql -XAtq -U postgres -v ON_ERROR_STOP=1 >"$first" <<'SQL' &
SET statement_timeout = '12s';
SET ROLE paige_cloud_account_runtime;
BEGIN;
SELECT cloud_accounts.onboard_organization(
  cloud_accounts.find_verified_identity('test-issuer', 'concurrent'), 'Parallel'
)->>'id';
SELECT pg_sleep(4);
COMMIT;
SQL
first_pid=$!

first_holds_row=false
for _ in {1..20}; do
  if [[ "$(verify_db -Atq -c "SELECT EXISTS (
    SELECT 1 FROM pg_stat_activity WHERE application_name = 'onboarding_first' AND wait_event = 'PgSleep'
  )")" = t ]]; then
    first_holds_row=true
    break
  fi
  sleep 0.1
done
test "$first_holds_row" = true

docker exec -i -e PGAPPNAME=onboarding_second "$container" psql -XAtq -U postgres -v ON_ERROR_STOP=1 >"$second" <<'SQL' &
SET statement_timeout = '12s';
SET ROLE paige_cloud_account_runtime;
SELECT cloud_accounts.onboard_organization(
  cloud_accounts.find_verified_identity('test-issuer', 'concurrent'), 'Parallel'
)->>'id';
SQL
second_pid=$!

waited=false
for _ in {1..20}; do
  if [[ "$(verify_db -Atq -c "SELECT EXISTS (
    SELECT 1 FROM pg_stat_activity WHERE application_name = 'onboarding_second' AND wait_event_type = 'Lock'
  )")" = t ]]; then
    waited=true
    break
  fi
  sleep 0.1
done
test "$waited" = true
wait "$first_pid"
wait "$second_pid"
organization="$(head -n 1 "$first")"
[[ "$organization" =~ ^[a-f0-9-]{36}$ ]]
test "$organization" = "$(cat "$second")"
test 1 = "$(verify_db -Atq -c "SELECT count(*) FROM cloud_accounts.memberships WHERE organization_id = '$organization'")"
printf 'Confirmed one persisted organization and one membership after two concurrent requests.\n'

verify_db -q -c "
  SELECT cloud_accounts.registry_create_project(
    cloud_accounts.find_verified_identity('test-issuer', 'concurrent'), '$organization', 'capacity', 'Capacity');
  INSERT INTO cloud_accounts.registry_applications
  SELECT '$organization', 'capacity', 'seed-' || n, 'Seed ' || n, 'application', NULL FROM generate_series(1,99) n;"

register_at_capacity() {
  docker exec -i -e PGAPPNAME="$1" "$container" psql -XAtq -U postgres -v ON_ERROR_STOP=1 <<SQL
SET statement_timeout = '12s';
SET ROLE paige_cloud_account_runtime;
BEGIN;
SELECT coalesce(result->>'error', result->>'id') FROM cloud_accounts.registry_register_application(
  cloud_accounts.find_verified_identity('test-issuer', 'concurrent'), '$organization',
  'capacity', '$2', '$2', 'application', NULL, 'development') result;
SELECT pg_sleep($3);
COMMIT;
SQL
}
register_at_capacity registry_capacity_first last-slot 3 >"$first" &
first_pid=$!
first_holds_row=false
for _ in {1..20}; do
  if [[ "$(verify_db -Atq -c "SELECT EXISTS (
    SELECT 1 FROM pg_stat_activity WHERE application_name = 'registry_capacity_first' AND wait_event = 'PgSleep'
  )")" = t ]]; then
    first_holds_row=true
    break
  fi
  sleep 0.1
done
test "$first_holds_row" = true
register_at_capacity registry_capacity_second over-capacity 0 >"$second" &
second_pid=$!
wait "$first_pid"
wait "$second_pid"
test last-slot = "$(head -n 1 "$first")"
test registry_limit = "$(head -n 1 "$second")"
test 100 = "$(verify_db -Atq -c "SELECT count(*) FROM cloud_accounts.registry_applications
  WHERE organization_id = '$organization' AND project_id = 'capacity'")"
printf 'Confirmed that two concurrent registrations cannot exceed the application limit.\n'

save_first_configuration() {
  docker exec -i -e PGAPPNAME="$1" "$container" psql -XAtq -U postgres -v ON_ERROR_STOP=1 <<SQL
SET statement_timeout = '12s';
SET ROLE paige_cloud_account_runtime;
BEGIN;
SELECT coalesce(result->>'error', result->>'revision') FROM cloud_accounts.save_workload_configuration_v2(
  cloud_accounts.find_verified_identity('test-issuer', 'concurrent'), '$organization',
  'capacity', 'last-slot', 'development', 0, 'info', $2) result;
SELECT pg_sleep($3);
COMMIT;
SQL
}
save_first_configuration config_first 1000 3 >"$first" &
first_pid=$!
first_holds_row=false
for _ in {1..20}; do
  if [[ "$(verify_db -Atq -c "SELECT EXISTS (
    SELECT 1 FROM pg_stat_activity WHERE application_name = 'config_first' AND wait_event = 'PgSleep'
  )")" = t ]]; then
    first_holds_row=true
    break
  fi
  sleep 0.1
done
test "$first_holds_row" = true
save_first_configuration config_second 1500 0 >"$second" &
second_pid=$!
wait "$first_pid"
wait "$second_pid"
test 1 = "$(head -n 1 "$first")"
test configuration_changed = "$(head -n 1 "$second")"
test 1 = "$(verify_db -Atq -c "SELECT count(*) FROM cloud_accounts.workload_configuration_revisions
  WHERE organization_id = '$organization' AND project_id = 'capacity' AND application_id = 'last-slot'")"
printf 'Confirmed that concurrent configuration writers cannot overwrite or duplicate the first revision.\n'
