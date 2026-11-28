// Operator-only migration entry point. Do not package this module in the Lambda ZIP.
import { createHash } from "node:crypto";
import { readFile } from "node:fs/promises";
import { resolve } from "node:path";
import { pathToFileURL } from "node:url";
import { BeginTransactionCommand, CommitTransactionCommand, ExecuteStatementCommand, RDSDataClient, RollbackTransactionCommand } from "@aws-sdk/client-rds-data";
import { GetSecretValueCommand, SecretsManagerClient } from "@aws-sdk/client-secrets-manager";

function migrationParts(raw) {
  const migration = raw.trim().match(/^BEGIN;([\s\S]+)COMMIT;$/)?.[1];
  if (!migration || migration.includes("$cloud_ddl$")) throw new Error("Unexpected migration boundary");
  const hash = createHash("sha256").update(raw.replaceAll("\r\n", "\n")).digest("hex");
  return { migration, hash };
}

export async function applyAccountMigration(raw, execute, readRuntimeCredential) {
  const { migration, hash } = migrationParts(raw);
  await execute("DO $cloud_lock$ BEGIN PERFORM pg_advisory_xact_lock(hashtextextended('paige-cloud-account-migration', 0)); END $cloud_lock$");
  await execute("CREATE SCHEMA IF NOT EXISTS cloud_account_migrations");
  await execute("REVOKE ALL ON SCHEMA cloud_account_migrations FROM PUBLIC");
  await execute("CREATE TABLE IF NOT EXISTS cloud_account_migrations.applied (version text PRIMARY KEY, checksum text NOT NULL)");
  const existing = await execute("SELECT checksum FROM cloud_account_migrations.applied WHERE version = '001'");
  if (existing) {
    if (existing !== hash) throw new Error("Applied account migration differs from reviewed source");
    return false;
  }

  const { username, password } = await readRuntimeCredential();
  if (username !== "paige_cloud_app" || typeof password !== "string" || password.length < 32) {
    throw new Error("Application database credential does not match its provisioned role");
  }
  await execute("CREATE ROLE paige_cloud_account_runtime NOLOGIN");
  await execute("SELECT length(set_config('paige_cloud.bootstrap_password', :password, true))", { password });
  await execute(`DO $cloud_role$ BEGIN
    EXECUTE format('CREATE ROLE paige_cloud_app LOGIN NOSUPERUSER NOCREATEROLE NOCREATEDB NOREPLICATION NOBYPASSRLS PASSWORD %L',
      current_setting('paige_cloud.bootstrap_password'));
    GRANT paige_cloud_account_runtime TO paige_cloud_app;
    GRANT CONNECT ON DATABASE paige_cloud TO paige_cloud_app;
  EXCEPTION WHEN OTHERS THEN
    RAISE EXCEPTION 'Application database login setup failed';
  END $cloud_role$`);
  await execute(`DO $cloud_ddl$ BEGIN ${migration} END $cloud_ddl$`);
  await execute("INSERT INTO cloud_account_migrations.applied (version, checksum) VALUES ('001', :checksum)", { checksum: hash });
  return true;
}

async function applyAdditiveMigration(version, raw, execute) {
  const { migration, hash } = migrationParts(raw);
  const applied = await execute("SELECT checksum FROM cloud_account_migrations.applied WHERE version = :version", { version });
  if (applied) {
    if (applied !== hash) throw new Error("Applied migration differs from reviewed source");
    return false;
  }
  await execute(`DO $cloud_ddl$ BEGIN ${migration} END $cloud_ddl$`);
  await execute("INSERT INTO cloud_account_migrations.applied (version, checksum) VALUES (:version, :checksum)", { version, checksum: hash });
  return true;
}

async function bootstrap() {
  const {
    CLOUD_DB_CLUSTER_ARN: resourceArn, CLOUD_DB_ADMIN_SECRET_ARN: secretArn,
    CLOUD_DB_RUNTIME_SECRET_ARN: runtimeSecretArn
  } = process.env;
  if (!resourceArn || !secretArn || !runtimeSecretArn || secretArn === runtimeSecretArn) {
    throw new Error("Separate operator and application database credentials are required");
  }
  const raw = await readFile(new URL("../sql/cloud-accounts/001-accounts.sql", import.meta.url), "utf8");
  const registry = await readFile(new URL("../sql/cloud-accounts/002-registry.sql", import.meta.url), "utf8");
  const observation = await readFile(new URL("../sql/cloud-accounts/003-workload-observation.sql", import.meta.url), "utf8");
  const organizationName = await readFile(new URL("../sql/cloud-accounts/004-organization-name.sql", import.meta.url), "utf8");
  const workloadConfiguration = await readFile(new URL("../sql/cloud-accounts/005-workload-configuration.sql", import.meta.url), "utf8");
  const configurationHistory = await readFile(new URL("../sql/cloud-accounts/006-configuration-history.sql", import.meta.url), "utf8");
  const accountEmailAdmission = await readFile(new URL("../sql/cloud-accounts/007-account-email-admission.sql", import.meta.url), "utf8");
  const accountEmailCapacity = await readFile(new URL("../sql/cloud-accounts/008-account-email-capacity.sql", import.meta.url), "utf8");
  const accountEmailProviderWindow = await readFile(new URL("../sql/cloud-accounts/009-account-email-provider-window.sql", import.meta.url), "utf8");
  const repositoryBinding = await readFile(new URL("../sql/cloud-accounts/010-repository-binding.sql", import.meta.url), "utf8");
  const repositoryBindingTransitions = await readFile(new URL("../sql/cloud-accounts/011-repository-binding-transitions.sql", import.meta.url), "utf8");
  const connection = { resourceArn, secretArn, database: "paige_cloud" };
  const data = new RDSDataClient({});
  const { transactionId } = await data.send(new BeginTransactionCommand(connection));
  if (!transactionId) throw new Error("Database migration transaction was not created");
  const transaction = { ...connection, transactionId };

  async function execute(sql, params = {}) {
    const parameters = Object.entries(params).map(([name, value]) => ({ name, value: { stringValue: value } }));
    const response = await data.send(new ExecuteStatementCommand({ ...transaction, sql, parameters }));
    return response.records?.[0]?.[0]?.stringValue;
  }

  let applied;
  try {
    applied = await applyAccountMigration(raw, execute, async () => {
      const secrets = new SecretsManagerClient({});
      const secret = await secrets.send(new GetSecretValueCommand({ SecretId: runtimeSecretArn }));
      return JSON.parse(secret.SecretString ?? "{}");
    });
    applied = (await applyAdditiveMigration("002", registry, execute)) || applied;
    applied = (await applyAdditiveMigration("003", observation, execute)) || applied;
    applied = (await applyAdditiveMigration("004", organizationName, execute)) || applied;
    applied = (await applyAdditiveMigration("005", workloadConfiguration, execute)) || applied;
    applied = (await applyAdditiveMigration("006", configurationHistory, execute)) || applied;
    applied = (await applyAdditiveMigration("007", accountEmailAdmission, execute)) || applied;
    applied = (await applyAdditiveMigration("008", accountEmailCapacity, execute)) || applied;
    applied = (await applyAdditiveMigration("009", accountEmailProviderWindow, execute)) || applied;
    applied = (await applyAdditiveMigration("010", repositoryBinding, execute)) || applied;
    applied = (await applyAdditiveMigration("011", repositoryBindingTransitions, execute)) || applied;
    await data.send(new CommitTransactionCommand(transaction));
  } catch (error) {
    try {
      await data.send(new RollbackTransactionCommand(transaction));
    } catch {
      // A lost commit response is reconciled by re-reading the recorded checksum on retry.
    }
    throw error;
  }

  const check = await data.send(new ExecuteStatementCommand({
    ...connection, secretArn: runtimeSecretArn,
    sql: `SELECT current_user = 'paige_cloud_app'
      AND has_function_privilege(current_user, 'cloud_accounts.account_details(uuid)', 'EXECUTE')
      AND has_function_privilege(current_user, 'cloud_accounts.rename_organization(uuid, uuid, text, text)', 'EXECUTE')
      AND has_function_privilege(current_user, 'cloud_accounts.registry_list_projects(uuid, uuid)', 'EXECUTE')
      AND has_function_privilege(current_user, 'cloud_accounts.reserve_workload_observation(uuid, uuid, text, text, text)', 'EXECUTE')
      AND NOT has_table_privilege(current_user, 'cloud_accounts.accounts', 'SELECT, INSERT, UPDATE, DELETE')
      AND NOT has_table_privilege(current_user, 'cloud_accounts.organizations', 'SELECT, INSERT, UPDATE, DELETE')
      AND NOT has_table_privilege(current_user, 'cloud_accounts.registry_applications', 'SELECT, INSERT, UPDATE, DELETE')
      AND NOT has_table_privilege(current_user, 'cloud_accounts.workload_observation_budget', 'SELECT, INSERT, UPDATE, DELETE')
      AND has_function_privilege(current_user, 'cloud_accounts.read_workload_configuration(uuid, uuid, text, text, text, integer)', 'EXECUTE')
      AND has_function_privilege(current_user, 'cloud_accounts.save_workload_configuration(uuid, uuid, text, text, text, integer, text, integer)', 'EXECUTE')
      AND has_function_privilege(current_user, 'cloud_accounts.save_workload_configuration_v2(uuid, uuid, text, text, text, integer, text, integer)', 'EXECUTE')
      AND NOT has_function_privilege(current_user, 'cloud_accounts.save_workload_configuration_revision(uuid, uuid, text, text, text, integer, text, integer, boolean)', 'EXECUTE')
      AND has_function_privilege(current_user, 'cloud_accounts.reserve_account_email(text, text, text)', 'EXECUTE')
      AND has_function_privilege(current_user, 'cloud_accounts.read_repository_binding(uuid, uuid, text, text, text)', 'EXECUTE')
      AND NOT has_table_privilege(current_user, 'cloud_accounts.account_email_admission', 'SELECT, INSERT, UPDATE, DELETE')
      AND NOT has_table_privilege(current_user, 'cloud_accounts.repository_bindings', 'SELECT, INSERT, UPDATE, DELETE, TRUNCATE, REFERENCES, TRIGGER')
      AND NOT has_table_privilege(current_user, 'cloud_accounts.repository_binding_operations', 'SELECT, INSERT, UPDATE, DELETE, TRUNCATE, REFERENCES, TRIGGER')
      AND NOT has_function_privilege(current_user, 'cloud_accounts.record_repository_binding_operation(uuid, uuid, uuid, text, text, text, uuid, uuid, text, text, text, text, text, text)', 'EXECUTE')
      AND NOT has_table_privilege(current_user, 'cloud_accounts.workload_configuration_revisions', 'SELECT, INSERT, UPDATE, DELETE')`
  }));
  if (check.records?.[0]?.[0]?.booleanValue !== true) throw new Error("Application database login was not confirmed");
  console.log(applied ? "Cloud accounts migration and application login confirmed" : "Existing migration and application login confirmed");
}

if (process.argv[1] && import.meta.url === pathToFileURL(resolve(process.argv[1])).href) {
  bootstrap().catch(() => {
    console.error("Cloud account database readiness was not confirmed. Check the migration ledger and application credential.");
    process.exitCode = 1;
  });
}
