import { Buffer } from "node:buffer";
import { createHmac, timingSafeEqual } from "node:crypto";
import { isIP } from "node:net";
import { setTimeout as delay } from "node:timers/promises";
import { developerCapabilities, developerCapabilitiesPath } from "./developer-capabilities.mjs";

const prefix = "/api/cloud/auth";
const registryPath = /^\/api\/cloud\/v1\/organizations\/([a-fA-F0-9-]{36})\/projects(?:\/([a-z0-9][a-z0-9-]{0,47})\/applications)?$/;
const workloadPath = /^\/api\/cloud\/v1\/organizations\/([a-f0-9-]{36})\/projects\/([a-z0-9][a-z0-9-]{0,47})\/applications\/([a-z0-9][a-z0-9-]{0,47})\/environments\/([a-z0-9][a-z0-9-]{0,47})\/(inspection|configuration|published-releases|repository-binding)(?:\/revisions\/([1-9][0-9]{0,9}))?$/;
const maxConfigurationRevision = 2147483647;
const resourceId = /^[a-z0-9][a-z0-9-]{0,47}$/;
const repositoryName = /^[a-zA-Z0-9][a-zA-Z0-9-]{0,38}\/[a-zA-Z0-9_.-]{1,100}$/;
const cookieName = "__Host-paige_cloud_session";
const cookieAttributes = "Path=/; Secure; HttpOnly; SameSite=Lax";
const clearSessionCookies = [cookieName + "=; " + cookieAttributes + "; Max-Age=0"];
const uuid = /^[a-f0-9]{8}(?:-[a-f0-9]{4}){3}-[a-f0-9]{12}$/i;
const jwt = /^[A-Za-z0-9_-]+\.[A-Za-z0-9_-]+\.[A-Za-z0-9_-]+$/;
const noCodeRecipient = new Set(["NotAuthorizedException", "UserNotFoundException", "InvalidParameterException"]);
const providerErrors = new Map([
  ["NotAuthorizedException", [401, "invalid_credentials"]],
  ["UserNotFoundException", [401, "invalid_credentials"]],
  ["UserNotConfirmedException", [403, "verification_required"]],
  ["UsernameExistsException", [409, "email_already_registered"]],
  ["CodeMismatchException", [400, "invalid_code"]],
  ["ExpiredCodeException", [400, "expired_code"]],
  ["InvalidPasswordException", [400, "invalid_password"]],
  ["InvalidParameterException", [400, "invalid_input"]],
  ["LimitExceededException", [429, "try_again_later"]],
  ["TooManyRequestsException", [429, "try_again_later"]],
  ["TooManyFailedAttemptsException", [429, "try_again_later"]]
]);

class RequestError extends Error {
  constructor(status, code) {
    super(code);
    this.status = status;
    this.code = code;
  }
}

function reply(statusCode, body, cookies) {
  return {
    statusCode,
    headers: {
      ...(body !== undefined && { "content-type": "application/json; charset=utf-8" }),
      "cache-control": "no-store",
      "x-content-type-options": "nosniff"
    },
    body: body === undefined ? "" : JSON.stringify(body),
    ...(cookies ? { cookies } : {})
  };
}

function readJson(event, keys) {
  if (event.isBase64Encoded || typeof event.body !== "string" ||
      Buffer.byteLength(event.body) > 8192 ||
      event.headers?.["content-type"]?.split(";")[0]?.trim().toLowerCase() !== "application/json") {
    throw new RequestError(400, "invalid_body");
  }
  let value;
  try {
    value = JSON.parse(event.body);
  } catch {
    throw new RequestError(400, "invalid_body");
  }
  if (!value || typeof value !== "object" || Array.isArray(value) ||
      Object.keys(value).some(key => !keys.includes(key))) {
    throw new RequestError(400, "invalid_body");
  }
  return value;
}

function normalizeEmail(input) {
  return typeof input === "string" ? input.trim().toLowerCase() : "";
}

function requireEmail(input) {
  const email = normalizeEmail(input);
  if (email.length > 254 || !/^[^\s@]+@[^\s@.]+(?:\.[^\s@.]+)+$/.test(email)) {
    throw new RequestError(400, "invalid_email");
  }
  return email;
}

function requirePassword(password, enrollment = false) {
  if (typeof password !== "string" || !password.length ||
      (enrollment ? password.length > 256 || [...password].length < 15 || /\s/u.test(password) : Buffer.byteLength(password) > 512)) {
    throw new RequestError(400, "invalid_password");
  }
  return password;
}

function requireCode(code) {
  if (typeof code !== "string" || !/^[0-9]{6}$/.test(code)) throw new RequestError(400, "invalid_code");
  return code;
}

function requireName(value, allowEmpty = false) {
  if (typeof value !== "string" || [...value.trim()].length > 120 || (!allowEmpty && !value.trim())) {
    throw new RequestError(400, "invalid_name");
  }
  return value.trim();
}

function sessionToken(event) {
  if (!Array.isArray(event.cookies)) return null;
  const values = event.cookies.flatMap(line => line.split(";"))
    .map(part => part.trim()).filter(part => part.startsWith(cookieName + "="));
  if (values.length !== 1) return null;
  const value = values[0].slice(cookieName.length + 1);
  return value.length <= 3800 && jwt.test(value) ? value : null;
}

function requireResourceId(value) {
  if (typeof value !== "string" || !resourceId.test(value)) throw new RequestError(400, "invalid_identifier");
  return value;
}

export function createAccountHandler({ origin, evaluatorEmails, identity, records, edgeKey, consoleHtml, workloadObservation,
  enrollmentMode = "evaluator-only" }) {
  const site = new URL(origin);
  if (site.protocol !== "https:" || site.origin !== origin) throw new Error("An HTTPS site origin is required");
  if (typeof edgeKey !== "string" || Buffer.byteLength(edgeKey) < 32) throw new Error("A private edge key is required");
  const expectedKey = Buffer.from(edgeKey);
  if (!["evaluator-only", "members", "public"].includes(enrollmentMode)) throw new Error("Invalid account enrollment mode");
  const publicAccounts = enrollmentMode !== "evaluator-only";
  const eligible = new Set(publicAccounts ? [] : evaluatorEmails.map(requireEmail));
  if (!publicAccounts && !eligible.size) throw new Error("An evaluator allowlist is required for the private pilot");
  if (typeof records.reserveAccountEmail !== "function") throw new Error("Account email admission is required");
  const allowsAccount = email => publicAccounts || eligible.has(email);

  async function reserveEmail(event, lane, email) {
    const address = event.headers?.["x-paige-viewer-ip"];
    if (typeof address !== "string" || !isIP(address)) throw new RequestError(403, "edge_required");
    const fingerprint = (kind, value) => createHmac("sha256", expectedKey).update(kind + "\0" + value).digest("hex");
    const reserved = await records.reserveAccountEmail(lane, fingerprint("account-email-network", address),
      fingerprint("account-email-recipient", email));
    if (reserved !== true) throw new RequestError(429, "try_again_later");
  }

  async function requireIdentity(token) {
    if (!token) throw new RequestError(401, "sign_in_required");
    const user = await identity.verify(token);
    const email = normalizeEmail(user?.email);
    if (!email || !allowsAccount(email)) {
      throw new RequestError(401, "sign_in_required");
    }
    return user;
  }

  async function requireAccount(event) {
    const user = await requireIdentity(sessionToken(event));
    const account = await records.findIdentity(user);
    if (!account) throw new RequestError(401, "sign_in_required");
    return account;
  }

  async function openVerifiedSession(email, password) {
    for (let attempt = 0; attempt < 2; attempt += 1) {
      const result = await identity.signIn(email, password);
      const token = result?.token;
      if (typeof token !== "string" || token.length > 3800 || !jwt.test(token) ||
          !Number.isSafeInteger(result.lifetimeSeconds) || result.lifetimeSeconds <= 0) break;

      const user = await identity.verify(token);
      if (user) {
        if (normalizeEmail(user.email) !== email) break;
        return { token, user, lifetime: Math.min(result.lifetimeSeconds, 3600) };
      }

      // Cognito can reject a token minted immediately after global sign-out.
      // Mint a fresh token once after the provider's timestamp has advanced.
      if (attempt === 0) await delay(1250);
    }
    throw new RequestError(503, "account_service_unavailable");
  }

  async function handleRegistry(event, method, organization, project) {
    if (!uuid.test(organization) || !["GET", "POST"].includes(method)) throw new RequestError(404, "not_found");
    if (method === "POST" && event.headers?.origin !== origin) throw new RequestError(403, "origin_denied");
    const actor = await requireAccount(event);
    let result;
    if (method === "GET") {
      result = project ? await records.registryApplications(actor, organization, project)
        : await records.registryProjects(actor, organization);
    } else if (project) {
      const body = readJson(event, ["id", "name", "kind", "sourceRepository", "environment"]);
      if (!["application", "service"].includes(body.kind)) throw new RequestError(400, "invalid_kind");
      const repository = body.sourceRepository ?? "";
      if (typeof repository !== "string" || (repository !== "" && !repositoryName.test(repository))) {
        throw new RequestError(400, "invalid_repository");
      }
      result = await records.registryRegisterApplication(actor, organization, project, {
        id: requireResourceId(body.id), name: requireName(body.name), kind: body.kind, repository,
        environment: requireResourceId(body.environment)
      });
    } else {
      const body = readJson(event, ["id", "name"]);
      result = await records.registryCreateProject(actor, organization, requireResourceId(body.id), requireName(body.name));
    }
    if (result === null || result === undefined) throw new RequestError(404, "not_found");
    if (["registration_conflict", "registry_limit"].includes(result.error)) throw new RequestError(409, result.error);
    if (method === "GET" && project && workloadObservation) {
      result = result.map(record => {
        const environment = workloadObservation.targetFor(organization, project, record);
        return environment ? {
          ...record, inspectionEnvironment: environment,
          ...(workloadObservation.releasesAvailable && { releaseInventoryEnvironment: environment })
        } : record;
      });
    }
    return reply(200, result);
  }

  async function handleConfiguration(event, method, [, organization, project, application, environment, , revision]) {
    if (!uuid.test(organization) || !["GET", "PUT"].includes(method) ||
        (revision && (method !== "GET" || Number(revision) > maxConfigurationRevision))) {
      throw new RequestError(404, "not_found");
    }
    if (method === "PUT" && event.headers?.origin !== origin) throw new RequestError(403, "origin_denied");
    const actor = await requireAccount(event);
    const scope = { organization, project, application, environment };
    let result;
    if (method === "GET") {
      result = await records.readWorkloadConfiguration(actor, scope, revision);
    } else {
      const { expectedRevision, logLevel, requestTimeoutMs } = readJson(event, ["expectedRevision", "logLevel", "requestTimeoutMs"]);
      if (!Number.isInteger(expectedRevision) || expectedRevision < 0 || expectedRevision > maxConfigurationRevision ||
          !["error", "warn", "info"].includes(logLevel) ||
          !Number.isInteger(requestTimeoutMs) || requestTimeoutMs < 100 || requestTimeoutMs > 30000) {
        throw new RequestError(400, "invalid_configuration");
      }
      result = await records.saveWorkloadConfiguration(actor, scope, { expectedRevision, logLevel, requestTimeoutMs });
    }
    if (result == null) throw new RequestError(404, "not_found");
    if (result.error === "invalid_configuration") throw new RequestError(400, result.error);
    if (["configuration_changed", "configuration_limit"].includes(result.error)) throw new RequestError(409, result.error);
    if (result.error === "configuration_rate_limited") throw new RequestError(429, result.error);
    return reply(200, result);
  }

  async function handleObservation(event, method, [, organization, project, application, environment]) {
    if (!workloadObservation || method !== "POST" || !uuid.test(organization)) throw new RequestError(404, "not_found");
    if (event.headers?.origin !== origin) throw new RequestError(403, "origin_denied");
    const actor = await requireAccount(event);
    const registered = await records.registryApplications(actor, organization, project);
    const result = await workloadObservation.inspect(actor, { organization, project, application, environment }, registered);
    if (result.status === 200) return reply(200, result.observation);
    if (result.status === 404) throw new RequestError(404, "not_found");
    if (result.status === 403) throw new RequestError(403, "inspection_denied");
    if (result.status === 429) throw new RequestError(429, "inspection_limited");
    throw new RequestError(503, "inspection_unavailable");
  }

  async function handleReleaseInventory(event, method, [, organization, project, application, environment]) {
    if (!workloadObservation?.releasesAvailable || method !== "POST" || !uuid.test(organization)) {
      throw new RequestError(404, "not_found");
    }
    if (event.headers?.origin !== origin) throw new RequestError(403, "origin_denied");
    const actor = await requireAccount(event);
    const scope = { organization, project, application, environment };
    const registered = await records.registryApplications(actor, organization, project);
    const result = await workloadObservation.listReleases(actor, scope, registered);
    if (result.status === 404) throw new RequestError(404, "not_found");
    if (result.status === 403) throw new RequestError(403, "inspection_denied");
    if (result.status === 429) throw new RequestError(429, "inspection_limited");
    if (result.status !== 200) throw new RequestError(503, "release_inventory_unavailable");

    if (await requireAccount(event) !== actor) throw new RequestError(401, "sign_in_required");
    const current = await records.registryApplications(actor, organization, project);
    if (!workloadObservation.matches(scope, current)) throw new RequestError(404, "not_found");
    return reply(200, result.inventory);
  }

  async function handleRepositoryBinding(event, method, [, organization, project, application, environment]) {
    if (method !== "GET" || !uuid.test(organization)) throw new RequestError(404, "not_found");
    const actor = await requireAccount(event);
    const result = await records.readRepositoryBinding(actor, { organization, project, application, environment });
    if (result == null) throw new RequestError(404, "not_found");
    return reply(200, result);
  }

  async function handle(event) {
    const method = event.requestContext?.http?.method;
    const path = event.rawPath;
    const provided = Buffer.from(event.headers?.["x-paige-cloud-edge"] ?? "");
    if (provided.length !== expectedKey.length || !timingSafeEqual(provided, expectedKey)) {
      throw new RequestError(403, "edge_required");
    }
    if (path === developerCapabilitiesPath) {
      if (method !== "GET") throw new RequestError(404, "not_found");
      await requireAccount(event);
      return reply(200, developerCapabilities(workloadObservation));
    }
    if (method === "GET" && path === "/mission-control" && consoleHtml) {
      try {
        await requireAccount(event);
      } catch (error) {
        if (!(error instanceof RequestError) || error.status !== 401) throw error;
        return { statusCode: 303, headers: { location: "/sign-in", "cache-control": "no-store" }, body: "" };
      }
      return {
        statusCode: 200,
        headers: { "content-type": "text/html; charset=utf-8", "cache-control": "no-store" },
        body: consoleHtml
      };
    }
    const workload = typeof path === "string" && path.match(workloadPath);
    if (workload?.[5] === "configuration") return handleConfiguration(event, method, workload);
    if (workload?.[5] === "inspection" && !workload[6]) return handleObservation(event, method, workload);
    if (workload?.[5] === "published-releases" && !workload[6]) return handleReleaseInventory(event, method, workload);
    if (workload?.[5] === "repository-binding" && !workload[6]) return handleRepositoryBinding(event, method, workload);
    const registry = typeof path === "string" && path.match(registryPath);
    if (registry) return handleRegistry(event, method, registry[1], registry[2]);
    const route = typeof path === "string" && path.startsWith(prefix + "/") ? path.slice(prefix.length) : "";
    if (!route) throw new RequestError(404, "not_found");
    if (method !== "GET" && event.headers?.origin !== origin) throw new RequestError(403, "origin_denied");

    switch (method + " " + route) {
      case "POST /sign-up": {
        const body = readJson(event, ["email", "password"]);
        const email = requireEmail(body.email);
        if (enrollmentMode === "members" || !allowsAccount(email)) throw new RequestError(403, "registration_unavailable");
        await reserveEmail(event, "enrollment", email);
        try {
          await identity.signUp(email);
        } catch (error) {
          if (!publicAccounts || error.name !== "UsernameExistsException") throw error;
        }
        return reply(202, { next: "verify_email" });
      }
      case "POST /verify-email": {
        const body = readJson(event, ["email", "code", "password"]);
        const email = requireEmail(body.email);
        if (!allowsAccount(email)) throw new RequestError(403, "registration_unavailable");
        const code = requireCode(body.code);
        const password = requirePassword(body.password, true);
        try {
          await identity.confirmSignUp(email, code, password);
        } catch (error) {
          if (error.name === "EnrollmentPasswordUnconfirmed") throw new RequestError(503, "enrollment_password_unverified");
          if (publicAccounts && noCodeRecipient.has(error.name)) throw new RequestError(400, "invalid_code");
          throw error;
        }
        return reply(204);
      }
      case "POST /resend-code": {
        const body = readJson(event, ["email"]);
        const email = requireEmail(body.email);
        if (allowsAccount(email)) {
          await reserveEmail(event, "enrollment", email);
          try {
            await identity.resendCode(email);
          } catch (error) {
            if (!publicAccounts || !noCodeRecipient.has(error.name)) throw error;
          }
        }
        return reply(202);
      }
      case "POST /sign-in": {
        const body = readJson(event, ["email", "password"]);
        const email = requireEmail(body.email);
        const password = requirePassword(body.password);
        if (!allowsAccount(email)) throw new RequestError(401, "invalid_credentials");
        const { token, user, lifetime } = await openVerifiedSession(email, password);
        const account = await records.recordIdentity(user);
        if (!account) throw new RequestError(503, "account_service_unavailable");
        return reply(204, undefined, [cookieName + "=" + token + "; " + cookieAttributes + "; Max-Age=" + lifetime]);
      }
      case "POST /sign-out": {
        const token = sessionToken(event);
        if (token) {
          try {
            await identity.signOut(token);
          } catch (error) {
            if (error.name !== "NotAuthorizedException" && error.name !== "UserNotFoundException") throw error;
          }
        }
        return reply(204, undefined, clearSessionCookies);
      }
      case "POST /recover": {
        const body = readJson(event, ["email"]);
        const email = requireEmail(body.email);
        if (allowsAccount(email)) {
          await reserveEmail(event, "recovery", email);
          try {
            await identity.startRecovery(email);
          } catch (error) {
            if (!noCodeRecipient.has(error.name)) throw error;
          }
        }
        return reply(202);
      }
      case "POST /reset-password": {
        const body = readJson(event, ["email", "code", "password"]);
        const email = requireEmail(body.email);
        if (!allowsAccount(email)) throw new RequestError(400, "invalid_code");
        const code = requireCode(body.code);
        const password = requirePassword(body.password, true);
        try {
          await identity.finishRecovery(email, code, password);
        } catch (error) {
          if (error.name === "RecoveryRevocationUnconfirmed") {
            return reply(503, { error: "recovery_sessions_unverified" }, clearSessionCookies);
          }
          if (publicAccounts && noCodeRecipient.has(error.name)) throw new RequestError(400, "invalid_code");
          throw error;
        }
        return reply(204, undefined, clearSessionCookies);
      }
      case "GET /account": {
        const account = await records.accountDetails(await requireAccount(event));
        if (!account) throw new RequestError(401, "sign_in_required");
        return reply(200, account);
      }
      case "PATCH /account": {
        const actor = await requireAccount(event);
        const body = readJson(event, ["displayName"]);
        const account = await records.updateDisplayName(actor, requireName(body.displayName, true));
        if (!account) throw new RequestError(401, "sign_in_required");
        return reply(200, account);
      }
      case "POST /organizations": {
        const actor = await requireAccount(event);
        const body = readJson(event, ["name"]);
        const organization = await records.onboardOrganization(actor, requireName(body.name));
        if (!organization) throw new RequestError(404, "not_found");
        if (organization.error === "organization_exists") throw new RequestError(409, "organization_exists");
        return reply(200, organization);
      }
    }

    const organization = route.startsWith("/organizations/") && route.slice("/organizations/".length);
    if (method === "GET" && organization && uuid.test(organization)) {
      const result = await records.organizationDetails(await requireAccount(event), organization);
      if (result) return reply(200, result);
    }
    if (method === "PATCH" && organization && uuid.test(organization)) {
      const actor = await requireAccount(event);
      const body = readJson(event, ["expectedName", "name"]);
      const result = await records.renameOrganization(actor, organization, requireName(body.expectedName), requireName(body.name));
      if (result?.error === "organization_changed") throw new RequestError(409, "organization_changed");
      if (result) return reply(200, result);
    }
    throw new RequestError(404, "not_found");
  }

  return async event => {
    try {
      return await handle(event);
    } catch (error) {
      const [status, code] = error instanceof RequestError ? [error.status, error.code]
        : providerErrors.get(error?.name) ?? [503, "account_service_unavailable"];
      return reply(status, { error: code });
    }
  };
}
