import assert from "node:assert/strict";
import test from "node:test";
import { createAccountHandler } from "./handler.mjs";

const origin = "https://cloud.example.test";
const allowedEmails = ["a@example.test", "b@example.test"];
const tokens = ["access.a.test", "access.b.test"];
const ids = ["00000000-0000-4000-8000-000000000001", "00000000-0000-4000-8000-000000000002"];
const cookie = token => "__Host-paige_cloud_session=" + token;
const authError = name => Object.assign(new Error("private provider diagnostic"), { name });
const password = "synthetic-passphrase-for-tests";
const defaultEdgeKey = "test-only-default-edge-key-with-thirty-two-characters";

function event(method, route, { token, body, from = origin, network = "192.0.2.8" } = {}) {
  return {
    rawPath: "/api/cloud/auth" + route,
    requestContext: { http: { method } },
    headers: { origin: from, "content-type": "application/json", "x-paige-cloud-edge": defaultEdgeKey,
      "x-paige-viewer-ip": network },
    cookies: token ? [cookie(token)] : [],
    body: body === undefined ? undefined : JSON.stringify(body)
  };
}

function fixture(overrides = {}) {
  const calls = [];
  const active = new Map();
  const registered = new Map();
  const verified = new Set();
  for (const [i, email] of allowedEmails.entries()) {
    active.set(tokens[i], { issuer: "test-issuer", subject: String(i), email });
  }
  const store = new Map();
  const recordLookups = [];
  const identity = {
    async signUp(email) {
      calls.push(["signUp", email]);
      registered.set(email, true);
    },
    async confirmSignUp(email, code) {
      if (!registered.has(email) || code !== "123456" || verified.has(email)) throw authError("CodeMismatchException");
      verified.add(email);
    },
    async resendCode(email) { calls.push(["resendCode", email]); },
    async signIn(email) {
      if (!verified.has(email)) throw authError("UserNotConfirmedException");
      return { token: tokens[allowedEmails.indexOf(email)], lifetimeSeconds: 900 };
    },
    async verify(token) { return active.get(token) ?? null; },
    async signOut(token) { active.delete(token); },
    async startRecovery(email) { calls.push(["startRecovery", email]); },
    async finishRecovery(email, code) {
      if (code !== "654321") throw authError("ExpiredCodeException");
      calls.push(["finishRecovery", email]);
    },
    ...overrides.identity
  };
  const records = {
    async reserveAccountEmail() { return true; },
    async recordIdentity(user) {
      const actor = "actor-" + user.subject;
      if (!store.has(actor)) store.set(actor, { email: user.email, displayName: null, organizations: [] });
      return actor;
    },
    async findIdentity(user) {
      recordLookups.push(user.subject);
      const actor = "actor-" + user.subject;
      return store.has(actor) ? actor : null;
    },
    async accountDetails(actor) { return store.get(actor); },
    async updateDisplayName(actor, displayName) {
      const account = store.get(actor);
      account.displayName = displayName;
      return account;
    },
    async onboardOrganization(actor, name) {
      const organization = { id: ids[Number(actor.slice(-1))], role: "owner", name };
      store.get(actor).organizations.push(organization);
      return organization;
    },
    async organizationDetails(actor, id) { return store.get(actor).organizations.find(org => org.id === id); },
    ...overrides.records
  };
  const handle = createAccountHandler({ origin, evaluatorEmails: allowedEmails, identity, records, edgeKey: defaultEdgeKey, ...overrides.config });
  const request = (method, route, options) => handle(event(method, route, options));
  async function register(email) {
    assert.equal((await request("POST", "/sign-up", { body: { email, password } })).statusCode, 202);
    assert.equal((await request("POST", "/verify-email", { body: { email, code: "123456", password } })).statusCode, 204);
    return request("POST", "/sign-in", { body: { email, password } });
  }
  return { handle, request, register, calls, recordLookups };
}

test("public enrollment and recovery use email ownership and scoped accounts regardless of network", async () => {
  const email = "new-owner@example.test";
  const token = "public.owner.token";
  const reservations = [];
  let created = false;
  let verified = false;
  let active = false;
  let confirmationCalls = 0;
  const { request, handle } = fixture({
    config: { enrollmentMode: "public", evaluatorEmails: [], consoleHtml: "<main>Mission Control</main>" },
    identity: {
      async signUp(address, proposedPassword) {
        assert.equal(address, email);
        assert.equal(proposedPassword, undefined);
        if (created) throw authError("UsernameExistsException");
        created = true;
      },
      async confirmSignUp(address, code, chosenPassword) {
        confirmationCalls++;
        if (address !== email) throw authError("UserNotFoundException");
        if (verified) throw authError("NotAuthorizedException");
        if (code !== "123456") throw authError("CodeMismatchException");
        assert.equal(chosenPassword, password);
        verified = true;
      },
      async signIn() {
        if (!verified) throw authError("UserNotConfirmedException");
        active = true;
        return { token, lifetimeSeconds: 1800 };
      },
      async verify(value) {
        return active && value === token ? { issuer: "test-issuer", subject: "0", email } : null;
      },
      async startRecovery(address) {
        if (address !== email) throw authError("UserNotFoundException");
      },
      async finishRecovery(address, code) {
        if (address !== email || code !== "654321") throw authError("CodeMismatchException");
        active = false;
      }
    },
    records: { async reserveAccountEmail(...args) { reservations.push(args); return true; } }
  });
  const enroll = network => request("POST", "/sign-up", { body: { email, password }, network });
  const first = await enroll("203.0.113.9");
  assert.equal(first.statusCode, 202);
  assert.deepEqual(first, await enroll("2001:db8::9"));
  assert.equal((await request("POST", "/sign-in", { body: { email, password } })).statusCode, 403);
  const confirm = (address, code) => request("POST", "/verify-email", { body: { email: address, code, password } });
  for (const invalidPassword of ["a".repeat(257), "passphrase with spaces"]) {
    const denied = await request("POST", "/verify-email", { body: { email, code: "123456", password: invalidPassword } });
    assert.equal(denied.statusCode, 400);
    assert.equal(JSON.parse(denied.body).error, "invalid_password");
  }
  assert.equal(confirmationCalls, 0);
  assert.deepEqual(await confirm("unknown@example.test", "123456"), await confirm(email, "111111"));
  assert.equal((await confirm(email, "123456")).statusCode, 204);
  assert.equal((await confirm(email, "123456")).statusCode, 400);
  assert.equal((await request("POST", "/sign-in", { body: { email, password }, network: "2001:db8::11" })).statusCode, 204);
  const mission = value => handle({ ...event("GET", "", { token: value }), rawPath: "/mission-control" });
  assert.equal((await mission(token)).statusCode, 200);
  assert.equal((await request("GET", "/organizations/" + ids[1], { token })).statusCode, 404);
  const recover = address => request("POST", "/recover", { body: { email: address }, network: "2001:db8::11" });
  assert.deepEqual(await recover(email), await recover("unknown@example.test"));
  const reset = await request("POST", "/reset-password", { body: { email, code: "654321", password } });
  assert.equal(reset.statusCode, 204);
  assert.match(reset.cookies[0], /Max-Age=0/);
  assert.equal((await mission(token)).statusCode, 303);
  assert.notEqual(reservations[0][1], reservations[1][1]);
  assert.equal(reservations[0][2], reservations[1][2]);
  assert.ok(reservations.every(([, network, recipient]) => /^[a-f0-9]{64}$/.test(network) && /^[a-f0-9]{64}$/.test(recipient)));
});

test("email admission and same-origin controls run before contacting the provider", async () => {
  const { request, calls } = fixture({ config: { enrollmentMode: "public" },
    records: { async reserveAccountEmail() { return false; } } });
  const recipient = { email: "someone@example.test" };
  const body = { ...recipient, password };
  assert.equal((await request("POST", "/sign-up", { body, from: "https://different.example.test" })).statusCode, 403);
  assert.equal((await request("POST", "/sign-up", { body, network: "invalid" })).statusCode, 403);
  assert.equal((await request("POST", "/sign-up", { body })).statusCode, 429);
  assert.equal((await request("POST", "/recover", { body: recipient })).statusCode, 429);
  assert.equal(calls.length, 0);
});

test("the evaluator-mode account package also reserves email before provider contact", async () => {
  const { request, calls } = fixture({ records: { async reserveAccountEmail() { return false; } } });
  const email = allowedEmails[0];
  assert.equal((await request("POST", "/sign-up", { body: { email, password } })).statusCode, 429);
  assert.equal((await request("POST", "/resend-code", { body: { email } })).statusCode, 429);
  assert.equal((await request("POST", "/recover", { body: { email } })).statusCode, 429);
  assert.equal(calls.length, 0);
});

test("evaluator mode uses the same email-first password boundary during the network transition", async () => {
  const sent = [];
  const verified = [];
  const email = allowedEmails[0];
  const { request } = fixture({ identity: {
    async signUp(...args) { sent.push(args); },
    async confirmSignUp(...args) { verified.push(args); }
  } });
  assert.equal((await request("POST", "/sign-up", { body: { email, password } })).statusCode, 202);
  assert.deepEqual(sent, [[email]]);
  assert.equal((await request("POST", "/verify-email", { body: { email, code: "123456" } })).statusCode, 400);
  assert.equal(verified.length, 0);
  assert.equal((await request("POST", "/verify-email", { body: { email, code: "123456", password } })).statusCode, 204);
  assert.deepEqual(verified, [[email, "123456", password]]);
});

test("pausing enrollment keeps verification and recovery available to existing accounts", async () => {
  const { request, calls } = fixture({ config: { enrollmentMode: "members" },
    records: { async reserveAccountEmail() { return true; } } });
  const recipient = { email: "already-enrolled@example.test" };
  assert.equal((await request("POST", "/sign-up", { body: { ...recipient, password } })).statusCode, 403);
  assert.equal((await request("POST", "/sign-up", { body: { email: allowedEmails[0], password } })).statusCode, 403);
  assert.equal((await request("POST", "/resend-code", { body: recipient })).statusCode, 202);
  assert.equal((await request("POST", "/recover", { body: recipient })).statusCode, 202);
  assert.deepEqual(calls, [["resendCode", recipient.email], ["startRecovery", recipient.email]]);
});

test("ordinary account requests do not depend on the recipient domain or a configured pilot list", async () => {
  const { request, calls } = fixture({ config: { enrollmentMode: "public", evaluatorEmails: [] } });
  const recipients = ["member+cloud@gmail.com", "admin@nonprofit.org", "engineer@team.example.co.uk"];
  for (const email of recipients) {
    assert.equal((await request("POST", "/sign-up", { body: { email } })).statusCode, 202);
    assert.equal((await request("POST", "/recover", { body: { email } })).statusCode, 202);
  }
  assert.deepEqual(calls, recipients.flatMap(email => [["signUp", email], ["startRecovery", email]]));
});

test("organization name updates derive the actor and enforce same-origin, scope and stale writes", async () => {
  const changes = [];
  const { request, register } = fixture({ records: {
    async renameOrganization(...args) {
      changes.push(args);
      const [actor, organization, expectedName, name] = args;
      if (actor !== "actor-0" || organization !== ids[0]) return null;
      if (expectedName !== "Original") return { error: "organization_changed" };
      return { id: organization, name, role: "owner" };
    }
  } });
  for (const email of allowedEmails) await register(email);
  const route = "/organizations/" + ids[0];
  const body = { name: "Updated", expectedName: "Original" };
  assert.equal((await request("PATCH", route, { body })).statusCode, 401);
  assert.equal((await request("PATCH", route, { token: tokens[0], body, from: "https://different.example.test" })).statusCode, 403);
  assert.equal((await request("PATCH", route, { token: tokens[0], body: { ...body, actor: "actor-1" } })).statusCode, 400);
  assert.equal(changes.length, 0);
  assert.equal((await request("PATCH", route, { token: tokens[1], body })).statusCode, 404);
  const stale = await request("PATCH", route, { token: tokens[0], body: { ...body, expectedName: "Stale" } });
  assert.equal(stale.statusCode, 409);
  const result = await request("PATCH", route, { token: tokens[0], body });
  assert.equal(result.statusCode, 200);
  assert.deepEqual(JSON.parse(result.body), { id: ids[0], name: "Updated", role: "owner" });
  assert.deepEqual(changes.at(-1), ["actor-0", ids[0], "Original", "Updated"]);
});

test("workload configuration uses current session, exact scope, bounded values and same-origin writes", async () => {
  const calls = [];
  const { handle, register } = fixture({ records: {
    async readWorkloadConfiguration(actor, scope, revision) {
      calls.push({ actor, scope, revision });
      return actor === "actor-0" && scope.organization === ids[0] ? { revision: 0, configuration: null } : null;
    },
    async saveWorkloadConfiguration(actor, scope, body) {
      calls.push({ actor, scope, body });
      if (actor !== "actor-0" || scope.organization !== ids[0]) return null;
      return { error: body.expectedRevision === 33 ? "configuration_rate_limited" : "configuration_changed" };
    },
  } });
  for (const email of allowedEmails) await register(email);
  const path = `/api/cloud/v1/organizations/${ids[0]}/projects/project/applications/app/environments/development/configuration`;
  const request = (method, options, suffix = "") =>
    handle({ ...event(method, "", options), rawPath: path + suffix });
  const body = { expectedRevision: 0, logLevel: "info", requestTimeoutMs: 2500 };
  assert.equal((await request("GET")).statusCode, 401);
  assert.equal((await request("PUT", { token: tokens[0], body, from: "https://foreign.example.test" })).statusCode, 403);
  for (const invalid of [{ requestTimeoutMs: 1.5 }, { expectedRevision: 2147483648 }, { logLevel: "debug" },
    { destination: "secret" }, { requestTimeoutMs: 30001 }]) {
    assert.equal((await request("PUT", { token: tokens[0], body: { ...body, ...invalid } })).statusCode, 400);
  }
  assert.equal((await request("GET", { token: tokens[0] }, "/revisions/2147483648")).statusCode, 404);
  assert.equal((await request("PUT", { token: tokens[0], body }, "/revisions/1")).statusCode, 404);
  assert.equal(calls.length, 0);
  assert.equal((await request("GET", { token: tokens[1] })).statusCode, 404);
  const empty = await request("GET", { token: tokens[0] });
  assert.equal(empty.statusCode, 200);
  assert.equal(empty.headers["cache-control"], "no-store");
  assert.deepEqual(JSON.parse(empty.body), { revision: 0, configuration: null });
  assert.equal((await request("GET", { token: tokens[0] }, "/revisions/1")).statusCode, 200);
  assert.equal(calls.at(-1).revision, "1");
  const conflict = await request("PUT", { token: tokens[0], body });
  assert.equal(conflict.statusCode, 409);
  assert.equal(JSON.parse(conflict.body).error, "configuration_changed");
  assert.deepEqual(calls.at(-1), {
    actor: "actor-0", scope: { organization: ids[0], project: "project", application: "app", environment: "development" }, body
  });
  assert.equal((await request("GET", { token: tokens[0] }, "/revisions/33")).statusCode, 200);
  assert.equal(calls.at(-1).revision, "33");
  const limited = await request("PUT", { token: tokens[0], body: { ...body, expectedRevision: 33 } });
  assert.equal(limited.statusCode, 429);
  assert.equal(JSON.parse(limited.body).error, "configuration_rate_limited");
});

test("evaluator registration requires confirmation and keeps provider tokens out of the response body", async () => {
  const { request, register, calls } = fixture();
  const stranger = await request("POST", "/sign-up", { body: { email: "unlisted@example.test", password } });
  assert.equal(stranger.statusCode, 403);
  assert.equal(calls.length, 0);

  const preVerification = await request("POST", "/sign-in", { body: { email: allowedEmails[0], password } });
  assert.equal(preVerification.statusCode, 403);
  assert.equal(preVerification.cookies, undefined);

  const response = await register(allowedEmails[0]);
  assert.equal(response.statusCode, 204);
  assert.equal(response.body, "");
  assert.equal(response.headers["content-type"], undefined);
  assert.equal(response.headers["cache-control"], "no-store");
  assert.deepEqual(response.cookies, [
    cookie(tokens[0]) + "; Path=/; Secure; HttpOnly; SameSite=Lax; Max-Age=900"
  ]);
  const replay = await request("POST", "/verify-email", { body: { email: allowedEmails[0], code: "123456", password } });
  assert.equal(replay.statusCode, 400);
});

test("onboarding and account management derive the actor from the current credential", async () => {
  const { request, register } = fixture();
  for (const email of allowedEmails) assert.equal((await register(email)).statusCode, 204);
  for (const [i, token] of tokens.entries()) {
    const result = await request("POST", "/organizations", { token, body: { name: "Organization " + i } });
    assert.equal(result.statusCode, 200);
    assert.equal(JSON.parse(result.body).id, ids[i]);
  }
  for (const [i, token] of tokens.entries()) {
    const own = await request("GET", "/organizations/" + ids[i], { token });
    const foreign = await request("GET", "/organizations/" + ids[1 - i], { token });
    assert.equal(own.statusCode, 200);
    assert.equal(foreign.statusCode, 404);
    assert.equal(foreign.body, '{"error":"not_found"}');
  }
  const invalid = await request("PATCH", "/account", {
    token: tokens[0], body: { displayName: "Other", actor: "actor-1" }
  });
  assert.equal(invalid.statusCode, 400);
  assert.equal((await request("PATCH", "/account", {
    token: tokens[0], body: { displayName: "Updated" }
  })).statusCode, 200);
  assert.equal(JSON.parse((await request("GET", "/account", { token: tokens[0] })).body).displayName, "Updated");
  assert.equal(JSON.parse((await request("GET", "/account", { token: tokens[1] })).body).displayName, null);
});

test("sign-in retries once when a newly issued token is rejected and only sets a verified cookie", async () => {
  const oldToken = "provider.rejected.token";
  const newToken = "provider.accepted.token";
  const email = allowedEmails[0];
  let attempts = 0;
  let writes = 0;
  const { request } = fixture({
    identity: {
      async signIn() {
        attempts += 1;
        return { token: attempts === 1 ? oldToken : newToken, lifetimeSeconds: 900 };
      },
      async verify(token) {
        return token === newToken ? { issuer: "test-issuer", subject: "0", email } : null;
      }
    },
    records: {
      async recordIdentity() { writes += 1; return "actor-0"; }
    }
  });
  const response = await request("POST", "/sign-in", { body: { email, password } });
  assert.equal(attempts, 2);
  assert.equal(writes, 1);
  assert.equal(response.statusCode, 204);
  assert.match(response.cookies[0], /^__Host-paige_cloud_session=provider\.accepted\.token;/);
});

test("persistent token rejection issues no cookie and records no account", async () => {
  let attempts = 0;
  const { request } = fixture({
    identity: {
      async signIn() { attempts += 1; return { token: tokens[0], lifetimeSeconds: 900 }; },
      async verify() { return null; }
    },
    records: {
      async recordIdentity() { assert.fail("Rejected tokens must not write identity records"); }
    }
  });
  const response = await request("POST", "/sign-in", { body: { email: allowedEmails[0], password } });
  assert.equal(attempts, 2);
  assert.equal(response.statusCode, 503);
  assert.equal(response.cookies, undefined);
});

test("credentials rejected by the provider are not retried", async () => {
  let attempts = 0;
  const { request } = fixture({
    identity: {
      async signIn() { attempts += 1; throw authError("NotAuthorizedException"); }
    }
  });
  const response = await request("POST", "/sign-in", { body: { email: allowedEmails[0], password } });
  assert.equal(attempts, 1);
  assert.equal(response.statusCode, 401);
  assert.equal(response.cookies, undefined);
});

test("invalid, unavailable, and signed-out sessions fail closed before account reads", async () => {
  const { request, register, recordLookups } = fixture();
  await register(allowedEmails[0]);
  assert.equal((await request("GET", "/account")).statusCode, 401);
  assert.equal((await request("GET", "/account", { token: "expired.token.test" })).statusCode, 401);
  assert.equal((await request("GET", "/account", { token: "malformed" })).statusCode, 401);
  assert.equal(recordLookups.length, 0);
  assert.equal((await request("POST", "/sign-out", { token: tokens[0], from: "https://other.example.test" })).statusCode, 403);
  assert.equal((await request("GET", "/account", { token: tokens[0] })).statusCode, 200);
  const signedOut = await request("POST", "/sign-out", { token: tokens[0] });
  assert.equal(signedOut.statusCode, 204);
  assert.match(signedOut.cookies[0], /Max-Age=0/);
  assert.equal((await request("GET", "/account", { token: tokens[0] })).statusCode, 401);
  assert.equal(recordLookups.length, 1);
});

test("account recovery suppresses unlisted addresses and validates reset confirmation", async () => {
  const { request, calls } = fixture();
  const admitted = await request("POST", "/recover", { body: { email: allowedEmails[0] } });
  const omitted = await request("POST", "/recover", { body: { email: "other@example.test" } });
  assert.deepEqual(admitted, omitted);
  assert.equal(admitted.headers["content-type"], undefined);
  assert.deepEqual(calls, [["startRecovery", allowedEmails[0]]]);
  const expired = await request("POST", "/reset-password", {
    body: { email: allowedEmails[0], code: "111111", password }
  });
  assert.equal(expired.statusCode, 400);
  assert.equal(expired.body, '{"error":"expired_code"}');
  const success = await request("POST", "/reset-password", {
    body: { email: allowedEmails[0], code: "654321", password }
  });
  assert.equal(success.statusCode, 204);
});

test("the private edge and session gate protect the console before returning its document", async () => {
  const edgeKey = "test-only-secret-with-thirty-two-characters";
  const consoleHtml = "<main>Workspace</main>";
  const { handle } = fixture({ config: { edgeKey, consoleHtml } });
  const page = event("GET", "/account");
  page.rawPath = "/mission-control";
  delete page.headers["x-paige-cloud-edge"];
  assert.equal((await handle(page)).statusCode, 403);
  page.headers["x-paige-cloud-edge"] = edgeKey.toUpperCase();
  assert.equal((await handle(page)).statusCode, 403);

  async function request(method, route, options) {
    const candidate = event(method, route, options);
    candidate.headers["x-paige-cloud-edge"] = edgeKey;
    return handle(candidate);
  }
  page.headers["x-paige-cloud-edge"] = edgeKey;
  const signedOut = await handle(page);
  assert.equal(signedOut.statusCode, 303);
  assert.equal(signedOut.headers.location, "/sign-in");
  const email = allowedEmails[0];
  await request("POST", "/sign-up", { body: { email, password } });
  await request("POST", "/verify-email", { body: { email, code: "123456", password } });
  await request("POST", "/sign-in", { body: { email, password } });
  page.cookies = [cookie(tokens[0])];
  const signedIn = await handle(page);
  assert.equal(signedIn.statusCode, 200);
  assert.equal(signedIn.body, consoleHtml);
  assert.equal(signedIn.headers["cache-control"], "no-store");
  await request("POST", "/sign-out", { token: tokens[0] });
  assert.equal((await handle(page)).statusCode, 303);
});

test("upstream failures neither disclose diagnostics nor issue a cookie or report revocation", async () => {
  const failed = fixture({ records: { async recordIdentity() { throw new Error("opaque internal error"); } } });
  const response = await failed.register(allowedEmails[0]);
  assert.equal(response.statusCode, 503);
  assert.equal(response.body, '{"error":"account_service_unavailable"}');
  assert.equal(response.cookies, undefined);
  const unrevoked = fixture({ identity: { async signOut() { throw new Error("service unavailable"); } } });
  await unrevoked.register(allowedEmails[0]);
  const unsuccessful = await unrevoked.request("POST", "/sign-out", { token: tokens[0] });
  assert.equal(unsuccessful.statusCode, 503);
  assert.equal(unsuccessful.cookies, undefined);
});

test("the versioned registry derives its actor from the session and validates inputs before writing", async () => {
  const writes = [];
  const { handle, register } = fixture({ records: {
    async registryProjects(actor, organization) { return actor === "actor-0" && organization === ids[0] ? [] : null; },
    async registryCreateProject(...args) { writes.push(args); return { id: args[2] }; },
    async registryRegisterApplication(...args) { writes.push(args); return { error: "registration_conflict" }; }
  } });
  await register(allowedEmails[0]);
  const base = "/api/cloud/v1/organizations/" + ids[0] + "/projects";
  const request = (method, rawPath, options) => handle({ ...event(method, "", options), rawPath });
  assert.equal((await request("GET", base)).statusCode, 401);
  assert.deepEqual(JSON.parse((await request("GET", base, { token: tokens[0] })).body), []);
  assert.equal((await request("POST", base, { token: tokens[0], from: "https://other.example.test",
    body: { id: "workspace", name: "Workspace" } })).statusCode, 403);
  assert.equal((await request("POST", base, { token: tokens[0],
    body: { id: "workspace", name: "Workspace", actor: "someone else" } })).statusCode, 400);
  assert.equal((await request("POST", base, { token: tokens[0],
    body: { id: "workspace", name: "Workspace" } })).statusCode, 200);
  const appPath = base + "/workspace/applications";
  const app = { id: "second-app", name: "Second app", kind: "application", environment: "development" };
  assert.equal((await request("POST", appPath, { token: tokens[0],
    body: { ...app, sourceRepository: "https://example.test/token" } })).statusCode, 400);
  assert.equal((await request("POST", appPath, { token: tokens[0],
    body: { ...app, sourceRepository: "example/source" } })).statusCode, 409);
  assert.deepEqual(writes, [
    ["actor-0", ids[0], "workspace", "Workspace"],
    ["actor-0", ids[0], "workspace", { id: "second-app", name: "Second app", kind: "application",
      repository: "example/source", environment: "development" }]
  ]);
});

test("the developer capability reference is versioned, no-store, and session-gated", async () => {
  const developerPath = "/api/cloud/v1/developer/capabilities";
  for (const observation of [undefined, { releasesAvailable: false }, { releasesAvailable: true }]) {
    const { handle, register, request } = fixture({ config: { workloadObservation: observation } });
    const catalog = (method, token) => handle({ ...event(method, "", { token }), rawPath: developerPath });
    assert.equal((await catalog("GET")).statusCode, 401);
    await register(allowedEmails[0]);
    assert.equal((await catalog("POST", tokens[0])).statusCode, 404);
    const result = await catalog("GET", tokens[0]);
    assert.equal(result.statusCode, 200);
    assert.equal(result.headers["cache-control"], "no-store");
    const reference = JSON.parse(result.body);
    assert.equal(reference.schema, "paige.cloud.developer-capabilities.v1");
    assert.equal(reference.authentication, "cloud-account-session");
    assert.deepEqual(Object.keys(reference).sort(), ["authentication", "operations", "schema"]);
    assert.deepEqual(reference.operations.map(operation => operation.id), [
      "registry.projects.list", "registry.applications.list", "repository.binding.read", "configuration.read",
      ...(observation ? ["workload.inspection.read"] : []),
      ...(observation?.releasesAvailable ? ["workload.releases.read"] : [])
    ]);
    assert.equal(reference.operations.find(row => row.id === "repository.binding.read").path.endsWith("/{environment}/repository-binding"), true);
    assert.equal((await request("POST", "/sign-out", { token: tokens[0] })).statusCode, 204);
    assert.equal((await catalog("GET", tokens[0])).statusCode, 401);
  }
});

test("repository binding is a session-derived read for one registered environment", async () => {
  const reads = [];
  const binding = { repository: "example/source", repositoryId: "981547682137",
    ref: "refs/heads/main", recordedAt: "2026-11-27T01:00:00Z" };
  const { handle, register } = fixture({ records: {
    async readRepositoryBinding(actor, scope) {
      reads.push([actor, scope]);
      if (actor !== "actor-0" || scope.environment === "missing") return null;
      return { binding: scope.environment === "development" ? binding : null };
    }
  } });
  await register(allowedEmails[0]);
  await register(allowedEmails[1]);
  const base = `/api/cloud/v1/organizations/${ids[0]}/projects/workspace/applications/independent/environments/`;
  const request = (environment, token, method = "GET", suffix = "") => handle({
    ...event(method, "", { token }), rawPath: base + environment + "/repository-binding" + suffix
  });
  assert.equal((await request("development")).statusCode, 401);
  assert.equal((await request("development", tokens[0], "PUT")).statusCode, 404);
  assert.equal((await request("development", tokens[0], "GET", "/revisions/1")).statusCode, 404);
  assert.equal(reads.length, 0);
  const result = await request("development", tokens[0]);
  assert.equal(result.statusCode, 200);
  assert.equal(result.headers["cache-control"], "no-store");
  assert.deepEqual(JSON.parse(result.body), { binding });
  assert.deepEqual(reads[0], ["actor-0", {
    organization: ids[0], project: "workspace", application: "independent", environment: "development"
  }]);
  assert.deepEqual(JSON.parse((await request("preview", tokens[0])).body), { binding: null });
  assert.equal((await request("development", tokens[1])).statusCode, 404);
  assert.equal((await request("missing", tokens[0])).statusCode, 404);
});

test("release inventory verifies the session and project grant again before returning provider evidence", async () => {
  const target = { organization: ids[0], project: "workspace", application: "independent", environment: "development" };
  const records = [{ id: target.application, environments: ["development", "preview"] }];
  let granted = true;
  let revoke = false;
  let reads = 0;
  let lastSession;
  const { handle, register, request: accountRequest } = fixture({
    config: { workloadObservation: {
      releasesAvailable: true,
      matches: (scope, eligible) => !!eligible && Object.keys(target).every(key => scope[key] === target[key]),
      async listReleases(actor, scope, eligible) {
        if (!this.matches(scope, eligible)) return { status: 404 };
        reads++;
        if (revoke === "grant") granted = false;
        if (revoke === "session") await accountRequest("POST", "/sign-out", { token: lastSession });
        return { status: 200, inventory: { liveAliasVersion: "5" } };
      }
    } },
    records: { async registryApplications(actor, id) { return granted && id === ids[0] && actor === "actor-0" ? records : null; } }
  });
  await register(allowedEmails[0]);
  await register(allowedEmails[1]);
  const base = `/api/cloud/v1/organizations/${ids[0]}/projects/workspace/applications/independent/environments/`;
  const input = (environment, token, from = origin) => handle({
    ...event("POST", "", { token, from }), rawPath: base + environment + "/published-releases"
  });
  for (const [environment, token, from, status] of [
    ["development", undefined, origin, 401], ["development", tokens[1], origin, 404],
    ["preview", tokens[0], origin, 404], ["development", tokens[0], "https://foreign.example.test", 403]
  ]) {
    assert.equal((await input(environment, token, from)).statusCode, status);
    assert.equal(reads, 0);
  }
  const success = await input("development", tokens[0]);
  assert.equal(success.statusCode, 200);
  assert.equal(success.headers["cache-control"], "no-store");
  assert.deepEqual(JSON.parse(success.body), { liveAliasVersion: "5" });
  revoke = "grant";
  const lostGrant = await input("development", tokens[0]);
  assert.equal(lostGrant.statusCode, 404);
  assert.doesNotMatch(lostGrant.body, /liveAliasVersion/);
  granted = true;
  revoke = "session";
  lastSession = tokens[0];
  const lostSession = await input("development", tokens[0]);
  assert.equal(lostSession.statusCode, 401);
  assert.doesNotMatch(lostSession.body, /liveAliasVersion/);
});
