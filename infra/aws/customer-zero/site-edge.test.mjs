import assert from "node:assert/strict";
import { readFileSync } from "node:fs";
import { test } from "node:test";
import { runInNewContext } from "node:vm";

const template = readFileSync(new URL("site-edge.yaml", import.meta.url), "utf8").replaceAll("\r\n", "\n");
const code = template.split("FunctionCode: !Sub |\n")[1].split("\n  AccountsRequestPolicy:")[0];
const evaluatorIp = "192.0.2.1";
const externalIps = ["198.51.100.4", "203.0.113.59", "2001:db8::20"];
const signup = "/api/cloud/auth/sign-up";
const workspace = "/mission-control";
const registry = "/api/cloud/v1/organizations/00000000-0000-4000-8000-000000000001/projects";
const settings = `${registry}/platform/applications/independent/environments/development/configuration/revisions/33`;

function handler(mode) {
  return runInNewContext(code.replaceAll("${EvaluatorIp}", evaluatorIp).replaceAll("${SiteAccessMode}", mode) + "\nhandler");
}

function request(fn, ip, uri, method = "GET", token) {
  return fn({ viewer: { ip }, request: { uri, method,
    headers: { "x-paige-viewer-ip": { value: "192.0.2.99" } },
    cookies: token ? { "__Host-paige_cloud_session": { value: token } } : {}
  } });
}

test("the rollback configuration preserves the evaluator and blocks external access", () => {
  const fn = handler("evaluator-only");
  assert.equal(request(fn, evaluatorIp, "/sign-in").uri, "/account-entry.html");
  assert.equal(request(fn, evaluatorIp, workspace, "GET", "a.b.c").uri, workspace);
  for (const path of ["/", "/sign-in", "/signup", workspace, signup, registry]) {
    assert.equal(request(fn, externalIps[0], path).statusCode, 403);
  }
});

test("marketing assets and the complete account entry flow accept any viewer network", () => {
  const fn = handler("route-governed");
  for (const ip of externalIps) {
    for (const path of ["/", "/index.html", "/site.css", "/site.js", "/favicon.ico", "/favicon.svg",
      "/account.css", "/account.js", "/instrument-sans.woff2", "/cloud-bracket.svg"]) {
      assert.equal(request(fn, ip, path).uri, path);
    }
    for (const path of ["/sign-in", "/signup", "/verify-email", "/recover", "/reset-password"]) {
      assert.equal(request(fn, ip, path).uri, "/account-entry.html");
    }
    for (const path of [signup, "/api/cloud/auth/verify-email", "/api/cloud/auth/resend-code",
      "/api/cloud/auth/sign-in", "/api/cloud/auth/recover", "/api/cloud/auth/reset-password"]) {
      const admitted = request(fn, ip, path, "POST");
      assert.equal(admitted.uri, path);
      assert.equal(admitted.headers["x-paige-viewer-ip"].value, ip);
    }
  }
});

test("public marketing works without opening the private account pilot", () => {
  const fn = handler("marketing-public");
  for (const ip of externalIps) {
    for (const path of ["/", "/index.html", "/site.css", "/site.js", "/favicon.ico", "/favicon.svg",
      "/cloud-bracket.svg", "/instrument-sans.woff2"]) {
      for (const method of ["GET", "HEAD"]) assert.equal(request(fn, ip, path, method).uri, path);
    }
    for (const path of ["/account", "/sign-in", "/signup", "/verify-email", "/recover", "/reset-password",
      "/account-entry.html", workspace, "/platform-operator", "/api/cloud/auth/account", registry, settings]) {
      const denied = request(fn, ip, path, "GET", "a.b.c");
      assert.equal(denied.statusCode, 403);
      assert.equal(denied.headers["cache-control"].value, "no-store");
    }
    for (const path of ["/", signup, "/api/cloud/auth/sign-in", "/api/cloud/auth/recover", registry]) {
      assert.equal(request(fn, ip, path, "POST").statusCode, 403);
    }
    assert.equal(request(fn, ip, "/sign-in", "HEAD").body, undefined);
  }
  assert.equal(request(fn, evaluatorIp, "/sign-in").uri, "/account-entry.html");
  assert.equal(request(fn, evaluatorIp, workspace, "GET", "a.b.c").uri, workspace);
  assert.equal(request(fn, evaluatorIp, signup, "POST").uri, signup);
});

test("workspace and data API still depend on the origin session and authority", () => {
  const fn = handler("route-governed");
  const ip = externalIps[0];
  assert.equal(request(fn, ip, workspace).headers.location.value, "/sign-in");
  assert.equal(request(fn, ip, "/account", "GET", "bad-cookie").statusCode, 303);
  assert.equal(request(fn, ip, workspace, "GET", "a.b.c").uri, workspace);
  for (const path of ["/api/cloud/auth/account", registry, settings]) {
    assert.equal(request(fn, ip, path).statusCode, 401);
    assert.equal(request(fn, ip, path, "GET", "a.b.c").uri, path);
  }
  for (const path of ["/platform-operator", "/api/cloud/v1/platform-operator", "/account-entry.html",
    "/DESIGN.md", "/%73ign-in", "/api/cloud/auth/../v1", "/api/cloud/auth/unknown"]) {
    const denied = request(fn, ip, path, "GET", "a.b.c");
    assert.equal(denied.statusCode, 404);
    assert.equal(denied.headers["cache-control"].value, "no-store");
    assert.equal(denied.headers["x-content-type-options"].value, "nosniff");
    assert.match(denied.headers["content-type"].value, path.startsWith("/api/") ? /^application\/json/ : /^text\/html/);
  }
  assert.equal(request(fn, ip, "/missing", "HEAD").body, undefined);
});

test("published versions use the protected uncached workload route", () => {
  const route = registry + "/platform/applications/independent/environments/development/published-releases";
  const governed = handler("route-governed");
  assert.equal(request(governed, externalIps[0], route, "POST").statusCode, 401);
  assert.equal(request(governed, externalIps[0], route, "POST", "a.b.c").uri, route);
  assert.equal(request(governed, externalIps[0], route + "/revisions/4", "POST", "a.b.c").statusCode, 404);
  assert.equal(request(handler("marketing-public"), externalIps[0], route, "POST", "a.b.c").statusCode, 403);
});

test("repository binding is protected by the workspace account route", () => {
  const route = registry + "/platform/applications/independent/environments/development/repository-binding";
  const governed = handler("route-governed");
  assert.equal(request(governed, externalIps[0], route).statusCode, 401);
  assert.equal(request(governed, externalIps[0], route, "GET", "a.b.c").uri, route);
  assert.equal(request(governed, externalIps[0], route + "/revisions/1", "GET", "a.b.c").statusCode, 404);
  assert.equal(request(handler("marketing-public"), externalIps[0], route, "GET", "a.b.c").statusCode, 403);
});

test("developer discovery uses the protected account origin in route-governed mode", () => {
  const path = "/api/cloud/v1/developer/capabilities";
  const governed = handler("route-governed");
  assert.equal(request(governed, externalIps[0], path).statusCode, 401);
  assert.equal(request(governed, externalIps[0], path, "GET", "a.b.c").uri, path);
  assert.equal(request(governed, externalIps[0], path, "POST", "a.b.c").statusCode, 404);
  assert.equal(request(handler("marketing-public"), externalIps[0], path, "GET", "a.b.c").statusCode, 403);
});
