const base = "/api/cloud/auth";
const find = selector => document.querySelector(selector);
const status = find("[data-account-status]");
const failure = find("[data-account-error]") || status;
const credentials = find('[data-account-form="credentials"]');
const profile = find('[data-account-form="profile"]');
const workspace = find("[data-workspace]");
const links = find("[data-account-links]");
const sessionUpdates = typeof BroadcastChannel === "function" ? new BroadcastChannel("paige-cloud-session") : null;

const screens = {
  "/sign-in": {
    title: "Sign in", action: "Sign in", path: "/sign-in", password: "current-password",
    links: [["Forgot password?", "/recover"], ["Create an account", "/signup"]]
  },
  "/signup": {
    title: "Create your account", intro: "Verify your email address to open your workspace.",
    action: "Send verification code", path: "/sign-up",
    links: [["Already have an account? Sign in", "/sign-in"]]
  },
  "/verify-email": {
    title: "Verify your email", intro: "Enter your six-digit code and choose a password.",
    action: "Verify email", path: "/verify-email", code: true, password: "new-password",
    links: [["Sign in", "/sign-in"], ["Forgot password?", "/recover"]]
  },
  "/recover": {
    title: "Recover your account", intro: "Enter the email address associated with your account.",
    action: "Send reset code", path: "/recover", links: [["Back to sign in", "/sign-in"]]
  },
  "/reset-password": {
    title: "Reset your password", intro: "Enter the code you received and choose a new password.",
    action: "Reset password", path: "/reset-password", password: "new-password", code: true,
    links: [["Request another reset code", "/recover"]]
  }
};

const errors = {
  invalid_credentials: "Check your email address and password, then try again.",
  registration_unavailable: "New registrations are unavailable right now. You can still sign in or recover an existing account.",
  email_already_registered: "An account already exists for this address. Sign in or verify your email.",
  invalid_code: "Check the six-digit code and try again.",
  expired_code: "That code has expired. Request a new one.",
  enrollment_password_unverified: "Your email was verified. Use password recovery to finish setting up your sign-in.",
  recovery_sessions_unverified: "Your password changed. We could not confirm that other sessions ended. Sign in with your new password, then sign out to end them.",
  invalid_password: "Check the password requirements and try again.",
  invalid_email: "Enter a valid email address.",
  invalid_name: "Enter a name with no more than 120 characters.",
  invalid_identifier: "Use a lowercase ID that starts with a letter or number and contains only letters, numbers, or hyphens.",
  invalid_kind: "Choose Application or Service.",
  invalid_repository: "Enter the repository as owner/repository.",
  organization_exists: "Your first organization already exists. Reload the workspace to see it.",
  organization_changed: "The organization name changed in another session. Reload to see the current name.",
  try_again_later: "Too many attempts. Wait a minute, then try again."
};

async function requestJson(url, method, body) {
  const response = await fetch(url, {
    method, credentials: "same-origin", cache: "no-store",
    ...(body && { headers: { "Content-Type": "application/json" }, body: JSON.stringify(body) })
  });
  const result = response.headers.get("content-type")?.includes("application/json") ? await response.json() : null;
  if (!response.ok) {
    const error = new Error(errors[result?.error] ?? "PAIGE Cloud account access is temporarily unavailable. Try again.");
    error.status = response.status;
    error.code = result?.error;
    throw error;
  }
  return result;
}

function request(path, method = "GET", body) {
  return requestJson(base + path, method, body);
}

function showError(error) {
  failure.textContent = error.message;
  failure.hidden = false;
}

async function run(button, operation, isCurrent = () => true) {
  button.disabled = true;
  failure.textContent = "";
  if (failure !== status) failure.hidden = true;
  status.textContent = "Working…";
  try {
    await operation();
    if (isCurrent() && status.textContent === "Working…") status.textContent = "";
  } catch (error) {
    if (isCurrent()) {
      if (error.status === 401 && (workspace || (profile && !profile.hidden))) {
        clearWorkspace();
        location.replace("/sign-in");
      }
      else {
        if (failure !== status) status.textContent = "";
        showError(error);
      }
    }
  } finally {
    button.disabled = false;
  }
}

let screen;
let screenRevision = 0;
function showScreen(path, email = "", message = "", moveFocus = false) {
  screenRevision += 1;
  failure.textContent = "";
  failure.hidden = true;
  screen = screens[path] ?? screens["/sign-in"];
  document.title = screen.title + " · PAIGE Cloud";
  const heading = find("[data-account-heading]");
  heading.textContent = screen.title;
  find("[data-account-intro]").textContent = screen.intro ?? "";
  status.textContent = message;
  credentials.reset();
  const password = credentials.elements.password;
  password.required = Boolean(screen.password);
  password.disabled = !screen.password;
  password.autocomplete = screen.password || "current-password";
  const choosingPassword = screen.password === "new-password";
  password.minLength = choosingPassword ? 15 : 1;
  password.maxLength = choosingPassword ? 256 : 512;
  if (choosingPassword) password.pattern = "\\S+";
  else password.removeAttribute("pattern");
  find("[data-password-field]").hidden = !screen.password;
  find("[data-password-note]").hidden = screen.password !== "new-password";
  credentials.elements.code.required = Boolean(screen.code);
  credentials.elements.code.disabled = !screen.code;
  find("[data-code-field]").hidden = !screen.code;
  find("[data-resend]").hidden = path !== "/verify-email";
  find("[data-account-submit]").textContent = screen.action;
  credentials.elements.email.value = email;
  links.replaceChildren(...screen.links.map(([label, href]) => {
    const link = document.createElement("a");
    link.href = href;
    link.textContent = label;
    return link;
  }));
  credentials.hidden = false;
  if (moveFocus) {
    heading.tabIndex = -1;
    heading.focus();
  }
}

function advance(path, email, message) {
  history.pushState(null, "", path);
  showScreen(path, email, message, true);
}

credentials?.addEventListener("submit", event => {
  event.preventDefault();
  const values = Object.fromEntries(new FormData(credentials));
  const submitted = screen.path;
  const revision = screenRevision;
  const isCurrent = () => screenRevision === revision;
  run(event.submitter, async () => {
    try {
      await request(submitted, "POST", values);
    } catch (error) {
      if (isCurrent() && submitted === "/sign-in" && error.code === "verification_required") {
        advance("/verify-email", values.email, "Verify your email before signing in.");
        return;
      }
      throw error;
    }
    if (submitted === "/sign-in" || submitted === "/reset-password") sessionUpdates?.postMessage("changed");
    if (!isCurrent()) return;
    switch (submitted) {
      case "/sign-up": advance("/verify-email", values.email, "Check your inbox for a verification code."); break;
      case "/verify-email": advance("/sign-in", values.email, "Email verified. You can sign in now."); break;
      case "/recover": advance("/reset-password", values.email, "If a reset code can be sent, it will arrive by email."); break;
      case "/reset-password":
        advance("/sign-in", values.email, "Password reset. Sign in with your new password.");
        break;
      case "/sign-in":
        location.replace("/mission-control");
        break;
    }
  }, isCurrent);
});

find("[data-resend]")?.addEventListener("click", event => {
  const email = credentials.elements.email;
  if (!email.reportValidity()) return;
  const revision = screenRevision;
  const isCurrent = () => screenRevision === revision;
  run(event.currentTarget, async () => {
    await request("/resend-code", "POST", { email: email.value });
    if (isCurrent()) status.textContent = "If this account is eligible, a new code will arrive by email.";
  }, isCurrent);
});

async function readAccount() {
  try {
    return await request("/account");
  } catch (error) {
    if (error.status === 401) location.replace("/sign-in");
    else showError(error);
    return null;
  }
}

const organizationControl = find("[data-active-organization]");
const projectStatus = find("[data-project-status]");
const projectRetry = find("[data-project-retry]");
const projectList = find("[data-projects]");
const projectEditor = find("[data-create-project]");
const organizationEditor = find("[data-rename-organization]");
let organizations = [];
let projectRevision = 0;
let workspaceClosed = false;
const missionHeading = find("[data-mission-heading]");
const missionViewsReady = missionHeading && getComputedStyle(workspace)
  .getPropertyValue("--mission-operating-views").trim() === "1";
const releaseInventoryReady = missionViewsReady && getComputedStyle(workspace)
  .getPropertyValue("--mission-release-inventory").trim() === "1";
const developerPage = find("[data-developer-reference]");
const developerStatus = find("[data-developer-status]");
const developerOperations = find("[data-developer-operations]");
const developerRetry = find("[data-developer-retry]");
const developerReady = developerPage && missionViewsReady && getComputedStyle(workspace)
  .getPropertyValue("--mission-developer-reference").trim() === "1";
let developerRevision = 0;
const missionViews = {
  overview: ["Mission Control", ""],
  projects: ["Projects", ""],
  infrastructure: ["Infrastructure", "Open a project to inspect a registered workload. Health is checked on demand for its bound environment."],
  deployments: ["Deployments", "Open a project to check the serving release for a bound workload."],
  configuration: ["Configuration", "Open an application environment to view its saved non-secret settings and check what the workload consumed."],
  ...(developerReady && { developer: ["Developer Platform", ""] })
};

async function loadDeveloperReference() {
  const revision = ++developerRevision;
  const current = () => !workspaceClosed && revision === developerRevision && !developerPage.hidden;
  developerOperations.replaceChildren();
  developerRetry.hidden = true;
  developerStatus.textContent = "Loading API reference…";
  try {
    const result = await requestJson("/api/cloud/v1/developer/capabilities", "GET");
    if (!current()) return;
    if (result?.schema !== "paige.cloud.developer-capabilities.v1" || result.authentication !== "cloud-account-session" ||
      !Array.isArray(result.operations) || !result.operations.every(operation => operation &&
        [operation.name, operation.method, operation.path, operation.access].every(value => typeof value === "string"))) {
      throw new Error("Invalid API reference");
    }
    developerStatus.textContent = result.operations.length ? "" : "No endpoints are available in this environment.";
    developerOperations.replaceChildren(...result.operations.map(({ name, method, path, access }) => {
      const item = document.createElement("li");
      const label = document.createElement("strong");
      const route = document.createElement("code");
      const detail = document.createElement("p");
      label.textContent = name;
      route.textContent = `${method} ${path}`;
      detail.textContent = access;
      item.append(label, route, detail);
      return item;
    }));
  } catch (error) {
    if (error.status === 401 && !workspaceClosed) {
      clearWorkspace();
      location.replace("/sign-in");
      return;
    }
    if (!current()) return;
    developerStatus.textContent = "API reference is unavailable. Try again.";
    developerRetry.hidden = false;
  }
}

developerRetry?.addEventListener("click", () => {
  developerStatus.tabIndex = -1;
  developerStatus.focus();
  void loadDeveloperReference();
});

function renderMissionRoute(moveFocus = false) {
  if (!missionViewsReady || workspaceClosed) return;
  const requested = location.hash.slice(1);
  const view = Object.hasOwn(missionViews, requested) ? requested : "overview";
  const [label, description] = missionViews[view];
  workspace.dataset.missionView = view;
  missionHeading.textContent = label;
  document.title = `${label} · PAIGE Cloud`;
  const intro = find("[data-mission-description]");
  intro.textContent = description;
  intro.hidden = !description;
  find("#projects-heading").textContent = view === "overview" ? "Projects" : "Project scope";
  for (const link of document.querySelectorAll("[data-mission-route]")) {
    if (view === link.dataset.missionRoute) link.setAttribute("aria-current", "page");
    else link.removeAttribute("aria-current");
  }
  if (developerReady) {
    developerPage.hidden = view !== "developer";
    if (view === "developer") void loadDeveloperReference();
    else {
      developerRevision++;
      developerOperations.replaceChildren();
    }
  }
  if (moveFocus) missionHeading.focus();
}

function clearWorkspace() {
  if (!workspace) return;
  workspaceClosed = true;
  projectRevision++;
  developerRevision++;
  projectList?.replaceChildren();
  developerOperations?.replaceChildren();
  const scope = find("[data-mission-scope]");
  if (scope) {
    scope.hidden = true;
    scope.textContent = "";
  }
  const projectLink = find("[data-project-link]");
  if (projectLink) projectLink.hidden = true;
  find("[data-account-content]").hidden = true;
}

if (workspace) {
  window.addEventListener("hashchange", () => renderMissionRoute(true));
  const refreshWorkspace = () => {
    clearWorkspace();
    location.reload();
  };
  sessionUpdates?.addEventListener("message", event => {
    if (event.data === "changed" && !workspaceClosed) refreshWorkspace();
  });
  window.addEventListener("pageshow", event => {
    if (event.persisted) refreshWorkspace();
  });
}

async function readRegistryList(path) {
  const result = await requestJson(`/api/cloud/v1${path}`, "GET");
  if (!Array.isArray(result)) throw new Error("Invalid registry response");
  return result;
}

function activeOrganization() {
  return organizations.find(organization => organization.id === organizationControl?.value);
}

function resetEditor(editor, name = "") {
  if (!editor) return;
  editor.open = false;
  const form = editor.querySelector("form");
  form.reset();
  if (form.elements.name) form.elements.name.value = name;
  form.querySelector("[role='alert']").hidden = true;
}

function wireEditor(editor, operation) {
  const form = editor.querySelector("form");
  const detailsLabel = editor.querySelector("summary");
  const alert = form.querySelector("[role='alert']");
  const button = form.querySelector("button[type='submit']");
  const cancel = form.querySelector("[data-registry-cancel]");
  const labels = {
    registration_conflict: "That ID already has different details. Choose a different ID or review the existing record.",
    registry_limit: "This workspace has reached its registration limit."
  };

  cancel.addEventListener("click", () => {
    resetEditor(editor, form.elements.name?.defaultValue);
    detailsLabel.focus();
  });
  form.addEventListener("submit", async event => {
    event.preventDefault();
    if (button.disabled || !editor.open) return;
    const values = Object.fromEntries(new FormData(form));
    for (const key of Object.keys(values)) values[key] = values[key].trim();
    const revision = projectRevision;
    const current = () => !workspaceClosed && revision === projectRevision && editor.isConnected;
    const buttonLabel = button.textContent;
    button.textContent = "Saving…";
    button.disabled = cancel.disabled = true;
    alert.hidden = true;
    try {
      await operation(values, current);
    } catch (error) {
      if (!current()) return;
      if (error.status === 401) {
        clearWorkspace();
        location.replace("/sign-in");
        return;
      }
      alert.textContent = labels[error.code] ?? ((error.status === 403 || error.status === 404)
        ? "You no longer have permission to save here. Reload to check your access."
        : error.status === 400 || error.status === 409
          ? error.message
          : "The save could not be confirmed. Try again with the same details or reload to check.");
      editor.open = true;
      alert.hidden = false;
    } finally {
      button.textContent = buttonLabel;
      button.disabled = cancel.disabled = false;
    }
  });
}

if (projectEditor) wireEditor(projectEditor, async (values, current) => {
  const organization = activeOrganization();
  const path = `/organizations/${encodeURIComponent(organization.id)}/projects`;
  const project = await requestJson(`/api/cloud/v1${path}`, "POST", values);
  if (current()) await loadProjects(project.id, `Project saved: ${project.name}.`);
});

if (organizationEditor) wireEditor(organizationEditor, async ({ name }, current) => {
  const organization = activeOrganization();
  const result = await request(`/organizations/${encodeURIComponent(organization.id)}`, "PATCH", {
    expectedName: organization.name, name
  });
  if (!current()) return;
  renderOrganizations(organizations.map(item => item.id === result.id ? result : item), result.id);
  organizationEditor.querySelector("summary").focus();
  status.textContent = "Organization name saved.";
});

function workloadInspection(app, applicationsPath, revision, settings) {
  const container = document.createElement("div");
  const trigger = document.createElement("button");
  const observation = document.createElement("p");
  const incident = document.createElement("p");
  const path = `${applicationsPath}/${encodeURIComponent(app.id)}/environments/${encodeURIComponent(app.inspectionEnvironment)}/inspection`;
  container.className = "workload-inspection";
  container.dataset.missionFeature = "observation";
  trigger.className = "plain-button";
  trigger.type = "button";
  trigger.textContent = `Check ${app.inspectionEnvironment} health`;
  observation.setAttribute("role", "status");
  incident.setAttribute("role", "status");
  container.append(trigger, observation, incident);
  settings?.connectInspection(denied => {
    trigger.hidden = denied;
    observation.textContent = denied ? "This workload is no longer available to inspect." : "";
    incident.textContent = "";
  });

  trigger.addEventListener("click", async () => {
    const generation = settings?.inspectionGeneration();
    const isCurrent = () => revision === projectRevision && container.isConnected
      && (!settings || settings.acceptsInspection(generation));
    if (!isCurrent()) return;
    settings?.report(null, "Checking the running workload…");
    trigger.setAttribute("aria-disabled", "true");
    trigger.disabled = true;
    observation.textContent = "Checking the running workload…";
    incident.textContent = "";
    try {
      const result = await requestJson(`/api/cloud/v1${path}`, "POST");
      if (!isCurrent()) return;
      settings?.report(result);
      const time = document.createElement("time");
      time.dateTime = result.observedAt;
      time.textContent = new Intl.DateTimeFormat(undefined, {
        month: "short", day: "numeric", hour: "numeric", minute: "2-digit",
        second: "2-digit", timeZoneName: "short"
      }).format(new Date(result.observedAt));
      const status = document.createElement("strong");
      status.textContent = result.state === "healthy" ? "Healthy" : "Needs attention";
      observation.replaceChildren(status, ` · Version ${result.release.version} · ${result.release.commit.slice(0, 8)} · `, time);
      if (result.consumedConfiguration) {
        observation.append(` · Observed configuration revision ${result.consumedConfiguration.revision}`);
      }
      if (result.incident?.reason === "backend_access_denied") {
        const plan = result.incident.plan;
        incident.textContent = plan?.operation === "restore_verified_alias" && plan.status === "review_required"
          ? `AWS denied the configuration read. Proposed recovery: restore verified version ${plan.target.version} (${plan.target.commit.slice(0, 8)}) through a reviewed deployment. Check health after recovery.`
          : "AWS denied the configuration read. Verify the workload’s data binding before changing it.";
      } else if (result.incident?.reason === "backend_record_invalid") {
        incident.textContent = "The configuration record failed validation. Review the release and its data binding.";
      } else if (result.incident) {
        incident.textContent = "The workload could not verify its configuration read. Review the runtime evidence.";
      }
    } catch (error) {
      if (!isCurrent()) return;
      if (error.status === 401) {
        clearWorkspace();
        location.replace("/sign-in");
      } else if (error.status === 404 || error.status === 403) {
        if (error.status === 404) settings?.invalidateScope();
        settings?.report(null, "Inspection is unavailable in your current scope.");
        observation.textContent = "This workload is no longer available to inspect.";
        trigger.hidden = true;
      } else if (error.status === 429) {
        settings?.report(null, "Inspection limit reached. No new observation was recorded.");
        observation.textContent = "Inspection limit reached. Try again in 30 seconds. Daily capacity resets at 00:00 UTC.";
      } else {
        settings?.report(null, "Consumption could not be verified.");
        observation.textContent = "Health could not be verified. Try again in 30 seconds.";
      }
    } finally {
      trigger.disabled = false;
      trigger.removeAttribute("aria-disabled");
    }
  });
  return container;
}

function workloadReleaseInventory(app, applicationsPath, projectGeneration, settings) {
  const panel = document.createElement("section");
  const trigger = document.createElement("button");
  const status = document.createElement("p");
  const versions = document.createElement("ol");
  const environment = app.releaseInventoryEnvironment;
  const path = `/api/cloud/v1${applicationsPath}/${encodeURIComponent(app.id)}/environments/${encodeURIComponent(environment)}/published-releases`;

  panel.dataset.missionFeature = "release-inventory";
  panel.className = "release-inventory";
  panel.setAttribute("aria-label", `Published versions for ${app.name} · ${environment}`);
  trigger.className = "plain-button";
  trigger.type = "button";
  trigger.textContent = "Check published versions";
  status.setAttribute("role", "status");
  versions.className = "published-versions";
  versions.setAttribute("role", "list");
  panel.append(trigger, status, versions);

  settings?.connectInspection(denied => {
    trigger.hidden = denied;
    versions.replaceChildren();
    status.textContent = denied ? "Published versions are unavailable in your current scope." : "";
  });

  trigger.addEventListener("click", async () => {
    const generation = settings?.inspectionGeneration();
    const isCurrent = () => projectGeneration === projectRevision && panel.isConnected &&
      (!settings || settings.acceptsInspection(generation));
    if (!isCurrent() || trigger.disabled) return;
    trigger.disabled = true;
    versions.replaceChildren();
    status.textContent = "Checking published versions…";
    try {
      const inventory = await requestJson(path, "POST");
      if (!isCurrent()) return;
      const checkedAt = new Date(inventory.observedAt).toLocaleString();
      const aliasTarget = inventory.liveAliasVersion
        ? `Live alias pointed to version ${inventory.liveAliasVersion} at ${checkedAt}.`
        : `The live alias target could not be matched to this page at ${checkedAt}.`;
      status.textContent = inventory.completeness === "partial" ? `${aliasTarget} Showing part of the inventory.` : aliasTarget;
      for (const entry of inventory.versions) {
        const row = document.createElement("li");
        const version = document.createElement("strong");
        const pin = document.createElement("span");
        const modified = document.createElement("time");
        const checksum = document.createElement("code");
        version.textContent = `Version ${entry.version}${entry.version === inventory.liveAliasVersion ? " · Live alias target" : ""}`;
        pin.textContent = entry.pinnedRevision === null ? "No configuration pin" : `Pinned revision ${entry.pinnedRevision}`;
        modified.dateTime = entry.lastModified;
        modified.textContent = `Modified ${new Date(entry.lastModified).toLocaleString()}`;
        checksum.textContent = `SHA-256 ${entry.codeSha256}`;
        row.append(version, pin, modified, checksum);
        versions.append(row);
      }
    } catch (error) {
      if (!isCurrent()) return;
      if (error.status === 401) {
        clearWorkspace();
        location.replace("/sign-in");
      } else if (error.status === 404 || error.status === 403) {
        versions.replaceChildren();
        if (error.status === 404) settings?.invalidateScope();
        trigger.hidden = true;
        status.textContent = "Published versions are unavailable in your current scope.";
      } else {
        versions.replaceChildren();
        status.textContent = error.status === 429
          ? "Wait 30 seconds before checking this environment again."
          : "Published versions could not be verified. Try again.";
      }
    } finally {
      trigger.disabled = false;
    }
  });
  return panel;
}

function environmentConfiguration(app, environment, applicationsPath, projectGeneration, canWrite) {
  const details = document.createElement("details");
  const title = document.createElement("summary");
  const evidence = document.createElement("p");
  const runtime = document.createElement("p");
  const path = `/api/cloud/v1${applicationsPath}/${encodeURIComponent(app.id)}/environments/${encodeURIComponent(environment)}/configuration`;
  const bound = app.inspectionEnvironment === environment;
  const editor = canWrite && missionViewsReady
    ? find("#workload-configuration-editor")?.content.firstElementChild.cloneNode(true)
    : null;
  const submit = editor && editor.querySelector("button[type='submit']");
  const errorMessage = editor && editor.querySelector("[role='alert']");
  let saved = null;
  let observed = null;
  let runtimeMessage = bound ? "Run the environment health check to verify consumption." : "No inspection is bound to this environment.";
  let generation = 0;
  let inspectionGeneration = 0;
  let inspectionDenied = false;
  const inspectionListeners = new Set();

  title.textContent = `Configuration · ${environment}`;
  evidence.setAttribute("role", "status");
  runtime.setAttribute("role", "status");
  details.append(title, evidence, runtime);
  if (editor) details.append(editor);

  const scopeCurrent = () => projectGeneration === projectRevision && details.isConnected;
  const scopeRequestCurrent = request => scopeCurrent() && request === generation;
  const isCurrent = request => scopeRequestCurrent(request) && details.open;
  function renderRuntime() {
    const consumed = observed?.consumedConfiguration;
    if (!consumed) {
      runtime.textContent = runtimeMessage;
      return;
    }
    const observationTime = new Date(observed.observedAt).toLocaleString();
    let comparison = "";
    if (saved) {
      comparison = consumed.revision === saved.revision
        ? " Matches the saved revision."
        : " Differs from the saved revision.";
    }
    runtime.textContent = `Consumed revision ${consumed.revision} at ${observationTime}.${comparison}`;
  }

  function report(result, message) {
    if (!scopeCurrent()) return;
    observed = result;
    runtimeMessage = message ?? (result?.state === "healthy"
      ? "The running release reported no consumed configuration revision."
      : "This inspection could not verify a consumed revision.");
    renderRuntime();
  }

  function denyScope() {
    inspectionDenied = true;
    inspectionGeneration++;
    for (const update of inspectionListeners) update(true);
    report(null, "No configuration evidence is available in your current scope.");
  }

  function showSaved(result) {
    if (inspectionDenied) {
      inspectionDenied = false;
      for (const update of inspectionListeners) update(false);
    }
    if (editor) {
      editor.elements.logLevel.value = result.configuration?.logLevel ?? "";
      editor.elements.requestTimeoutMs.value = result.configuration?.requestTimeoutMs ?? "";
      editor.hidden = false;
    }
    saved = result;
    evidence.textContent = result.configuration
      ? `Saved revision ${result.revision} · Log level ${result.configuration.logLevel} · Request timeout ${result.configuration.requestTimeoutMs} ms.`
      : "No configuration has been saved for this environment.";
    renderRuntime();
  }

  function signInAgain(error) {
    if (error.status !== 401) return false;
    clearWorkspace();
    location.replace("/sign-in");
    return true;
  }

  details.addEventListener("toggle", async () => {
    saved = null;
    if (editor) {
      editor.hidden = true;
      errorMessage.hidden = true;
    }
    if (!details.open) return;
    const request = ++generation;
    evidence.textContent = "Reading saved configuration…";
    renderRuntime();
    try {
      const result = await requestJson(path, "GET");
      if (isCurrent(request)) showSaved(result);
    } catch (error) {
      if (!scopeRequestCurrent(request) || signInAgain(error)) return;
      const denied = error.status === 404 || error.status === 403;
      if (denied) denyScope();
      if (details.open) {
        evidence.textContent = denied
          ? "Configuration is unavailable in your current scope."
          : "Could not read configuration. Reopen this environment to retry.";
      }
    }
  });

  editor?.addEventListener("submit", async event => {
    event.preventDefault();
    if (!saved || submit.disabled || !scopeCurrent()) return;
    const request = generation;
    const values = {
      expectedRevision: saved.revision,
      logLevel: editor.elements.logLevel.value,
      requestTimeoutMs: editor.elements.requestTimeoutMs.valueAsNumber
    };
    submit.disabled = true;
    editor.elements.logLevel.disabled = editor.elements.requestTimeoutMs.disabled = true;
    errorMessage.hidden = true;
    submit.textContent = "Saving…";
    try {
      const result = await requestJson(path, "PUT", values);
      if (isCurrent(request)) showSaved(result);
    } catch (error) {
      if (!scopeRequestCurrent(request) || signInAgain(error)) return;
      const denied = error.status === 403 || error.status === 404;
      if (denied) denyScope();
      if (!details.open) return;
      if (denied || error.code === "configuration_changed") {
        editor.hidden = true;
        saved = null;
        if (error.code === "configuration_changed") {
          renderRuntime();
          evidence.textContent = "The saved revision changed. Reopen the environment to review it before saving again.";
        } else {
          evidence.textContent = "Configuration is unavailable in your current scope.";
        }
        title.focus();
        return;
      }
      if (error.code === "configuration_rate_limited" || error.code === "configuration_limit") {
        errorMessage.textContent = error.code === "configuration_rate_limited"
          ? "Wait one minute before saving another revision."
          : "This configuration has reached its revision limit.";
        errorMessage.hidden = false;
      } else {
        editor.hidden = true;
        saved = null;
        renderRuntime();
        evidence.textContent = "The save could not be confirmed. Reopen this environment to check the saved revision.";
        title.focus();
      }
    } finally {
      submit.disabled = false;
      editor.elements.logLevel.disabled = editor.elements.requestTimeoutMs.disabled = false;
      submit.textContent = "Save revision";
      if (scopeCurrent() && details.open && !isCurrent(request)) {
        details.open = false;
        title.focus();
      }
    }
  });
  renderRuntime();
  return {
    details, report,
    connectInspection(update) { inspectionListeners.add(update); },
    invalidateScope() {
      generation++;
      saved = null;
      if (editor) editor.hidden = true;
      evidence.textContent = "Configuration is unavailable in your current scope.";
      denyScope();
    },
    inspectionGeneration: () => inspectionGeneration,
    acceptsInspection: request => !inspectionDenied && request === inspectionGeneration
  };
}

function repositoryBindingPanel(app, applicationsPath, projectGeneration) {
  const panel = document.createElement("details");
  const title = document.createElement("summary");
  const status = document.createElement("p");
  const label = document.createElement("label");
  const picker = document.createElement("select");
  panel.className = "environment-settings";
  panel.dataset.missionFeature = "registry";
  title.textContent = "Repository binding";
  status.setAttribute("role", "status");
  label.className = "organization-picker";
  label.append("Environment ", picker);
  for (const environment of app.environments) picker.add(new Option(environment, environment));
  panel.append(title);
  if (app.environments.length > 1) panel.append(label);
  panel.append(status);

  let generation = 0;
  async function read() {
    const request = ++generation;
    const environment = picker.value;
    const scopeCurrent = () => panel.isConnected && projectGeneration === projectRevision;
    const current = () => panel.open && request === generation && scopeCurrent();
    status.textContent = "";
    if (!environment || !current()) return;
    status.textContent = "Checking repository binding…";
    const path = `${applicationsPath}/${encodeURIComponent(app.id)}/environments/${encodeURIComponent(environment)}/repository-binding`;
    try {
      const { binding } = await requestJson(`/api/cloud/v1${path}`, "GET");
      if (!current()) return;
      status.textContent = binding
        ? `${environment} · ${binding.repository} · ${binding.ref} · GitHub ID ${binding.repositoryId}`
        : `${environment} has no recorded source binding.`;
    } catch (error) {
      if (error.status === 401 && scopeCurrent()) {
        clearWorkspace();
        location.replace("/sign-in");
        return;
      }
      if (!current()) return;
      status.textContent = error.status === 404 ? "Repository binding is unavailable in your current scope."
        : "Repository binding could not be checked. Close and reopen to retry.";
    }
  }
  panel.addEventListener("toggle", read);
  picker.addEventListener("change", read);
  return panel;
}

function renderProject(project, registryPath, revision) {
  const row = document.createElement("li");
  const details = document.createElement("details");
  const summary = document.createElement("summary");
  const name = document.createElement("strong");
  const role = document.createElement("span");
  const message = document.createElement("p");
  const apps = document.createElement("ul");
  const applicationsPath = `${registryPath}/${encodeURIComponent(project.id)}/applications`;
  name.textContent = project.name;
  role.textContent = `${project.id} · ${project.role}`;
  message.setAttribute("role", "status");
  summary.append(name, role);
  details.append(summary, message, apps);
  row.append(details);
  function renderApplication(app) {
    const item = document.createElement("li");
    const label = document.createElement("strong");
    const targets = document.createElement("span");
    label.textContent = app.name;
    targets.textContent = `${app.id} · Environments: ${app.environments.join(", ")}`;
    item.append(label, targets);
    if (app.sourceRepository) {
      const source = document.createElement("p");
      source.dataset.missionFeature = "registry";
      source.textContent = `Registered repository · ${app.sourceRepository}`;
      item.append(source, repositoryBindingPanel(app, applicationsPath, revision));
    }
    const configuration = document.createElement("div");
    configuration.className = "environment-settings";
    configuration.dataset.missionFeature = "configuration";
    const settings = new Map(app.environments.map(environment => [
      environment, environmentConfiguration(app, environment, applicationsPath, revision, project.role === "owner")
    ]));
    configuration.append(...Array.from(settings.values(), result => result.details));
    item.append(configuration);
    if (app.inspectionEnvironment) {
      item.append(workloadInspection(app, applicationsPath, revision, settings.get(app.inspectionEnvironment)));
    } else if (missionHeading) {
      const unavailable = document.createElement("p");
      unavailable.dataset.missionFeature = "observation";
      unavailable.textContent = "No workload inspection is bound to this application.";
      item.append(unavailable);
    }
    if (releaseInventoryReady && app.releaseInventoryEnvironment) {
      item.append(workloadReleaseInventory(app, applicationsPath, revision, settings.get(app.releaseInventoryEnvironment)));
    }
    const template = find("#environment-editor");
    if (template && project.role === "owner") {
      const editor = template.content.firstElementChild.cloneNode(true);
      editor.dataset.missionFeature = "registry";
      editor.querySelector("[data-application-label]").textContent = `for ${app.name}`;
      wireEditor(editor, async ({ environment }, current) => {
        const { id, name, kind, sourceRepository } = app;
        await saveApplication({ id, name, kind, sourceRepository: sourceRepository ?? "", environment }, current);
      });
      item.append(editor);
    }
    return item;
  }

  async function saveApplication(values, current) {
    const saved = await requestJson(`/api/cloud/v1${applicationsPath}`, "POST", values);
    if (!current()) return;
    await loadApplications(`Application saved: ${saved.name}. Environment: ${values.environment}.`, saved.id);
  }

  const template = find("#application-editor");
  const applicationEditor = template && project.role === "owner"
    ? template.content.firstElementChild.cloneNode(true) : null;
  if (applicationEditor) {
    applicationEditor.hidden = true;
    applicationEditor.dataset.missionFeature = "registry";
    wireEditor(applicationEditor, saveApplication);
    details.append(applicationEditor);
  }

  let applicationRevision = 0;
  async function loadApplications(announcement = "", appId) {
    if (revision !== projectRevision) return;
    const read = ++applicationRevision;
    if (applicationEditor) applicationEditor.hidden = true;
    message.textContent = "Loading applications…";
    try {
      const records = await readRegistryList(applicationsPath);
      if (revision !== projectRevision || read !== applicationRevision) return;
      const items = records.map(renderApplication);
      apps.replaceChildren(...items);
      resetEditor(applicationEditor);
      if (applicationEditor) applicationEditor.hidden = false;
      message.textContent = announcement || (records.length ? "" : "No applications registered.");
      const target = items[records.findIndex(app => app.id === appId)]?.querySelector("strong");
      if (target && details.open) {
        target.tabIndex = -1;
        target.focus();
      }
    } catch (error) {
      if (revision !== projectRevision || read !== applicationRevision) return;
      apps.replaceChildren();
      if (error.status === 401) {
        clearWorkspace();
        location.replace("/sign-in");
      } else {
        message.textContent = error.status === 404 ? "This project is no longer available to you."
          : `${announcement ? announcement + " " : ""}Applications are unavailable. Close and reopen the project to reload the list.`;
      }
    }
  }
  details.addEventListener("toggle", () => {
    if (details.open) void loadApplications();
  });
  return row;
}

function showMissionScope(organization, message, action = "") {
  const overview = find("[data-mission-overview]");
  const scope = find("[data-mission-scope]");
  const attention = find("[data-mission-attention]");
  if (!scope || !attention) return;
  scope.hidden = !organization;
  scope.textContent = organization?.name ?? "";
  attention.textContent = message;
  const link = find("[data-mission-action]");
  link.hidden = !action;
  if (action) {
    link.href = organization ? "#projects" : "#organization";
    link.textContent = action;
  }
  const projectLink = find("[data-mission-projects]");
  projectLink.hidden = true;
  find("[data-mission-coverage]").textContent = organization
    ? "Select a project to view its registered environments and available workload checks."
    : "An organization is required to register projects and environments.";
  if (overview) overview.hidden = false;
}

async function loadProjects(openProject, announcement = "") {
  const revision = ++projectRevision;
  const organization = organizationControl.value;
  const selected = activeOrganization();
  resetEditor(projectEditor);
  resetEditor(organizationEditor, selected?.name);
  if (organizationEditor) {
    organizationEditor.hidden = selected?.role !== "owner";
    organizationEditor.querySelector("input").defaultValue = selected?.name ?? "";
  }
  if (projectEditor) projectEditor.hidden = true;
  projectList.replaceChildren();
  projectRetry.hidden = true;
  find("#projects").hidden = !organization;
  find("[data-project-link]").hidden = !organization;
  showMissionScope(selected, selected ? "Checking projects in this organization…" : "Create an organization to get started.",
    selected ? "" : "Set up organization");
  if (!organization) return;
  const path = `/organizations/${encodeURIComponent(organization)}/projects`;
  projectStatus.textContent = "Loading projects…";
  try {
    const projects = await readRegistryList(path);
    if (revision !== projectRevision) return;
    const rows = projects.map(project => renderProject(project, path, revision));
    projectList.replaceChildren(...rows);
    projectStatus.textContent = announcement || (projects.length ? "" : "No projects are available in this organization.");
    showMissionScope(selected, projects.length
      ? "Project registry is available. Review individual environments for workload health."
      : "There are no projects available in this organization.",
    projects.length ? "" : "Open projects");
    const healthCoverage = find("[data-mission-coverage]");
    if (healthCoverage && projects.length) {
      healthCoverage.textContent = `${projects.length} ${projects.length === 1 ? "project" : "projects"} accessible in this organization. Environment and health evidence is scoped to each application.`;
      find("[data-mission-projects]").hidden = false;
    }
    if (projectEditor && selected?.role === "owner") {
      projectEditor.querySelector("[data-project-scope]").textContent = `Organization: ${selected.name}`;
      projectEditor.hidden = false;
    }
    const target = rows[projects.findIndex(project => project.id === openProject)]?.querySelector("details");
    if (target) {
      target.open = true;
      target.querySelector("summary").focus();
    }
  } catch (error) {
    if (revision !== projectRevision) return;
    if (error.status === 401) {
      clearWorkspace();
      location.replace("/sign-in");
    } else {
      projectStatus.textContent = error.status === 404 ? "This organization is no longer available to you."
        : `${announcement ? announcement + " " : ""}Projects are temporarily unavailable.`;
      projectRetry.hidden = error.status === 404;
      showMissionScope(selected, error.status === 404
        ? "This organization is no longer available to you."
        : "The project registry could not be reached. Retry from Projects.", error.status === 404 ? "" : "Open projects");
      const coverage = find("[data-mission-coverage]");
      if (coverage) coverage.textContent = "Environment coverage is unavailable for this organization.";
    }
  }
}

function renderOrganizations(records, selectedId) {
  if (workspaceClosed) return;
  organizations = records;
  const organizationList = find("[data-organizations]");
  find('[data-account-form="organization"]').hidden = organizations.length > 0;
  // The authenticated HTML and static script can be cached and rolled back independently.
  organizationList.hidden = Boolean(organizationControl);
  if (!organizationControl) {
    organizationList.replaceChildren(...organizations.map(organization => {
      const item = document.createElement("li");
      const label = document.createElement("strong");
      const role = document.createElement("span");
      label.textContent = organization.name;
      role.textContent = organization.role;
      item.append(label, role);
      return item;
    }));
    return;
  }
  organizationControl.replaceChildren(...organizations.map(organization =>
    new Option(organization.name, organization.id)));
  if (selectedId) organizationControl.value = selectedId;
  find("[data-organization-picker]").hidden = !organizations.length;
  void loadProjects();
}

organizationControl?.addEventListener("change", () => void loadProjects());
projectRetry?.addEventListener("click", () => {
  const heading = find("#projects-heading");
  heading.tabIndex = -1;
  heading.focus();
  void loadProjects();
});

async function showWorkspace() {
  const account = await readAccount();
  if (!account || workspaceClosed) return;
  find("[data-account-number]").textContent = account.number;
  find("[data-account-email]").textContent = account.email;
  renderOrganizations(account.organizations);
  renderMissionRoute();
  if (missionViewsReady) {
    for (const link of document.querySelectorAll("[data-mission-route]:not([data-project-link])")) {
      link.hidden = link.dataset.missionRoute === "developer" && !developerReady;
    }
  }
  find("[data-account-content]").hidden = false;
  status.textContent = "";
}

find('[data-account-form="organization"]')?.addEventListener("submit", event => {
  event.preventDefault();
  const name = event.currentTarget.elements.name.value;
  run(event.submitter, async () => {
    const organization = await request("/organizations", "POST", { name });
    renderOrganizations([organization]);
    status.textContent = "Organization created.";
    find("#organizations-heading").tabIndex = -1;
    find("#organizations-heading").focus();
  });
});

async function showProfile() {
  document.title = "Account settings · PAIGE Cloud";
  find("[data-account-heading]").textContent = "Account settings";
  status.textContent = "Checking your account…";
  const account = await readAccount();
  if (!account) return;
  find("[data-profile-email]").textContent = account.email;
  profile.elements.displayName.value = account.displayName ?? "";
  profile.hidden = false;
  find("[data-workspace-link]").hidden = false;
  status.textContent = "";
}

profile?.addEventListener("submit", event => {
  event.preventDefault();
  run(event.submitter, async () => {
    const value = await request("/account", "PATCH", { displayName: profile.elements.displayName.value });
    profile.elements.displayName.value = value.displayName ?? "";
    status.textContent = "Changes saved.";
  });
});

for (const button of document.querySelectorAll("[data-sign-out]")) {
  button.addEventListener("click", () => run(button, async () => {
    await request("/sign-out", "POST");
    clearWorkspace();
    sessionUpdates?.postMessage("changed");
    location.replace("/sign-in");
  }));
}

if (workspace) showWorkspace().catch(showError);
else if (location.pathname === "/account") showProfile().catch(showError);
else {
  showScreen(location.pathname);
  addEventListener("popstate", () => showScreen(location.pathname));
}
