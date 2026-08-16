"use strict";

const API_ROOT = "/api/v1";
const MAX_TABLE_ROWS = 30;
const PREVIEW_MAX_FPS = 12;
const SPECTRUM_MAX_FPS = 4;
const MAX_PREVIEW_BINS = 1024;
const MAX_CANVAS_WIDTH = 1024;
const DIAGNOSTIC_SUMMARY_INTERVAL_MS = 5000;
const EVENT_LOOP_STALL_THRESHOLD_MS = 250;
const WATERFALL_RECONNECT_MAX_DELAY_MS = 5000;

const ui = Object.fromEntries(
  [
    "connection-dot", "connection-status", "refresh-radios", "radio-select", "radio-state",
    "radio-serial", "radio-transport", "radio-firmware", "radio-revision", "radio-activity",
    "radio-error", "recover-radio", "settings-form", "settings-fieldset", "settings-revision", "center-frequency",
    "sample-rate", "bandwidth", "gain-mode", "gain-db", "settings-validation", "reset-settings",
    "requested-settings", "actual-settings", "fft-size", "start-preview", "stop-preview",
    "stream-dot", "stream-status", "spectrum-canvas", "spectrum-range", "waterfall-rx0",
    "waterfall-rx1", "rx0-level", "rx1-level", "frame-metadata", "capture-form",
    "capture-fieldset", "capture-duration", "capture-label", "capture-message", "refresh-jobs",
    "jobs-body", "refresh-artifacts", "artifacts-body", "analysis-form", "analysis-fieldset",
    "analysis-artifact", "analyzer-select", "analysis-parameters", "analysis-validation",
    "analysis-summary", "analysis-result", "toast-region",
    "firmware-availability", "inspect-firmware", "firmware-form", "firmware-fieldset",
    "firmware-image", "firmware-mode", "plan-firmware", "firmware-plan-output",
    "firmware-expected-version", "firmware-confirm-serial", "execute-firmware", "firmware-result",
    "scan-form", "scan-fieldset", "scan-start", "scan-stop", "scan-step", "scan-samples",
    "start-scan", "stop-scan", "scan-message", "scans-body",
    "doctor-health", "run-doctor", "prepare-doctor-fix", "doctor-profile",
    "doctor-release", "doctor-sha", "doctor-findings", "prepare-setup-fix",
    "setup-availability", "setup-admin-token", "setup-plan-output", "setup-confirm-serial",
    "execute-setup", "reconcile-setup", "setup-result",
  ].map((id) => [id, document.getElementById(id)]),
);

const state = {
  radios: new Map(),
  snapshot: null,
  socket: null,
  socketGeneration: 0,
  socketReconnectTimer: null,
  socketReconnectAttempts: 0,
  streaming: false,
  artifacts: [],
  analyzers: [],
  latestFrame: null,
  frameScheduled: false,
  lastPreviewRenderMs: 0,
  lastSpectrumRenderMs: 0,
  pollingTimer: null,
  settingsDirty: false,
  firmwareAvailable: false,
  firmwarePlan: null,
  scanning: false,
  doctorReport: null,
  doctorRepair: false,
  setupAvailable: false,
  setupPlan: null,
  uncertainSetupReceipt: null,
};

const diagnosticState = {
  startedAtMs: performance.now(),
  api: {
    requests: 0,
    failures: 0,
    responseBytes: 0,
    lastDurationMs: null,
  },
  waterfall: {
    socketState: "closed",
    connections: 0,
    reconnects: 0,
    messages: 0,
    payloadBytes: 0,
    parsedFrames: 0,
    renderedFrames: 0,
    coalescedFrames: 0,
    invalidFrames: 0,
    lastSequence: null,
    lastMessageAtMs: null,
    lastSummaryAtMs: performance.now(),
    lastSummaryMessages: 0,
    lastSummaryBytes: 0,
    lastSummaryRendered: 0,
  },
  browser: {
    longTasks: 0,
    eventLoopStalls: 0,
    largestStallMs: 0,
  },
};

function diagnosticLog(level, event, details = {}) {
  const payload = {
    event,
    elapsed_ms: Math.round(performance.now() - diagnosticState.startedAtMs),
    ...details,
  };
  const writer = typeof console[level] === "function" ? console[level] : console.log;
  writer.call(console, `[pluto+] ${JSON.stringify(payload)}`);
}

function diagnosticsSnapshot() {
  const now = performance.now();
  return {
    uptimeMs: Math.round(now - diagnosticState.startedAtMs),
    page: {
      visibility: document.visibilityState,
      online: navigator.onLine,
      selectedRadio: ui["radio-select"]?.value || null,
      radioState: state.snapshot?.state || null,
    },
    api: { ...diagnosticState.api },
    waterfall: {
      ...diagnosticState.waterfall,
      lastMessageAgeMs: diagnosticState.waterfall.lastMessageAtMs === null
        ? null
        : Math.round(now - diagnosticState.waterfall.lastMessageAtMs),
    },
    browser: { ...diagnosticState.browser },
  };
}

window.plutoDiagnostics = diagnosticsSnapshot;

class ApiError extends Error {
  constructor(message, status, code, document = null) {
    super(message);
    this.name = "ApiError";
    this.status = status;
    this.code = code;
    this.receipt = document?.receipt || null;
  }
}

async function apiRequest(path, options = {}) {
  const startedAtMs = performance.now();
  const method = String(options.method || "GET").toUpperCase();
  diagnosticState.api.requests += 1;
  const headers = new Headers(options.headers || {});
  if (options.body !== undefined && !headers.has("Content-Type")) {
    headers.set("Content-Type", "application/json");
  }
  headers.set("Accept", "application/json");
  let response;
  try {
    response = await fetch(`${API_ROOT}${path}`, { ...options, headers });
  } catch (error) {
    const durationMs = Math.round(performance.now() - startedAtMs);
    diagnosticState.api.failures += 1;
    diagnosticState.api.lastDurationMs = durationMs;
    diagnosticLog("warn", "api.transport_failure", {
      method,
      path,
      duration_ms: durationMs,
      error: error instanceof Error ? error.message : String(error),
    });
    throw error;
  }
  const durationMs = Math.round(performance.now() - startedAtMs);
  const contentLength = response.headers.get("content-length");
  const responseBytes = contentLength === null ? null : Number(contentLength);
  diagnosticState.api.lastDurationMs = durationMs;
  if (Number.isFinite(responseBytes) && responseBytes >= 0) {
    diagnosticState.api.responseBytes += responseBytes;
  }
  if (!response.ok) diagnosticState.api.failures += 1;
  diagnosticLog(response.ok ? "info" : "warn", "api.response", {
    method,
    path,
    status: response.status,
    duration_ms: durationMs,
    response_bytes: Number.isFinite(responseBytes) ? responseBytes : null,
  });
  let document = null;
  try {
    document = await response.json();
  } catch (_error) {
    // A useful transport error is produced below if the response was not successful.
  }
  if (!response.ok) {
    const detail = document && document.error ? document.error : {};
    throw new ApiError(
      detail.message || `Request failed (${response.status})`,
      response.status,
      detail.code,
      document,
    );
  }
  return document;
}

function adminHeaders() {
  if (!browserPrivilegedTransportSafe()) {
    throw new Error("Privileged actions require HTTPS or an SSH tunnel to loopback.");
  }
  const token = ui["setup-admin-token"].value;
  if (!token) throw new Error("Enter the admin bearer token first.");
  return { Authorization: `Bearer ${token}` };
}

function browserPrivilegedTransportSafe() {
  if (window.location.protocol === "https:") return true;
  const host = window.location.hostname.toLowerCase();
  return host === "localhost" || host === "127.0.0.1" || host === "::1";
}

function radioPath(radioId, suffix = "") {
  return `/radios/${encodeURIComponent(radioId)}${suffix}`;
}

function setText(element, value, fallback = "—") {
  element.textContent = value === null || value === undefined || value === "" ? fallback : String(value);
}

function setError(element, message) {
  setText(element, message, "");
  element.hidden = !message;
}

function makeElement(tag, textValue, className = "") {
  const element = document.createElement(tag);
  if (textValue !== undefined) {
    setText(element, textValue, "");
  }
  if (className) {
    element.className = className;
  }
  return element;
}

function toast(message, isError = false) {
  const item = makeElement("div", message, isError ? "toast error" : "toast");
  ui["toast-region"].append(item);
  window.setTimeout(() => item.remove(), 5000);
}

function describeError(error) {
  if (error instanceof Error) {
    return error.message;
  }
  return String(error);
}

function formatNumber(value, maximumFractionDigits = 0) {
  const number = Number(value);
  return Number.isFinite(number)
    ? new Intl.NumberFormat(undefined, { maximumFractionDigits }).format(number)
    : "—";
}

function formatHz(value) {
  const number = Number(value);
  if (!Number.isFinite(number)) return "—";
  if (Math.abs(number) >= 1e9) return `${(number / 1e9).toFixed(6)} GHz`;
  if (Math.abs(number) >= 1e6) return `${(number / 1e6).toFixed(3)} MHz`;
  if (Math.abs(number) >= 1e3) return `${(number / 1e3).toFixed(3)} kHz`;
  return `${number.toFixed(0)} Hz`;
}

function formatDate(value) {
  if (!value) return "—";
  const date = new Date(value);
  return Number.isNaN(date.getTime()) ? String(value) : date.toLocaleString();
}

function shortId(value) {
  const textValue = String(value || "—");
  return textValue.length > 14 ? `${textValue.slice(0, 12)}…` : textValue;
}

function setConnection(ok, textValue) {
  setText(ui["connection-status"], textValue);
  ui["connection-dot"].className = `status-dot ${ok ? "status-ok" : "status-error"}`;
}

async function checkHealth() {
  try {
    const health = await apiRequest("/health");
    setConnection(true, `Daemon ${health.version || "ready"} · ${health.radio_count} radio${health.radio_count === 1 ? "" : "s"}`);
  } catch (error) {
    setConnection(false, `Daemon unavailable · ${describeError(error)}`);
  }
}

async function loadRadios() {
  const selected = ui["radio-select"].value;
  try {
    const radios = await apiRequest("/radios");
    state.radios = new Map(radios.map((radio) => [radio.identity.radio_id, radio]));
    const options = [];
    if (!radios.length) {
      const option = makeElement("option", "No radios discovered");
      option.value = "";
      options.push(option);
    } else {
      for (const radio of radios) {
        const option = makeElement(
          "option",
          `${radio.identity.model || "Pluto+"} · ${radio.identity.serial} · ${radio.state}`,
        );
        option.value = radio.identity.radio_id;
        options.push(option);
      }
    }
    ui["radio-select"].replaceChildren(...options);
    const nextId = state.radios.has(selected) ? selected : (radios[0]?.identity.radio_id || "");
    if (nextId !== selected) state.settingsDirty = false;
    ui["radio-select"].value = nextId;
    if (nextId) {
      await loadSnapshot(nextId);
    } else {
      clearRadio();
    }
    await checkHealth();
  } catch (error) {
    clearRadio();
    setConnection(false, "Daemon unavailable");
    toast(describeError(error), true);
  }
}

async function loadSnapshot(radioId = ui["radio-select"].value) {
  if (!radioId) return;
  try {
    const snapshot = await apiRequest(`${radioPath(radioId)}/settings`);
    if (radioId !== ui["radio-select"].value) return;
    state.snapshot = snapshot;
    state.radios.set(radioId, snapshot);
    renderSnapshot(snapshot, !state.settingsDirty);
  } catch (error) {
    setError(ui["radio-error"], describeError(error));
    toast(describeError(error), true);
  }
}

function clearRadio() {
  state.snapshot = null;
  state.settingsDirty = false;
  ["radio-state", "radio-serial", "radio-transport", "radio-firmware", "radio-revision"].forEach(
    (id) => setText(ui[id], null),
  );
  setText(ui["radio-activity"], "Idle");
  ui["settings-fieldset"].disabled = true;
  ui["capture-fieldset"].disabled = true;
  ui["start-preview"].disabled = true;
  ui["stop-preview"].disabled = true;
  ui["scan-fieldset"].disabled = true;
  ui["stop-scan"].disabled = true;
  ui["recover-radio"].disabled = true;
  ui["run-doctor"].disabled = true;
  setText(ui["run-doctor"], "Run doctor");
  ui["prepare-doctor-fix"].disabled = true;
  ui["prepare-setup-fix"].disabled = true;
  clearSetupPlan("No setup plan created.");
  renderSettingsList(ui["requested-settings"], null);
  renderSettingsList(ui["actual-settings"], null);
}

function renderSnapshot(snapshot, populateForm = true) {
  const wasStreaming = state.streaming;
  const identity = snapshot.identity;
  setText(ui["radio-state"], snapshot.state);
  setText(ui["radio-serial"], identity.serial);
  setText(ui["radio-transport"], identity.transport);
  setText(ui["radio-firmware"], identity.firmware_version, "Unknown");
  setText(ui["radio-revision"], snapshot.revision);
  setText(ui["settings-revision"], `Revision ${snapshot.revision}`);
  setText(ui["radio-activity"], snapshot.activity_id ? shortId(snapshot.activity_id) : "Idle");
  setError(ui["radio-error"], snapshot.last_error || "");
  ui["recover-radio"].disabled = !["error", "offline"].includes(snapshot.state);
  renderSettingsList(ui["requested-settings"], snapshot.requested_settings);
  renderSettingsList(ui["actual-settings"], snapshot.actual_settings);
  if (populateForm) populateSettingsForm(snapshot.requested_settings);

  const configurable = snapshot.state === "ready" || snapshot.state === "streaming";
  const ready = snapshot.state === "ready";
  ui["settings-fieldset"].disabled = !configurable;
  ui["capture-fieldset"].disabled = !ready;
  state.streaming = snapshot.state === "streaming";
  state.scanning = snapshot.state === "scanning";
  if (wasStreaming && !state.streaming && state.socket) disconnectWaterfall();
  if (state.streaming && !state.socket && !state.socketReconnectTimer) {
    diagnosticLog("info", "waterfall.auto_attach", {
      radio_id: identity.radio_id,
      reason: wasStreaming ? "socket_missing" : "page_loaded_mid_stream",
    });
    connectWaterfall(identity.radio_id, "snapshot");
  }
  ui["start-preview"].disabled = !ready;
  ui["stop-preview"].disabled = !state.streaming;
  ui["scan-fieldset"].disabled = !(ready || state.scanning);
  ui["start-scan"].disabled = !ready;
  ui["stop-scan"].disabled = !state.scanning;
  setStreamStatus(state.streaming, state.streaming ? "Streaming" : "Stopped");
  updateFirmwareEnabled();
  updateSetupEnabled();
  ui["run-doctor"].disabled = false;
}

function renderDoctor(report, reveal = false) {
  state.doctorReport = report;
  const attentionCount = report.findings.filter((finding) => finding.status !== "pass").length;
  const checkedAt = new Date(report.checked_at);
  const checkedLabel = Number.isNaN(checkedAt.getTime()) ? "just now" : checkedAt.toLocaleTimeString();
  setText(
    ui["doctor-health"],
    report.healthy ? `Canonical · ${checkedLabel}` : `${attentionCount} items need attention · ${checkedLabel}`,
  );
  ui["doctor-health"].className = report.healthy ? "deferred-badge doctor-pass" : "deferred-badge doctor-warn";
  const policy = report.canonical_policy;
  setText(ui["doctor-profile"], policy.profile_id);
  setText(ui["doctor-release"], policy.release_tag);
  setText(ui["doctor-sha"], policy.asset_sha256);
  const statusOrder = { fail: 0, warn: 1, unknown: 2, pass: 3 };
  const findings = [...report.findings]
    .sort((left, right) => statusOrder[left.status] - statusOrder[right.status])
    .map((finding) => {
    const item = makeElement("article", undefined, `doctor-finding doctor-${finding.status}`);
    const heading = makeElement("h3", `${finding.status.toUpperCase()} · ${finding.summary}`);
    const code = makeElement("p", finding.code, "hint mono");
    const comparison = makeElement("p", `Actual: ${JSON.stringify(finding.actual)} · Expected: ${JSON.stringify(finding.expected)}`);
    const evidence = makeElement("p", finding.evidence, "hint");
    item.append(heading, code, comparison, evidence);
    if (finding.remediation) {
      const repair = makeElement("p", `${finding.remediation.title}: ${finding.remediation.description}`);
      repair.className = "doctor-remediation";
      item.append(repair);
    }
    return item;
    });
  ui["doctor-findings"].replaceChildren(...findings);
  ui["prepare-doctor-fix"].disabled = !report.findings.some(
    (finding) => finding.remediation?.remediation_id === "flash_canonical_firmware_mtd3",
  );
  updateSetupEnabled();
  if (reveal) ui["doctor-findings"].scrollIntoView({ behavior: "smooth", block: "start" });
}

async function runDoctor(reveal = false) {
  if (!state.snapshot) return;
  ui["run-doctor"].disabled = true;
  setText(ui["run-doctor"], "Checking…");
  setText(ui["doctor-health"], "Checking…");
  try {
    const report = await apiRequest(`${radioPath(state.snapshot.identity.radio_id)}/doctor`);
    renderDoctor(report, reveal);
  } catch (error) {
    setText(ui["doctor-health"], `Failed · ${describeError(error)}`);
    toast(describeError(error), true);
  } finally {
    ui["run-doctor"].disabled = !state.snapshot;
    setText(ui["run-doctor"], state.doctorReport ? "Run again" : "Run doctor");
  }
}

function prepareDoctorFix() {
  const policy = state.doctorReport?.canonical_policy;
  if (!policy) return;
  ui["firmware-expected-version"].value = policy.device_firmware;
  ui["firmware-mode"].value = "volatile_dfu";
  state.doctorRepair = true;
  updateFirmwareEnabled();
  ui["firmware-form"].scrollIntoView({ behavior: "smooth", block: "center" });
  setText(
    ui["firmware-result"],
    `Choose ${policy.asset_name}; its SHA-256 must be ${policy.asset_sha256}. Qualify it in RAM before a separate persistent plan.`,
  );
}

function setupRepairNeeded() {
  return Boolean(state.doctorReport?.findings.some(
    (finding) => finding.status !== "pass"
      && finding.remediation?.remediation_id === "provision_ad9361_2r2t",
  ));
}

function updateSetupEnabled() {
  const ready = state.snapshot?.state === "ready";
  ui["prepare-setup-fix"].disabled = !(state.setupAvailable && ready && setupRepairNeeded());
  ui["execute-setup"].disabled = !state.setupPlan;
  ui["reconcile-setup"].disabled = !state.uncertainSetupReceipt;
}

function clearSetupPlan(message = "No setup plan created.") {
  state.setupPlan = null;
  ui["setup-confirm-serial"].value = "";
  ui["execute-setup"].disabled = true;
  setText(ui["setup-plan-output"], message);
}

function clearSetupUncertainty() {
  state.uncertainSetupReceipt = null;
  ui["reconcile-setup"].disabled = true;
}

function validatedSetupPlan(document) {
  const plan = document?.plan;
  const selected = state.snapshot?.identity;
  const expectedValues = {
    attr_name: "compatible",
    attr_val: "ad9361",
    compatible: "ad9361",
    mode: "2r2t",
  };
  if (!plan || !document.confirmation_token || !selected) {
    throw new Error("Daemon returned an incomplete setup plan.");
  }
  if (plan.identity?.serial !== selected.serial || plan.identity?.usb_sysfs_path !== selected.usb_path) {
    throw new Error("Setup plan identity does not match the selected radio.");
  }
  if (!Array.isArray(plan.changes_items) || !plan.changes_items.length) {
    throw new Error("Setup plan has no canonical changes.");
  }
  if (typeof plan.tx_mute_required !== "boolean") {
    throw new Error("Setup plan omitted its transmit-safety action.");
  }
  const changes = {};
  for (const item of plan.changes_items) {
    if (!Array.isArray(item) || item.length !== 2 || expectedValues[item[0]] !== item[1]) {
      throw new Error("Setup plan contains a non-canonical field or value.");
    }
    changes[item[0]] = item[1];
  }
  return {
    plan: {
      plan_id: plan.plan_id,
      expires_at: plan.expires_at,
      identity: {
        serial: plan.identity.serial,
        usb_sysfs_path: plan.identity.usb_sysfs_path,
        observed_firmware: plan.identity.observed_firmware,
      },
      profile_id: plan.profile_id,
      environment_sha256: plan.environment_sha256,
      changes,
      transmit_safety: plan.tx_mute_required
        ? "Required action: apply and verify fail-closed TX mute before the environment write"
        : "Already fail-closed; every TX safety indicator will be reread before write",
    },
    confirmationToken: document.confirmation_token,
  };
}

async function loadSetupStatus() {
  try {
    const status = await apiRequest("/setup");
    state.setupAvailable = Boolean(status.available) && browserPrivilegedTransportSafe();
    setText(
      ui["setup-availability"],
      state.setupAvailable
        ? "Guarded setup helper ready"
        : (browserPrivilegedTransportSafe()
          ? "Setup mutation not configured"
          : "Read-only mode · use HTTPS or an SSH tunnel to loopback"),
    );
  } catch (error) {
    state.setupAvailable = false;
    setText(ui["setup-availability"], `Unavailable · ${describeError(error)}`);
  }
  updateSetupEnabled();
}

async function prepareSetupFix() {
  if (!state.snapshot || !setupRepairNeeded()) return;
  clearSetupPlan("Creating a serial- and environment-bound setup plan…");
  setText(ui["setup-result"], "Inspecting persistent setup and transmit-safe state…");
  try {
    const planned = await apiRequest(
      `${radioPath(state.snapshot.identity.radio_id)}/doctor/setup-plans`,
      {
        method: "POST",
        headers: adminHeaders(),
        body: JSON.stringify({}),
      },
    );
    state.setupPlan = validatedSetupPlan(planned);
    setText(ui["setup-plan-output"], JSON.stringify(state.setupPlan.plan, null, 2));
    setText(
      ui["setup-result"],
      `Plan ready. Verify the immutable diff and type PROVISION ${state.snapshot.identity.serial}.`,
    );
    ui["setup-plan-output"].scrollIntoView({ behavior: "smooth", block: "center" });
  } catch (error) {
    clearSetupPlan("Setup plan was not created.");
    setText(ui["setup-result"], describeError(error));
    toast(describeError(error), true);
  }
  updateSetupEnabled();
}

async function executeSetup() {
  if (!state.snapshot || !state.setupPlan) return;
  const required = `PROVISION ${state.snapshot.identity.serial}`;
  if (ui["setup-confirm-serial"].value !== required) {
    setText(ui["setup-result"], `Confirmation must exactly match ${required}.`);
    return;
  }
  const plan = state.setupPlan;
  ui["execute-setup"].disabled = true;
  setText(ui["setup-result"], "Provisioning in progress. Do not disconnect power or USB.");
  try {
    const receipt = await apiRequest("/setup/executions", {
      method: "POST",
      headers: adminHeaders(),
      body: JSON.stringify({
        plan_id: plan.plan.plan_id,
        confirmation_token: plan.confirmationToken,
      }),
    });
    clearSetupPlan("Plan consumed. A new doctor run is required for any further repair.");
    clearSetupUncertainty();
    ui["setup-admin-token"].value = "";
    setText(ui["setup-result"], `Setup verified · receipt ${receipt.receipt_id}`);
    await loadSnapshot();
    await runDoctor(true);
  } catch (error) {
    clearSetupPlan("Plan consumed. Never replay an execution with an uncertain outcome.");
    const receipt = error instanceof ApiError ? error.receipt : null;
    if (receipt?.outcome === "unknown" && receipt.reconciliation_required) {
      state.uncertainSetupReceipt = receipt;
      setText(
        ui["setup-result"],
        `Outcome unknown · Do not retry. Receipt ${receipt.receipt_id}. `
          + `Failure phase: ${receipt.failure_phase || "unknown"}. `
          + `Backup: ${receipt.backup_path || "unavailable"}. `
          + `SHA-256: ${receipt.backup_sha256 || "unavailable"}. `
          + "After pinned SSH trust is updated out of band, run read-only reconcile.",
      );
    } else {
      ui["setup-admin-token"].value = "";
      setText(ui["setup-result"], describeError(error));
    }
    toast(describeError(error), true);
    await loadSnapshot();
    await runDoctor(true);
  }
  updateSetupEnabled();
}

async function reconcileSetup() {
  const uncertain = state.uncertainSetupReceipt;
  if (!uncertain) return;
  ui["reconcile-setup"].disabled = true;
  setText(ui["setup-result"], "Running read-only serial, setup, and firmware attestation…");
  try {
    const receipt = await apiRequest(
      `/setup/receipts/${encodeURIComponent(uncertain.receipt_id)}/reconcile`,
      { method: "POST", headers: adminHeaders(), body: JSON.stringify({}) },
    );
    clearSetupUncertainty();
    ui["setup-admin-token"].value = "";
    setText(
      ui["setup-result"],
      receipt.outcome === "reconciled_verified"
        ? `Read-only reconciliation verified setup · receipt ${receipt.receipt_id}`
        : `Read-only reconciliation found setup not canonical · receipt ${receipt.receipt_id}`,
    );
    await loadSnapshot();
    await runDoctor(true);
  } catch (error) {
    ui["reconcile-setup"].disabled = false;
    setText(
      ui["setup-result"],
      `Reconciliation unavailable: ${describeError(error)} Do not retry provisioning.`,
    );
  }
}

function updateFirmwareEnabled() {
  const snapshot = state.snapshot;
  const capabilities = snapshot?.capabilities || {};
  const mode = ui["firmware-mode"].value;
  const radioSupportsMode = mode === "persistent_qspi"
    ? capabilities.supports_persistent_firmware
    : capabilities.supports_volatile_firmware;
  const ready = snapshot?.state === "ready";
  ui["firmware-fieldset"].disabled = !(state.firmwareAvailable && ready && radioSupportsMode);
  ui["execute-firmware"].disabled = !state.firmwarePlan;
}

async function loadFirmwareStatus() {
  try {
    const status = await apiRequest("/firmware");
    state.firmwareAvailable = Boolean(status.available) && browserPrivilegedTransportSafe();
    setText(
      ui["firmware-availability"],
      state.firmwareAvailable
        ? "Guarded helper ready"
        : (browserPrivilegedTransportSafe()
          ? "Privileged helper not configured"
          : "Read-only mode · use HTTPS or an SSH tunnel to loopback"),
    );
  } catch (error) {
    state.firmwareAvailable = false;
    setText(ui["firmware-availability"], `Unavailable · ${describeError(error)}`);
  }
  updateFirmwareEnabled();
}

async function recoverRadio() {
  if (!state.snapshot) return;
  ui["recover-radio"].disabled = true;
  try {
    const snapshot = await apiRequest(
      `${radioPath(state.snapshot.identity.radio_id)}/recover`,
      { method: "POST" },
    );
    state.snapshot = snapshot;
    renderSnapshot(snapshot);
    toast("Radio reopened and serial re-attested.");
  } catch (error) {
    toast(describeError(error), true);
    await loadSnapshot();
  }
}

async function inspectFirmware() {
  await Promise.all([loadFirmwareStatus(), loadSnapshot()]);
  if (!state.snapshot) return;
  const identity = state.snapshot.identity;
  setText(
    ui["firmware-result"],
    `Serial ${identity.serial} · ${identity.firmware_version || "unknown firmware"} · ${identity.usb_path || "no attested USB path"}`,
  );
}

async function planFirmware(event) {
  event.preventDefault();
  if (!state.snapshot) return;
  const file = ui["firmware-image"].files?.[0];
  if (!file) {
    setText(ui["firmware-result"], "Choose one .dfu or .frm image.");
    return;
  }
  state.firmwarePlan = null;
  updateFirmwareEnabled();
  setText(ui["firmware-result"], "Uploading and validating firmware…");
  try {
    const upload = await apiRequest(`/firmware/images?filename=${encodeURIComponent(file.name)}`, {
      method: "POST",
      headers: { ...adminHeaders(), "Content-Type": "application/octet-stream" },
      body: await file.arrayBuffer(),
    });
    const planSuffix = state.doctorRepair ? "/doctor/firmware-plans" : "/firmware/plans";
    const planned = await apiRequest(
      `${radioPath(state.snapshot.identity.radio_id)}${planSuffix}`,
      {
        method: "POST",
        headers: adminHeaders(),
        body: JSON.stringify({
          image_id: upload.image_id,
          mode: ui["firmware-mode"].value,
          expected_firmware_version: ui["firmware-expected-version"].value.trim(),
        }),
      },
    );
    state.firmwarePlan = planned;
    state.doctorRepair = false;
    setText(ui["firmware-plan-output"], JSON.stringify(planned, null, 2));
    setText(
      ui["firmware-result"],
      "Plan created. Verify every field, type the selected serial, then execute before expiry.",
    );
    updateFirmwareEnabled();
  } catch (error) {
    setText(ui["firmware-result"], describeError(error));
    toast(describeError(error), true);
  }
}

async function executeFirmware() {
  if (!state.snapshot || !state.firmwarePlan) return;
  if (ui["firmware-confirm-serial"].value !== state.snapshot.identity.serial) {
    setText(ui["firmware-result"], "Confirmation must exactly match the selected radio serial.");
    return;
  }
  ui["execute-firmware"].disabled = true;
  setText(ui["firmware-result"], "Firmware operation in progress. Do not disconnect power.");
  try {
    const receipt = await apiRequest("/firmware/executions", {
      method: "POST",
      headers: adminHeaders(),
      body: JSON.stringify({
        plan_id: state.firmwarePlan.plan.plan_id,
        confirmation_token: state.firmwarePlan.confirmation_token,
      }),
    });
    state.firmwarePlan = null;
    state.doctorRepair = false;
    ui["firmware-confirm-serial"].value = "";
    setText(ui["firmware-plan-output"], "Plan consumed. Create a new plan for another update.");
    setText(ui["firmware-result"], `Update verified · receipt ${receipt.receipt_id}`);
    await loadRadios();
  } catch (error) {
    state.firmwarePlan = null;
    setText(ui["firmware-result"], describeError(error));
    toast(describeError(error), true);
  }
  updateFirmwareEnabled();
}

function scanPayload() {
  if (!state.snapshot) throw new Error("Select a radio first.");
  const start = Number(ui["scan-start"].value);
  const stop = Number(ui["scan-stop"].value);
  const step = Number(ui["scan-step"].value);
  const samples = Number(ui["scan-samples"].value);
  if (![start, stop, step, samples].every((value) => Number.isFinite(value) && value > 0)) {
    throw new Error("Scan bounds, step, and samples must be positive.");
  }
  if (stop < start) throw new Error("Scan stop must not be below start.");
  const settings = state.snapshot.actual_settings;
  return {
    start_frequency_hz: start,
    stop_frequency_hz: stop,
    step_hz: step,
    sample_rate_hz: settings.sample_rate_hz,
    bandwidth_hz: settings.bandwidth_hz,
    gain_mode: settings.gain_mode,
    gain_db: settings.gain_db,
    channels: settings.channels,
    samples_per_frequency: Math.round(samples),
    fft_size: 2 ** Math.floor(Math.log2(Math.min(4096, Math.round(samples)))),
    settle_buffers: 1,
  };
}

async function startScan(event) {
  event.preventDefault();
  if (!state.snapshot) return;
  try {
    const job = await apiRequest(`${radioPath(state.snapshot.identity.radio_id)}/scans`, {
      method: "POST",
      body: JSON.stringify(scanPayload()),
    });
    state.scanning = true;
    setText(ui["scan-message"], `Scan ${shortId(job.job_id)} is running exclusively.`);
    await loadSnapshot();
  } catch (error) {
    setText(ui["scan-message"], describeError(error));
    toast(describeError(error), true);
  }
}

async function stopScan() {
  if (!state.snapshot) return;
  try {
    const job = await apiRequest(`${radioPath(state.snapshot.identity.radio_id)}/scans/current`, {
      method: "DELETE",
    });
    setText(ui["scan-message"], `Scan ${shortId(job.job_id)} canceled; prior tune restored.`);
    await Promise.all([loadSnapshot(), loadScans()]);
  } catch (error) {
    setText(ui["scan-message"], describeError(error));
    toast(describeError(error), true);
  }
}

async function loadScans() {
  try {
    const scans = await apiRequest("/scans");
    const rows = scans.slice(0, MAX_TABLE_ROWS).map((scan) => {
      const row = makeElement("tr");
      row.append(
        makeElement("td", shortId(scan.scan_id)),
        makeElement("td", scan.radio_id),
        makeElement("td", formatNumber(scan.points?.length || 0)),
        makeElement("td", formatDate(scan.finished_at)),
      );
      return row;
    });
    if (!rows.length) {
      const row = makeElement("tr");
      const cell = makeElement("td", "No completed scans yet.");
      cell.colSpan = 4;
      row.append(cell);
      rows.push(row);
    }
    ui["scans-body"].replaceChildren(...rows);
  } catch (error) {
    toast(`Could not load scans: ${describeError(error)}`, true);
  }
}

function renderSettingsList(container, settings) {
  if (!settings) {
    const row = makeElement("div");
    row.append(makeElement("dt", "Waiting"), makeElement("dd", "—"));
    container.replaceChildren(row);
    return;
  }
  const gain = settings.gain_mode === "manual" ? `${formatNumber(settings.gain_db, 1)} dB` : "Automatic";
  const values = [
    ["Center", formatHz(settings.center_frequency_hz)],
    ["Sample rate", formatHz(settings.sample_rate_hz)],
    ["Bandwidth", formatHz(settings.bandwidth_hz)],
    ["Gain mode", settings.gain_mode],
    ["Gain", gain],
    ["Channels", (settings.channels || []).join(", ")],
  ];
  const rows = values.map(([label, value]) => {
    const row = makeElement("div");
    row.append(makeElement("dt", label), makeElement("dd", value));
    return row;
  });
  container.replaceChildren(...rows);
}

function populateSettingsForm(settings) {
  ui["center-frequency"].value = settings.center_frequency_hz;
  ui["sample-rate"].value = settings.sample_rate_hz;
  ui.bandwidth.value = settings.bandwidth_hz;
  ui["gain-mode"].value = settings.gain_mode;
  ui["gain-db"].value = settings.gain_db ?? "";
  syncGainControl();
}

function syncGainControl() {
  const manual = ui["gain-mode"].value === "manual";
  ui["gain-db"].disabled = !manual;
  ui["gain-db"].required = manual;
  if (!manual) ui["gain-db"].value = "";
  if (manual && ui["gain-db"].value === "") ui["gain-db"].value = "40";
}

function settingsPayload() {
  const center = Number(ui["center-frequency"].value);
  const sampleRate = Number(ui["sample-rate"].value);
  const bandwidth = Number(ui.bandwidth.value);
  const manual = ui["gain-mode"].value === "manual";
  const gain = manual ? Number(ui["gain-db"].value) : null;
  if (![center, sampleRate, bandwidth].every((value) => Number.isFinite(value) && value > 0)) {
    throw new Error("Frequency, sample rate, and bandwidth must be positive numbers.");
  }
  if (bandwidth > sampleRate) {
    throw new Error("RF bandwidth cannot exceed the sample rate.");
  }
  if (manual && (!Number.isFinite(gain) || gain < -10 || gain > 80)) {
    throw new Error("Manual gain must be between −10 and 80 dB.");
  }
  return {
    expected_revision: state.snapshot.revision,
    center_frequency_hz: center,
    sample_rate_hz: sampleRate,
    bandwidth_hz: bandwidth,
    gain_mode: ui["gain-mode"].value,
    gain_db: gain,
    channels: [0, 1],
  };
}

async function applySettings(event) {
  event.preventDefault();
  if (!state.snapshot) return;
  setError(ui["settings-validation"], "");
  try {
    const payload = settingsPayload();
    const snapshot = await apiRequest(`${radioPath(state.snapshot.identity.radio_id)}/settings`, {
      method: "PATCH",
      body: JSON.stringify(payload),
    });
    state.snapshot = snapshot;
    state.settingsDirty = false;
    renderSnapshot(snapshot);
    toast("Settings applied and verified by read-back.");
  } catch (error) {
    setError(ui["settings-validation"], describeError(error));
    if (error instanceof ApiError && error.code === "revision_conflict") {
      await loadSnapshot();
    }
  }
}

function streamPayload(persist) {
  const fftSize = Number(ui["fft-size"].value);
  const request = { block_size: 65536, fft_size: fftSize, persist };
  if (persist) {
    const duration = Number(ui["capture-duration"].value);
    if (!Number.isFinite(duration) || duration <= 0 || duration > 3600) {
      throw new Error("Capture duration must be between 0.1 and 3,600 seconds.");
    }
    request.duration_s = duration;
    const label = ui["capture-label"].value.trim();
    if (label) request.label = label;
  }
  return request;
}

async function startPreview() {
  if (!state.snapshot) return;
  try {
    const radioId = state.snapshot.identity.radio_id;
    const job = await apiRequest(`${radioPath(radioId)}/streams`, {
      method: "POST",
      body: JSON.stringify(streamPayload(false)),
    });
    state.streaming = true;
    setStreamStatus(true, `Preview · ${shortId(job.job_id)}`);
    ui["start-preview"].disabled = true;
    ui["stop-preview"].disabled = false;
    connectWaterfall(radioId);
    await Promise.all([loadJobs(), loadSnapshot(radioId)]);
  } catch (error) {
    toast(describeError(error), true);
  }
}

async function stopPreview() {
  if (!state.snapshot) return;
  const radioId = state.snapshot.identity.radio_id;
  ui["stop-preview"].disabled = true;
  try {
    await apiRequest(`${radioPath(radioId)}/streams/current`, { method: "DELETE" });
    disconnectWaterfall();
    state.streaming = false;
    setStreamStatus(false, "Stopped");
    await Promise.all([loadJobs(), loadArtifacts(), loadSnapshot(radioId)]);
  } catch (error) {
    toast(describeError(error), true);
    await loadSnapshot(radioId);
  }
}

async function startCapture(event) {
  event.preventDefault();
  if (!state.snapshot) return;
  setText(ui["capture-message"], "Starting capture…");
  try {
    const radioId = state.snapshot.identity.radio_id;
    const job = await apiRequest(`${radioPath(radioId)}/streams`, {
      method: "POST",
      body: JSON.stringify(streamPayload(true)),
    });
    setText(ui["capture-message"], `Capture ${shortId(job.job_id)} started. It will stop at its configured bound.`);
    state.streaming = true;
    connectWaterfall(radioId);
    await Promise.all([loadJobs(), loadSnapshot(radioId)]);
  } catch (error) {
    setText(ui["capture-message"], describeError(error));
    toast(describeError(error), true);
  }
}

function setStreamStatus(live, textValue) {
  setText(ui["stream-status"], textValue);
  ui["stream-dot"].className = `status-dot ${live ? "status-live" : "status-idle"}`;
}

function connectWaterfall(radioId, reason = "requested") {
  const reconnectAttempts = state.socketReconnectAttempts;
  disconnectWaterfall();
  if (reason === "reconnect") state.socketReconnectAttempts = reconnectAttempts;
  const generation = ++state.socketGeneration;
  const protocol = window.location.protocol === "https:" ? "wss:" : "ws:";
  const url = `${protocol}//${window.location.host}${API_ROOT}/ws/radios/${encodeURIComponent(radioId)}/waterfall`;
  let messagesOnSocket = 0;
  diagnosticState.waterfall.socketState = "connecting";
  diagnosticState.waterfall.connections += 1;
  if (reason === "reconnect") diagnosticState.waterfall.reconnects += 1;
  diagnosticLog("info", "waterfall.socket_connect", {
    radio_id: radioId,
    reason,
    attempt: state.socketReconnectAttempts,
    url,
  });
  const socket = new WebSocket(url);
  state.socket = socket;
  socket.addEventListener("open", () => {
    if (generation !== state.socketGeneration) return;
    diagnosticState.waterfall.socketState = "open";
    state.socketReconnectAttempts = 0;
    setStreamStatus(true, "Live · receiving spectrum");
    diagnosticLog("info", "waterfall.socket_open", { radio_id: radioId });
  });
  socket.addEventListener("message", (event) => {
    if (generation !== state.socketGeneration || typeof event.data !== "string") return;
    diagnosticState.waterfall.messages += 1;
    messagesOnSocket += 1;
    diagnosticState.waterfall.payloadBytes += event.data.length;
    diagnosticState.waterfall.lastMessageAtMs = performance.now();
    try {
      const frame = JSON.parse(event.data);
      diagnosticState.waterfall.parsedFrames += 1;
      diagnosticState.waterfall.lastSequence = frame.sequence ?? null;
      if (messagesOnSocket === 1) {
        diagnosticLog("info", "waterfall.first_frame", {
          radio_id: radioId,
          sequence: diagnosticState.waterfall.lastSequence,
          payload_bytes: event.data.length,
        });
      }
      enqueueFrame(frame);
    } catch (error) {
      diagnosticState.waterfall.invalidFrames += 1;
      setStreamStatus(true, "Live · invalid frame skipped");
      diagnosticLog("warn", "waterfall.invalid_frame", {
        payload_bytes: event.data.length,
        error: error instanceof Error ? error.message : String(error),
      });
    }
  });
  socket.addEventListener("close", (event) => {
    if (generation !== state.socketGeneration) return;
    state.socket = null;
    diagnosticState.waterfall.socketState = "closed";
    diagnosticLog(state.streaming ? "warn" : "info", "waterfall.socket_close", {
      radio_id: radioId,
      code: event.code,
      clean: event.wasClean,
      reason: String(event.reason || "").slice(0, 160),
      streaming: state.streaming,
    });
    if (state.streaming) {
      setStreamStatus(false, "Stream disconnected · reconnecting");
      scheduleWaterfallReconnect(radioId);
    }
  });
  socket.addEventListener("error", () => {
    if (generation !== state.socketGeneration) return;
    diagnosticState.waterfall.socketState = "error";
    setStreamStatus(false, "Waterfall connection error");
    diagnosticLog("warn", "waterfall.socket_error", { radio_id: radioId });
  });
}

function scheduleWaterfallReconnect(radioId) {
  if (state.socketReconnectTimer || !state.streaming) return;
  state.socketReconnectAttempts += 1;
  const delayMs = Math.min(
    WATERFALL_RECONNECT_MAX_DELAY_MS,
    500 * (2 ** Math.min(4, state.socketReconnectAttempts - 1)),
  );
  diagnosticLog("info", "waterfall.reconnect_scheduled", {
    radio_id: radioId,
    attempt: state.socketReconnectAttempts,
    delay_ms: delayMs,
  });
  state.socketReconnectTimer = window.setTimeout(() => {
    state.socketReconnectTimer = null;
    const selectedRadio = state.snapshot?.identity.radio_id;
    if (state.streaming && selectedRadio === radioId) connectWaterfall(radioId, "reconnect");
  }, delayMs);
}

function disconnectWaterfall() {
  state.socketGeneration += 1;
  if (state.socketReconnectTimer) {
    window.clearTimeout(state.socketReconnectTimer);
    state.socketReconnectTimer = null;
  }
  state.socketReconnectAttempts = 0;
  if (state.socket) {
    state.socket.close(1000, "UI stopped stream");
    state.socket = null;
  }
  diagnosticState.waterfall.socketState = "closed";
}

function validPowerRows(frame) {
  if (!frame || !Array.isArray(frame.receiver_power_db)) return null;
  const rows = frame.receiver_power_db.slice(0, 2).map((row) => {
    if (!Array.isArray(row) || row.length < 2) return null;
    const stride = Math.max(1, Math.ceil(row.length / MAX_PREVIEW_BINS));
    const values = [];
    for (let index = 0; index < row.length; index += stride) {
      const value = Number(row[index]);
      if (!Number.isFinite(value)) return null;
      values.push(value);
    }
    return values.length >= 2 ? values : null;
  });
  return rows.length && rows[0] ? rows : null;
}

function enqueueFrame(frame) {
  if (!frame || !Array.isArray(frame.receiver_power_db)) {
    diagnosticState.waterfall.invalidFrames += 1;
    return;
  }
  if (state.frameScheduled && state.latestFrame) diagnosticState.waterfall.coalescedFrames += 1;
  state.latestFrame = frame;
  if (state.frameScheduled) return;
  state.frameScheduled = true;
  const interval = 1000 / PREVIEW_MAX_FPS;
  const delay = Math.max(0, interval - (performance.now() - state.lastPreviewRenderMs));
  window.setTimeout(() => {
    window.requestAnimationFrame(() => {
      state.frameScheduled = false;
      state.lastPreviewRenderMs = performance.now();
      const latest = state.latestFrame;
      state.latestFrame = null;
      if (latest) renderFrame(latest);
    });
  }, delay);
}

function renderFrame(frame) {
  const rows = validPowerRows(frame);
  if (!rows) {
    diagnosticState.waterfall.invalidFrames += 1;
    return;
  }
  diagnosticState.waterfall.renderedFrames += 1;
  const now = performance.now();
  if (now - state.lastSpectrumRenderMs >= 1000 / SPECTRUM_MAX_FPS) {
    drawSpectrum(rows);
    state.lastSpectrumRenderMs = now;
  }
  rows.forEach((row, index) => {
    if (!row) return;
    if (index < 2) drawWaterfallRow(index === 0 ? ui["waterfall-rx0"] : ui["waterfall-rx1"], row);
    const peak = row.reduce((maximum, value) => Math.max(maximum, value), -Infinity);
    if (index === 0) setText(ui["rx0-level"], `${peak.toFixed(1)} dB peak`);
    if (index === 1) setText(ui["rx1-level"], `${peak.toFixed(1)} dB peak`);
  });
  const center = Number(frame.center_frequency_hz);
  const sampleRate = Number(frame.sample_rate_hz);
  if (Number.isFinite(center) && Number.isFinite(sampleRate)) {
    setText(ui["spectrum-range"], `${formatHz(center - sampleRate / 2)} — ${formatHz(center + sampleRate / 2)}`);
  }
  const timestamp = Number(frame.utc_ns) / 1e6;
  const received = Number.isFinite(timestamp) ? new Date(timestamp).toISOString() : "unknown time";
  setText(
    ui["frame-metadata"],
    `Frame ${formatNumber(frame.sequence)} · rev ${formatNumber(frame.configuration_revision)} · ${received} · ${formatHz(frame.bin_width_hz)}/bin`,
  );
  maybeLogWaterfallSummary();
}

function maybeLogWaterfallSummary() {
  const metrics = diagnosticState.waterfall;
  const now = performance.now();
  const elapsedMs = now - metrics.lastSummaryAtMs;
  const renderedSinceSummary = metrics.renderedFrames - metrics.lastSummaryRendered;
  if (elapsedMs < DIAGNOSTIC_SUMMARY_INTERVAL_MS && renderedSinceSummary < 50) return;
  const messages = metrics.messages - metrics.lastSummaryMessages;
  const payloadBytes = metrics.payloadBytes - metrics.lastSummaryBytes;
  const rendered = metrics.renderedFrames - metrics.lastSummaryRendered;
  diagnosticLog("info", "waterfall.render_summary", {
    interval_ms: Math.round(elapsedMs),
    messages,
    rendered_frames: rendered,
    coalesced_total: metrics.coalescedFrames,
    payload_bytes: payloadBytes,
    kib_per_second: elapsedMs > 0 ? Number((payloadBytes / 1024 / (elapsedMs / 1000)).toFixed(1)) : 0,
    render_fps: elapsedMs > 0 ? Number((rendered / (elapsedMs / 1000)).toFixed(1)) : 0,
    last_sequence: metrics.lastSequence,
  });
  metrics.lastSummaryAtMs = now;
  metrics.lastSummaryMessages = metrics.messages;
  metrics.lastSummaryBytes = metrics.payloadBytes;
  metrics.lastSummaryRendered = metrics.renderedFrames;
}

function fitCanvas(canvas) {
  const width = Math.max(1, Math.min(MAX_CANVAS_WIDTH, Math.floor(canvas.clientWidth)));
  const fallbackHeight = Number(canvas.getAttribute("height"));
  const height = Math.max(1, Math.floor(canvas.clientHeight || fallbackHeight));
  if (canvas.width !== width || canvas.height !== height) {
    const previous = [canvas.width, canvas.height];
    canvas.width = width;
    canvas.height = height;
    diagnosticLog("debug", "canvas.resize", {
      canvas: canvas.id,
      previous,
      current: [width, height],
      css: [canvas.clientWidth, canvas.clientHeight],
    });
    return true;
  }
  return false;
}

function powerBounds(rows) {
  const samples = rows.flat().filter(Number.isFinite).sort((a, b) => a - b);
  if (!samples.length) return [-120, -20];
  const low = samples[Math.floor(samples.length * 0.04)];
  const high = samples[Math.min(samples.length - 1, Math.floor(samples.length * 0.98))];
  return [Math.floor((low - 4) / 10) * 10, Math.ceil((high + 4) / 10) * 10];
}

function drawSpectrum(rows) {
  const canvas = ui["spectrum-canvas"];
  fitCanvas(canvas);
  const context = canvas.getContext("2d");
  const width = canvas.width;
  const height = canvas.height;
  const ratio = 1;
  const inset = { left: 32, right: 5, top: 4, bottom: 4 };
  const plotWidth = width - inset.left - inset.right;
  const plotHeight = height - inset.top - inset.bottom;
  const [minimum, maximumRaw] = powerBounds(rows);
  const maximum = maximumRaw <= minimum ? minimum + 10 : maximumRaw;

  context.fillStyle = "#030a0e";
  context.fillRect(0, 0, width, height);
  context.strokeStyle = "#17333d";
  context.fillStyle = "#78999f";
  context.font = "8px ui-monospace, monospace";
  context.lineWidth = ratio;
  for (let index = 0; index <= 2; index += 1) {
    const y = inset.top + (plotHeight * index) / 2;
    context.beginPath();
    context.moveTo(inset.left, y);
    context.lineTo(width - inset.right, y);
    context.stroke();
    const label = maximum - ((maximum - minimum) * index) / 2;
    context.fillText(`${label.toFixed(0)}`, 2, y + 3);
  }
  for (let index = 0; index <= 2; index += 1) {
    const x = inset.left + (plotWidth * index) / 2;
    context.beginPath();
    context.moveTo(x, inset.top);
    context.lineTo(x, height - inset.bottom);
    context.stroke();
  }

  const colors = ["#3de2d0", "#ffbd59"];
  rows.forEach((row, receiver) => {
    if (!row) return;
    context.beginPath();
    row.forEach((power, index) => {
      const x = inset.left + (index / (row.length - 1)) * plotWidth;
      const normalized = Math.max(0, Math.min(1, (power - minimum) / (maximum - minimum)));
      const y = inset.top + (1 - normalized) * plotHeight;
      if (index === 0) context.moveTo(x, y);
      else context.lineTo(x, y);
    });
    context.strokeStyle = colors[receiver] || "#ffffff";
    context.lineWidth = 1.25 * ratio;
    context.stroke();
  });
}

function waterfallColor(value, minimum, maximum) {
  const level = Math.max(0, Math.min(1, (value - minimum) / Math.max(1, maximum - minimum)));
  const stops = [
    [2, 7, 20], [12, 42, 74], [11, 119, 134], [51, 218, 190], [250, 209, 82], [255, 91, 79],
  ];
  const scaled = level * (stops.length - 1);
  const index = Math.min(stops.length - 2, Math.floor(scaled));
  const fraction = scaled - index;
  return stops[index].map((start, channel) => Math.round(start + (stops[index + 1][channel] - start) * fraction));
}

function drawWaterfallRow(canvas, powers) {
  const resized = fitCanvas(canvas);
  const context = canvas.getContext("2d", { alpha: false });
  const width = canvas.width;
  const height = canvas.height;
  if (!resized) context.drawImage(canvas, 0, 0, width, height - 1, 0, 1, width, height - 1);
  const sorted = [...powers].sort((a, b) => a - b);
  const minimum = sorted[Math.floor(sorted.length * 0.04)] - 5;
  const maximum = sorted[Math.min(sorted.length - 1, Math.floor(sorted.length * 0.98))] + 3;
  const image = context.createImageData(width, 1);
  for (let x = 0; x < width; x += 1) {
    const sourceIndex = Math.min(powers.length - 1, Math.floor((x / width) * powers.length));
    const color = waterfallColor(powers[sourceIndex], minimum, maximum);
    image.data[x * 4] = color[0];
    image.data[x * 4 + 1] = color[1];
    image.data[x * 4 + 2] = color[2];
    image.data[x * 4 + 3] = 255;
  }
  context.putImageData(image, 0, 0);
}

async function loadJobs() {
  try {
    const selected = ui["radio-select"].value;
    const suffix = selected ? `?radio_id=${encodeURIComponent(selected)}` : "";
    const jobs = await apiRequest(`/jobs${suffix}`);
    const rows = jobs.slice(0, MAX_TABLE_ROWS).map((job) => {
      const row = makeElement("tr");
      const stateCell = makeElement("td", job.state, `job-${job.state}`);
      row.append(
        makeElement("td", shortId(job.job_id)),
        makeElement("td", job.persist ? "Persistent" : "Preview"),
        stateCell,
        makeElement("td", job.artifact_id ? shortId(job.artifact_id) : "—"),
      );
      return row;
    });
    if (!rows.length) {
      const row = makeElement("tr");
      const cell = makeElement("td", "No jobs yet.");
      cell.colSpan = 4;
      row.append(cell);
      rows.push(row);
    }
    ui["jobs-body"].replaceChildren(...rows);
  } catch (error) {
    toast(`Could not load jobs: ${describeError(error)}`, true);
  }
}

async function loadArtifacts() {
  try {
    state.artifacts = await apiRequest("/artifacts");
    renderArtifacts();
  } catch (error) {
    toast(`Could not load artifacts: ${describeError(error)}`, true);
  }
}

function renderArtifacts() {
  const rows = state.artifacts.slice(0, MAX_TABLE_ROWS).map((artifact) => {
    const row = makeElement("tr");
    const button = makeElement("button", "Analyze", "button table-button");
    button.type = "button";
    button.dataset.artifactId = artifact.artifact_id;
    button.addEventListener("click", () => selectArtifact(artifact.artifact_id));
    const action = makeElement("td");
    action.append(button);
    row.append(
      makeElement("td", shortId(artifact.artifact_id)),
      makeElement("td", artifact.radio_id),
      makeElement("td", formatNumber(artifact.sample_count)),
      makeElement("td", formatDate(artifact.created_at)),
      action,
    );
    return row;
  });
  if (!rows.length) {
    const row = makeElement("tr");
    const cell = makeElement("td", "No completed capture artifacts yet.");
    cell.colSpan = 5;
    row.append(cell);
    rows.push(row);
  }
  ui["artifacts-body"].replaceChildren(...rows);

  const selected = ui["analysis-artifact"].value;
  const placeholder = makeElement("option", "Select an artifact");
  placeholder.value = "";
  const options = [placeholder, ...state.artifacts.map((artifact) => {
    const option = makeElement("option", `${shortId(artifact.artifact_id)} · ${artifact.radio_id} · ${formatNumber(artifact.sample_count)} samples`);
    option.value = artifact.artifact_id;
    return option;
  })];
  ui["analysis-artifact"].replaceChildren(...options);
  if (state.artifacts.some((artifact) => artifact.artifact_id === selected)) {
    ui["analysis-artifact"].value = selected;
  }
  updateAnalysisEnabled();
}

function selectArtifact(artifactId) {
  ui["analysis-artifact"].value = artifactId;
  updateAnalysisEnabled();
  ui["analysis-form"].scrollIntoView({ behavior: "smooth", block: "center" });
}

async function loadAnalyzers() {
  try {
    const response = await apiRequest("/analyzers");
    state.analyzers = Array.isArray(response) ? response : (response.analyzers || []);
    const options = state.analyzers.map((analyzer) => {
      const option = makeElement("option", analyzer);
      option.value = analyzer;
      return option;
    });
    if (!options.length) {
      const option = makeElement("option", "No analyzers available");
      option.value = "";
      options.push(option);
    }
    ui["analyzer-select"].replaceChildren(...options);
    updateAnalysisEnabled();
  } catch (error) {
    toast(`Could not load analyzers: ${describeError(error)}`, true);
  }
}

function updateAnalysisEnabled() {
  ui["analysis-fieldset"].disabled = !state.artifacts.length || !state.analyzers.length;
}

async function runAnalysis(event) {
  event.preventDefault();
  setError(ui["analysis-validation"], "");
  ui["analysis-parameters"].setAttribute("aria-invalid", "false");
  try {
    const artifactId = ui["analysis-artifact"].value;
    const analyzer = ui["analyzer-select"].value;
    if (!artifactId || !analyzer) throw new Error("Select an artifact and analyzer.");
    let parameters;
    try {
      parameters = JSON.parse(ui["analysis-parameters"].value || "{}");
    } catch (_error) {
      throw new Error("Analysis parameters must be valid JSON.");
    }
    if (!parameters || Array.isArray(parameters) || typeof parameters !== "object") {
      throw new Error("Analysis parameters must be a JSON object.");
    }
    setText(ui["analysis-summary"], "Running…");
    const result = await apiRequest("/analyses", {
      method: "POST",
      body: JSON.stringify({ artifact_id: artifactId, analyzer, parameters }),
    });
    setText(ui["analysis-summary"], `${result.analyzer} v${result.analyzer_version} · ${formatDate(result.created_at)}`);
    setText(ui["analysis-result"], JSON.stringify(result.result, null, 2));
    toast("Analysis complete.");
  } catch (error) {
    const message = describeError(error);
    ui["analysis-parameters"].setAttribute("aria-invalid", "true");
    setError(ui["analysis-validation"], message);
    setText(ui["analysis-summary"], "Analysis failed");
  }
}

function installEventHandlers() {
  ui["refresh-radios"].addEventListener("click", loadRadios);
  ui["recover-radio"].addEventListener("click", recoverRadio);
  ui["radio-select"].addEventListener("change", async () => {
    disconnectWaterfall();
    state.streaming = false;
    state.settingsDirty = false;
    state.firmwarePlan = null;
    state.doctorRepair = false;
    state.doctorReport = null;
    clearSetupPlan("No setup plan created for this radio.");
    clearSetupUncertainty();
    ui["execute-firmware"].disabled = true;
    setText(ui["firmware-plan-output"], "No firmware plan created.");
    if (ui["radio-select"].value) {
      await loadSnapshot();
      await runDoctor();
    }
    else clearRadio();
    await loadJobs();
  });
  ui["gain-mode"].addEventListener("change", syncGainControl);
  ui["settings-form"].addEventListener("input", () => {
    state.settingsDirty = true;
  });
  ui["settings-form"].addEventListener("submit", applySettings);
  ui["reset-settings"].addEventListener("click", () => {
    if (state.snapshot) {
      populateSettingsForm(state.snapshot.requested_settings);
      state.settingsDirty = false;
    }
    setError(ui["settings-validation"], "");
  });
  ui["start-preview"].addEventListener("click", startPreview);
  ui["stop-preview"].addEventListener("click", stopPreview);
  ui["capture-form"].addEventListener("submit", startCapture);
  ui["refresh-jobs"].addEventListener("click", loadJobs);
  ui["refresh-artifacts"].addEventListener("click", loadArtifacts);
  ui["analysis-artifact"].addEventListener("change", updateAnalysisEnabled);
  ui["analysis-form"].addEventListener("submit", runAnalysis);
  ui["scan-form"].addEventListener("submit", startScan);
  ui["stop-scan"].addEventListener("click", stopScan);
  ui["inspect-firmware"].addEventListener("click", inspectFirmware);
  ui["firmware-mode"].addEventListener("change", updateFirmwareEnabled);
  ui["firmware-form"].addEventListener("submit", planFirmware);
  ui["execute-firmware"].addEventListener("click", executeFirmware);
  ui["run-doctor"].addEventListener("click", () => runDoctor(true));
  ui["prepare-doctor-fix"].addEventListener("click", prepareDoctorFix);
  ui["prepare-setup-fix"].addEventListener("click", prepareSetupFix);
  ui["execute-setup"].addEventListener("click", executeSetup);
  ui["reconcile-setup"].addEventListener("click", reconcileSetup);
  window.addEventListener("beforeunload", () => {
    state.setupPlan = null;
    ui["setup-admin-token"].value = "";
    disconnectWaterfall();
  });
}

async function initialize() {
  diagnosticLog("info", "ui.initialize_start", {
    location: window.location.origin,
    user_agent: navigator.userAgent,
    viewport: [window.innerWidth, window.innerHeight],
    device_pixel_ratio: window.devicePixelRatio,
  });
  installEventHandlers();
  clearRadio();
  await Promise.all([
    loadRadios(), loadJobs(), loadArtifacts(), loadAnalyzers(), loadFirmwareStatus(),
    loadSetupStatus(), loadScans(),
  ]);
  if (state.snapshot) await runDoctor();
  state.pollingTimer = window.setInterval(async () => {
    await Promise.all([checkHealth(), loadJobs(), loadArtifacts(), loadScans()]);
    if (ui["radio-select"].value) await loadSnapshot(ui["radio-select"].value);
  }, 5000);
  diagnosticLog("info", "ui.initialize_complete", {
    radios: state.radios.size,
    selected_radio: ui["radio-select"].value || null,
    state: state.snapshot?.state || null,
  });
}

function installRuntimeDiagnostics() {
  diagnosticLog("info", "diagnostics.ready", {
    help: "Run plutoDiagnostics() in this console for the current counters.",
    summary_interval_ms: DIAGNOSTIC_SUMMARY_INTERVAL_MS,
  });
  window.addEventListener("error", (event) => {
    diagnosticLog("error", "browser.uncaught_error", {
      message: String(event.message || "Unknown browser error").slice(0, 300),
      source: String(event.filename || "").slice(0, 200),
      line: event.lineno,
      column: event.colno,
    });
  });
  window.addEventListener("unhandledrejection", (event) => {
    const reason = event.reason instanceof Error ? event.reason.message : String(event.reason);
    diagnosticLog("error", "browser.unhandled_rejection", { reason: reason.slice(0, 300) });
  });
  window.addEventListener("online", () => diagnosticLog("info", "browser.online"));
  window.addEventListener("offline", () => diagnosticLog("warn", "browser.offline"));
  document.addEventListener("visibilitychange", () => {
    diagnosticLog("info", "browser.visibility", { state: document.visibilityState });
  });
  if (typeof PerformanceObserver === "function") {
    try {
      const observer = new PerformanceObserver((list) => {
        list.getEntries().forEach((entry) => {
          diagnosticState.browser.longTasks += 1;
          if (
            diagnosticState.browser.longTasks <= 10
            || diagnosticState.browser.longTasks % 10 === 0
          ) {
            diagnosticLog("warn", "browser.long_task", {
              duration_ms: Number(entry.duration.toFixed(1)),
              start_ms: Number(entry.startTime.toFixed(1)),
              count: diagnosticState.browser.longTasks,
            });
          }
        });
      });
      observer.observe({ type: "longtask", buffered: true });
    } catch (error) {
      diagnosticLog("debug", "browser.long_task_observer_unavailable", {
        error: error instanceof Error ? error.message : String(error),
      });
    }
  }
  let expectedTickMs = performance.now() + 1000;
  window.setInterval(() => {
    const now = performance.now();
    const driftMs = Math.max(0, now - expectedTickMs);
    expectedTickMs = now + 1000;
    if (driftMs < EVENT_LOOP_STALL_THRESHOLD_MS) return;
    diagnosticState.browser.eventLoopStalls += 1;
    diagnosticState.browser.largestStallMs = Math.max(
      diagnosticState.browser.largestStallMs,
      Math.round(driftMs),
    );
    diagnosticLog("warn", "browser.event_loop_stall", { drift_ms: Math.round(driftMs) });
  }, 1000);
}

installRuntimeDiagnostics();
initialize().catch((error) => {
  diagnosticLog("error", "ui.initialize_failed", {
    error: error instanceof Error ? error.message : String(error),
  });
  setText(ui["connection-status"], "Initialization failed · see browser console");
  ui["connection-dot"].className = "status-dot status-error";
});
