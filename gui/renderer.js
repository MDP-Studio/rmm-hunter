const scanButton = document.getElementById("scanButton");
const progressPanel = document.getElementById("progressPanel");
const progressStage = document.getElementById("progressStage");
const progressLog = document.getElementById("progressLog");
const verdictPanel = document.getElementById("verdictPanel");
const verdictText = document.getElementById("verdictText");
const riskScore = document.getElementById("riskScore");
const summaryText = document.getElementById("summaryText");
const findingCount = document.getElementById("findingCount");
const highCount = document.getElementById("highCount");
const mediumCount = document.getElementById("mediumCount");
const lowCount = document.getElementById("lowCount");
const evidenceList = document.getElementById("evidenceList");
const evidenceHint = document.getElementById("evidenceHint");
const aiExplain = document.getElementById("aiExplain");
const recommendationsPanel = document.getElementById("recommendationsPanel");
const recommendationList = document.getElementById("recommendationList");
const aiPanel = document.getElementById("aiPanel");
const aiStatus = document.getElementById("aiStatus");
const aiSummary = document.getElementById("aiSummary");
const aiNextSteps = document.getElementById("aiNextSteps");
const aiFindingList = document.getElementById("aiFindingList");
const aiPrivacyNote = document.getElementById("aiPrivacyNote");
const aiSetupNotice = document.getElementById("aiSetupNotice");
const aiSetupNoticeText = document.getElementById("aiSetupNoticeText");
const aiSetupJump = document.getElementById("aiSetupJump");
const aiSettingsToggle = document.getElementById("aiSettingsToggle");
const aiSettings = document.getElementById("aiSettings");
const aiProvider = document.getElementById("aiProvider");
const aiModel = document.getElementById("aiModel");
const aiEndpoint = document.getElementById("aiEndpoint");
const aiEndpointGroup = document.getElementById("aiEndpointGroup");
const aiApiKey = document.getElementById("aiApiKey");
const aiSaveSettings = document.getElementById("aiSaveSettings");
const aiClearKey = document.getElementById("aiClearKey");
const aiSettingsStatus = document.getElementById("aiSettingsStatus");
const exportJson = document.getElementById("exportJson");
const exportPdf = document.getElementById("exportPdf");
const reportPaths = document.getElementById("reportPaths");
const showJsonPath = document.getElementById("showJsonPath");
const checkUpdatesButton = document.getElementById("checkUpdates");
const updatePanel = document.getElementById("updatePanel");
const updateStatus = document.getElementById("updateStatus");
const updateTitle = document.getElementById("updateTitle");
const updateText = document.getElementById("updateText");
const openUpdate = document.getElementById("openUpdate");
const dismissUpdate = document.getElementById("dismissUpdate");

let currentReport = null;
let currentPaths = null;
let currentAiSettings = null;
let currentUpdate = null;
const desktopBridge = window.rmmHunter || {
  startScan: async () => {
    throw new Error("Desktop scanner bridge is unavailable. Start the app with npm.cmd start.");
  },
  onProgress: () => () => {},
  exportJson: async () => null,
  exportPdf: async () => null,
  getAiSettings: async () => ({
    providers: [],
    selected: "openai",
    providerLabel: "OpenAI",
    endpoint: "",
    model: "",
    hasApiKey: false,
    keySource: "none",
    setupRequired: true,
    setupReason: "Desktop scanner bridge is unavailable.",
    requiresApiKey: true,
    secureStorageAvailable: false
  }),
  saveAiSettings: async () => {
    throw new Error("Desktop scanner bridge is unavailable. Start the app with npm.cmd start.");
  },
  clearAiKey: async () => null,
  explainReport: async () => ({
    available: false,
    needs_setup: true,
    summary: "Desktop scanner bridge is unavailable. Start the app with npm.cmd start.",
    next_steps: ["Start the Electron app before requesting AI recommendations."],
    finding_explanations: [],
    privacy_note: "No report data was sent to an AI provider."
  }),
  showPath: async () => null,
  checkUpdates: async () => ({
    currentVersion: "0.0.0",
    latestVersion: "0.0.0",
    updateAvailable: false,
    releaseUrl: "https://github.com/MDP-Studio/rmm-hunter/releases",
    message: "Desktop scanner bridge is unavailable."
  }),
  openUpdate: async () => false
};

refreshAiSettings().catch((error) => {
  aiSettingsStatus.textContent = error?.message || "AI settings could not be loaded.";
});

checkForUpdates({ silent: true }).catch(() => {});

desktopBridge.onProgress((payload) => {
  progressPanel.classList.remove("hidden");
  progressStage.textContent = payload.stage || "Scanning";
  appendProgress(payload.detail || payload.stage || "Working");
});

scanButton.addEventListener("click", async () => {
  setScanning(true);
  resetResults();

  try {
    const result = await desktopBridge.startScan();
    currentReport = result.report;
    currentPaths = result.paths;
    renderReport(currentReport, currentPaths);
  } catch (error) {
    renderError(error);
  } finally {
    setScanning(false);
  }
});

exportJson.addEventListener("click", async () => {
  if (!currentReport) {
    return;
  }
  const exportedPath = await desktopBridge.exportJson(currentReport);
  if (exportedPath) {
    appendProgress(`JSON exported to ${exportedPath}`);
  }
});

exportPdf.addEventListener("click", async () => {
  if (!currentReport) {
    return;
  }
  const exportedPath = await desktopBridge.exportPdf(currentReport);
  if (exportedPath) {
    appendProgress(`PDF exported to ${exportedPath}`);
  }
});

aiExplain.addEventListener("click", requestAiExplanation);

checkUpdatesButton.addEventListener("click", () => {
  checkForUpdates({ silent: false });
});

openUpdate.addEventListener("click", async () => {
  if (!currentUpdate?.releaseUrl) {
    return;
  }
  openUpdate.disabled = true;
  try {
    await desktopBridge.openUpdate(currentUpdate.releaseUrl);
  } catch (error) {
    renderUpdatePanel({
      state: "error",
      title: "Could not open update page",
      text: error?.message || "Open the GitHub Releases page manually from the README."
    });
  } finally {
    openUpdate.disabled = false;
  }
});

dismissUpdate.addEventListener("click", () => {
  updatePanel.classList.add("hidden");
});

aiSetupJump.addEventListener("click", () => {
  openAiSettings({ focusApiKey: true });
});

aiSettingsToggle.addEventListener("click", async () => {
  aiPanel.classList.remove("hidden");
  aiSettings.classList.toggle("hidden");
  if (!currentAiSettings) {
    await refreshAiSettings();
  }
});

aiProvider.addEventListener("change", () => {
  applyProviderDefaults();
});

aiSaveSettings.addEventListener("click", async () => {
  aiSaveSettings.disabled = true;
  aiSettingsStatus.textContent = "Saving AI settings";
  try {
    const settings = await desktopBridge.saveAiSettings({
      provider: aiProvider.value,
      model: aiModel.value,
      endpoint: aiEndpoint.value,
      apiKey: aiApiKey.value
    });
    aiApiKey.value = "";
    renderAiSettings(settings);
    aiSettingsStatus.textContent = settings.hasApiKey
      ? "Saved. Your key stays on this Windows profile and is not written to scan reports."
      : "Provider settings saved. Add an API key before using cloud AI recommendations.";

    if (currentReport && (settings.hasApiKey || !settings.requiresApiKey)) {
      hideAiSetupNotice();
      await requestAiExplanation();
    } else if (currentReport) {
      showAiSetupNotice(settings.setupReason || "Add your own provider API key to generate AI recommendations.");
    }
  } catch (error) {
    aiSettingsStatus.textContent = error?.message || "AI settings could not be saved.";
  } finally {
    aiSaveSettings.disabled = false;
  }
});

aiClearKey.addEventListener("click", async () => {
  aiClearKey.disabled = true;
  try {
    const settings = await desktopBridge.clearAiKey();
    renderAiSettings(settings);
    aiSettings.classList.remove("hidden");
    aiSettingsStatus.textContent = "Saved API key cleared.";
  } catch (error) {
    aiSettingsStatus.textContent = error?.message || "Saved API key could not be cleared.";
  } finally {
    aiClearKey.disabled = false;
  }
});

async function requestAiExplanation() {
  if (!currentReport) {
    return;
  }

  aiExplain.disabled = true;
  aiExplain.textContent = "Checking AI setup...";
  hideAiSetupNotice();

  try {
    const settings = await refreshAiSettings();
    if (settings.setupRequired || (settings.requiresApiKey && !settings.hasApiKey)) {
      renderAiSetupNeeded(settings.setupReason || "Add your own provider API key to generate AI recommendations.");
      return;
    }

    aiExplain.textContent = "Generating...";
    aiPanel.classList.remove("hidden");
    aiStatus.textContent = "Preparing sanitized report";
    aiSummary.textContent = "Sending a minimized, redacted report summary to the AI explanation layer.";
    aiNextSteps.replaceChildren();
    aiFindingList.replaceChildren();
    aiPrivacyNote.textContent = "";

    const explanation = await desktopBridge.explainReport(currentReport);
    currentReport.ai_explanation = explanation;
    renderAiExplanation(explanation);
    if (explanation.needs_setup) {
      renderAiSetupNeeded(explanation.summary || "Add AI settings to continue.");
    } else {
      hideAiSetupNotice();
    }
  } catch (error) {
    hideAiSetupNotice();
    renderAiExplanation({
      available: false,
      summary: error?.message || "AI recommendations could not be generated.",
      next_steps: ["Use the deterministic recommendations and raw evidence cards for now."],
      finding_explanations: [],
      privacy_note: "The AI request failed before a usable explanation was returned."
    });
  } finally {
    aiExplain.disabled = false;
    aiExplain.textContent = "AI Recommendations";
  }
}

showJsonPath.addEventListener("click", () => {
  if (currentPaths?.json) {
    desktopBridge.showPath(currentPaths.json);
  }
});

async function checkForUpdates({ silent = false } = {}) {
  checkUpdatesButton.disabled = true;
  checkUpdatesButton.textContent = "Checking...";
  if (!silent) {
    renderUpdatePanel({
      state: "checking",
      title: "Checking for updates",
      text: "Looking at the official GitHub Releases page."
    });
  }

  try {
    const update = await desktopBridge.checkUpdates();
    currentUpdate = update;
    if (update.updateAvailable) {
      renderUpdatePanel({
        state: "available",
        title: `Update available: ${update.latestVersion}`,
        text: `You are running ${update.currentVersion}. Download the new release from the official GitHub Releases page.`,
        releaseUrl: update.releaseUrl
      });
    } else if (!silent) {
      renderUpdatePanel({
        state: "current",
        title: "RMM Hunter is up to date",
        text: update.message || `You are running ${update.currentVersion}.`,
        releaseUrl: update.releaseUrl
      });
    }
  } catch (error) {
    if (!silent) {
      renderUpdatePanel({
        state: "error",
        title: "Could not check for updates",
        text: error?.message || "Check the GitHub Releases page manually."
      });
    }
  } finally {
    checkUpdatesButton.disabled = false;
    checkUpdatesButton.textContent = "Check updates";
  }
}

function renderUpdatePanel({ state, title, text, releaseUrl }) {
  updatePanel.className = `update-panel ${state || "current"}`;
  updateStatus.textContent = state === "available" ? "Update available" : "Updates";
  updateTitle.textContent = title;
  updateText.textContent = text;
  if (releaseUrl) {
    currentUpdate = { ...(currentUpdate || {}), releaseUrl };
  }
  const canOpenRelease = Boolean(currentUpdate?.releaseUrl) && state !== "checking" && state !== "error";
  openUpdate.classList.toggle("hidden", !canOpenRelease);
  openUpdate.textContent = state === "available" ? "Download update" : "Open release page";
  updatePanel.classList.remove("hidden");
}

function setScanning(isScanning) {
  scanButton.disabled = isScanning;
  scanButton.textContent = isScanning ? "Scanning..." : "Scan this device";
  if (isScanning) {
    progressPanel.classList.remove("hidden");
    progressPanel.classList.remove("complete");
    progressPanel.classList.remove("failed");
    progressStage.textContent = "Preparing scanner";
    progressLog.replaceChildren();
  }
}

function resetResults() {
  currentReport = null;
  currentPaths = null;
  verdictPanel.className = "verdict-panel verdict-idle";
  verdictText.textContent = "Scanning";
  riskScore.textContent = "Risk score pending";
  summaryText.textContent = "The scanner is collecting local Windows evidence. No files are deleted or changed.";
  findingCount.textContent = "0";
  highCount.textContent = "0";
  mediumCount.textContent = "0";
  lowCount.textContent = "0";
  evidenceHint.textContent = "Scan in progress";
  evidenceList.replaceChildren();
  exportJson.disabled = true;
  exportPdf.disabled = true;
  aiExplain.disabled = true;
  recommendationsPanel.classList.add("hidden");
  recommendationList.replaceChildren();
  aiPanel.classList.add("hidden");
  aiSettings.classList.add("hidden");
  hideAiSetupNotice();
  aiStatus.textContent = "Optional";
  aiSummary.textContent = "";
  aiNextSteps.replaceChildren();
  aiFindingList.replaceChildren();
  aiPrivacyNote.textContent = "";
  reportPaths.classList.add("hidden");
}

function renderReport(report, paths) {
  const findings = Array.isArray(report.findings) ? report.findings : [];
  const severityCounts = countSeverities(findings);
  const evidenceTotal = findings.reduce((total, finding) => total + (finding.artifact_count || 1), 0);

  progressPanel.classList.remove("hidden");
  progressPanel.classList.remove("failed");
  progressPanel.classList.add("complete");
  progressStage.textContent = "Scan complete";
  appendProgress("Dashboard ready. Review grouped findings and export the full report when needed.");
  verdictPanel.className = `verdict-panel ${verdictClass(report.verdict)}`;
  verdictText.textContent = formatVerdict(report.verdict);
  riskScore.textContent = `Risk score ${report.risk_score ?? "unknown"}/100`;
  summaryText.textContent = report.summary || "Scan completed.";
  findingCount.textContent = String(findings.length);
  highCount.textContent = String(severityCounts.high);
  mediumCount.textContent = String(severityCounts.medium);
  lowCount.textContent = String(severityCounts.low);
  evidenceHint.textContent = findings.length ? `${findings.length} grouped findings, ${evidenceTotal} artifacts` : "No findings";
  renderRecommendations(report.recommendations || []);

  evidenceList.replaceChildren(...findings.map(renderFindingCard));
  if (!findings.length) {
    evidenceList.append(renderEmptyFindingCard());
  }

  exportJson.disabled = false;
  exportPdf.disabled = false;
  aiExplain.disabled = false;
  hideAiSetupNotice();

  if (paths?.json) {
    reportPaths.classList.remove("hidden");
    showJsonPath.textContent = paths.json;
  }
}

function renderRecommendations(recommendations) {
  recommendationList.replaceChildren();
  if (!Array.isArray(recommendations) || !recommendations.length) {
    recommendationsPanel.classList.add("hidden");
    return;
  }

  recommendationsPanel.classList.remove("hidden");
  recommendationList.replaceChildren(...recommendations.map((text) => {
    const item = document.createElement("li");
    item.textContent = text;
    return item;
  }));
}

async function refreshAiSettings() {
  const settings = await desktopBridge.getAiSettings();
  renderAiSettings(settings);
  return settings;
}

function renderAiSettings(settings) {
  currentAiSettings = settings || {};
  const providers = Array.isArray(currentAiSettings.providers) ? currentAiSettings.providers : [];
  const selected = currentAiSettings.selected || providers[0]?.id || "openai";

  aiProvider.replaceChildren(...providers.map((provider) => {
    const option = document.createElement("option");
    option.value = provider.id;
    option.textContent = provider.label;
    return option;
  }));

  if (providers.some((provider) => provider.id === selected)) {
    aiProvider.value = selected;
  }

  const provider = providers.find((item) => item.id === aiProvider.value) || providers[0] || {};
  aiModel.value = currentAiSettings.model || provider.defaultModel || "";
  aiEndpoint.value = currentAiSettings.endpoint || provider.endpoint || "";
  aiEndpoint.disabled = !provider.customEndpoint;
  aiEndpointGroup.classList.toggle("hidden", !provider.customEndpoint);
  aiApiKey.value = "";
  aiApiKey.placeholder = currentAiSettings.hasApiKey
    ? `Saved key from ${currentAiSettings.keySource || "settings"}`
    : `Paste ${provider.label || "provider"} API key`;
  aiClearKey.disabled = !currentAiSettings.hasApiKey || currentAiSettings.keySource !== "saved";
  aiSettingsStatus.textContent = buildAiSettingsStatusText(currentAiSettings, provider);
}

function applyProviderDefaults() {
  const providers = Array.isArray(currentAiSettings?.providers) ? currentAiSettings.providers : [];
  const provider = providers.find((item) => item.id === aiProvider.value) || {};
  aiModel.value = provider.defaultModel || "";
  aiEndpoint.value = provider.endpoint || "";
  aiEndpoint.disabled = !provider.customEndpoint;
  aiEndpointGroup.classList.toggle("hidden", !provider.customEndpoint);
  aiApiKey.value = "";
  aiApiKey.placeholder = `Paste ${provider.label || "provider"} API key`;
  aiSettingsStatus.textContent = provider.customEndpoint
    ? "Custom endpoints must be OpenAI-compatible. HTTP is allowed only for localhost."
    : `Save a ${provider.label || "provider"} key to use this provider.`;
}

function buildAiSettingsStatusText(settings, provider) {
  if (!settings.secureStorageAvailable) {
    return "Secure key storage is unavailable. Use an environment variable for the API key.";
  }
  if (settings.hasApiKey) {
    return settings.keySource === "saved"
      ? "API key saved locally with Windows profile encryption."
      : `API key loaded from ${settings.keySource}.`;
  }
  if (settings.setupReason) {
    return settings.setupReason;
  }
  return `${provider.label || "AI"} is ready for your API key.`;
}

function renderAiSetupNeeded(message) {
  const setupText = message || "Add your own provider API key to generate AI recommendations.";
  aiPanel.classList.remove("hidden");
  aiSettings.classList.remove("hidden");
  aiStatus.textContent = "Setup needed";
  aiSummary.textContent = setupText;
  aiNextSteps.replaceChildren(...[
    "Choose a provider.",
    "Paste your own API key.",
    "Save settings to generate AI recommendations."
  ].map((text) => {
    const item = document.createElement("li");
    item.textContent = text;
    return item;
  }));
  aiFindingList.replaceChildren();
  aiPrivacyNote.textContent = "No report data was sent to an AI provider.";
  showAiSetupNotice(setupText);
  openAiSettings({ focusApiKey: true });
}

function showAiSetupNotice(message) {
  aiSetupNoticeText.textContent = message || "Add your own provider API key to generate AI recommendations.";
  aiSetupNotice.classList.remove("hidden");
  aiSetupJump.focus({ preventScroll: true });
}

function hideAiSetupNotice() {
  aiSetupNotice.classList.add("hidden");
}

function openAiSettings({ focusApiKey = false } = {}) {
  aiPanel.classList.remove("hidden");
  aiSettings.classList.remove("hidden");
  requestAnimationFrame(() => {
    aiSettings.scrollIntoView({ behavior: "smooth", block: "center" });
    if (focusApiKey) {
      setTimeout(() => {
        aiApiKey.focus({ preventScroll: true });
      }, 250);
    }
  });
}

function renderAiExplanation(explanation) {
  aiPanel.classList.remove("hidden");
  if (explanation.available && !explanation.needs_setup) {
    aiSettings.classList.add("hidden");
    hideAiSetupNotice();
  }
  aiStatus.textContent = explanation.available ? `${explanation.provider || "AI"} ${explanation.model || ""}`.trim() : "Not enabled";
  aiSummary.textContent = explanation.summary || "No AI explanation was returned.";
  aiNextSteps.replaceChildren(...(Array.isArray(explanation.next_steps) ? explanation.next_steps : []).map((text) => {
    const item = document.createElement("li");
    item.textContent = text;
    return item;
  }));
  aiFindingList.replaceChildren(...(Array.isArray(explanation.finding_explanations) ? explanation.finding_explanations : []).map(renderAiFinding));
  aiPrivacyNote.textContent = explanation.privacy_note || "";
}

function renderAiFinding(finding) {
  const item = document.createElement("article");
  item.className = "ai-finding";

  const title = document.createElement("h4");
  title.textContent = `${finding.finding_id || "Finding"}: ${finding.title || "AI explanation"}`;

  const explanation = document.createElement("p");
  explanation.textContent = finding.explanation || "";

  const action = document.createElement("p");
  action.textContent = `Recommended action: ${finding.recommended_action || "Review the evidence."}`;

  const urgency = document.createElement("p");
  urgency.textContent = `Urgency: ${finding.urgency || "medium"}`;

  item.append(title, explanation, action, urgency);
  return item;
}

function renderFindingCard(finding) {
  const severity = finding.severity || "low";
  const card = document.createElement("article");
  card.className = `evidence-card ${severity}`;

  const artifact = Array.isArray(finding.artifacts) && finding.artifacts[0] ? finding.artifacts[0] : {};
  const rows = Object.entries(artifact)
    .slice(0, 10)
    .map(([key, value]) => {
      const row = document.createElement("div");
      row.className = "artifact-row";

      const keyCell = document.createElement("div");
      keyCell.className = "artifact-key";
      keyCell.textContent = key;

      const valueCell = document.createElement("div");
      valueCell.className = "artifact-value";
      valueCell.textContent = formatValue(value);

      row.append(keyCell, valueCell);
      return row;
    });

  const title = document.createElement("div");
  title.className = "evidence-title";

  const heading = document.createElement("h4");
  heading.textContent = finding.title || "Finding";

  const pill = document.createElement("span");
  pill.className = `pill ${severity}`;
  pill.textContent = severity;

  title.append(heading, pill);

  const reason = document.createElement("p");
  reason.className = "reason";
  reason.textContent = finding.reason || "";

  const guidance = getFindingGuidance(finding);
  const explanation = document.createElement("div");
  explanation.className = "finding-explanation";
  const explanationLabel = document.createElement("strong");
  explanationLabel.textContent = "What this means";
  const explanationText = document.createElement("p");
  explanationText.textContent = guidance.plainLanguage;
  explanation.append(explanationLabel, explanationText);

  const actionPanelId = `finding-actions-${finding.id || Math.random().toString(36).slice(2)}`;
  const actions = document.createElement("div");
  actions.className = "finding-actions hidden";
  actions.id = actionPanelId;
  const actionsTitle = document.createElement("strong");
  actionsTitle.textContent = "Suggested review actions";
  const actionList = document.createElement("ol");
  actionList.replaceChildren(...guidance.actions.map((text) => {
    const item = document.createElement("li");
    item.textContent = text;
    return item;
  }));
  const actionNote = document.createElement("p");
  actionNote.className = "safe-action-note";
  actionNote.textContent = "No automatic deletion or system changes are performed from this button.";
  actions.append(actionsTitle, actionList, actionNote);

  const cardActions = document.createElement("div");
  cardActions.className = "evidence-card-actions";
  const actionToggle = document.createElement("button");
  actionToggle.className = "secondary-button compact-button";
  actionToggle.type = "button";
  actionToggle.textContent = "Review actions";
  actionToggle.setAttribute("aria-expanded", "false");
  actionToggle.setAttribute("aria-controls", actionPanelId);
  actionToggle.addEventListener("click", () => {
    const expanded = actionToggle.getAttribute("aria-expanded") === "true";
    actionToggle.setAttribute("aria-expanded", String(!expanded));
    actionToggle.textContent = expanded ? "Review actions" : "Hide actions";
    actions.classList.toggle("hidden", expanded);
  });
  cardActions.append(actionToggle);

  const count = document.createElement("p");
  count.className = "artifact-count";
  count.textContent = `${finding.artifact_count || 1} artifact${(finding.artifact_count || 1) === 1 ? "" : "s"} in this finding. The first artifact is shown below.`;

  const artifactTable = document.createElement("div");
  artifactTable.className = "artifact-table";
  artifactTable.append(...rows);

  card.append(title, reason, explanation, cardActions, actions, count, artifactTable);
  return card;
}

function getFindingGuidance(finding) {
  const actions = Array.isArray(finding.recommended_actions)
    ? finding.recommended_actions.filter(Boolean)
    : [];
  return {
    plainLanguage: finding.plain_language || "This matched a local RMM Hunter rule. It is a review signal, not proof by itself. Confirm ownership, timestamp, path, and whether the activity was expected.",
    actions: actions.length
      ? actions
      : [
          "Ask the device owner or IT provider whether this activity is expected.",
          "Compare the finding timestamp with known installs, support sessions, updates, or admin work.",
          "Preserve the report before making changes so the timeline remains available."
        ]
  };
}

function renderEmptyFindingCard() {
  const card = document.createElement("div");
  card.className = "evidence-card low";

  const title = document.createElement("div");
  title.className = "evidence-title";

  const heading = document.createElement("h4");
  heading.textContent = "No evidence matched the current rules";

  const reason = document.createElement("p");
  reason.className = "reason";
  reason.textContent = "This is a clean scanner result, not a guarantee that the endpoint is safe.";

  title.append(heading);
  card.append(title, reason);
  return card;
}

function renderError(error) {
  progressPanel.classList.remove("hidden");
  progressPanel.classList.remove("complete");
  progressPanel.classList.add("failed");
  progressStage.textContent = "Scan stopped";
  appendProgress("The scanner stopped before a report was generated.");
  verdictPanel.className = "verdict-panel verdict-risk";
  verdictText.textContent = "Scan failed";
  riskScore.textContent = "No verdict generated";
  summaryText.textContent = error?.message || "The scanner failed before producing a report.";
  evidenceHint.textContent = "Error";
  exportJson.disabled = true;
  exportPdf.disabled = true;
  aiExplain.disabled = true;

  const card = document.createElement("article");
  card.className = "evidence-card high";

  const title = document.createElement("div");
  title.className = "evidence-title";

  const heading = document.createElement("h4");
  heading.textContent = "Scanner error";

  const pill = document.createElement("span");
  pill.className = "pill high";
  pill.textContent = "error";

  const reason = document.createElement("p");
  reason.className = "reason";
  reason.textContent = error?.message || "Unknown error";

  title.append(heading, pill);
  card.append(title, reason);
  evidenceList.replaceChildren(card);
}

function appendProgress(message) {
  const trimmed = String(message || "").trim();
  if (!trimmed) {
    return;
  }
  const item = document.createElement("li");
  item.textContent = trimmed.length > 220 ? `${trimmed.slice(0, 217)}...` : trimmed;
  progressLog.prepend(item);
  while (progressLog.children.length > 12) {
    progressLog.removeChild(progressLog.lastChild);
  }
}

function countSeverities(findings) {
  return findings.reduce(
    (counts, finding) => {
      if (finding.severity in counts) {
        counts[finding.severity] += 1;
      }
      return counts;
    },
    { high: 0, medium: 0, low: 0 }
  );
}

function verdictClass(verdict) {
  if (verdict === "clean") {
    return "verdict-clean";
  }
  if (verdict === "high_risk") {
    return "verdict-risk";
  }
  if (verdict === "needs_review") {
    return "verdict-review";
  }
  return "verdict-idle";
}

function formatVerdict(verdict) {
  if (!verdict) {
    return "Unknown";
  }
  return verdict.replace(/_/g, " ");
}

function formatValue(value) {
  if (value === null || value === undefined) {
    return "";
  }
  if (typeof value === "object") {
    return JSON.stringify(value);
  }
  return String(value);
}
