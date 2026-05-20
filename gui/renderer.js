const scanButton = document.getElementById("scanButton");
const progressPanel = document.getElementById("progressPanel");
const progressStage = document.getElementById("progressStage");
const progressLog = document.getElementById("progressLog");
const scanProgress = document.getElementById("scanProgress");
const scanProgressBar = document.getElementById("scanProgressBar");
const verdictPanel = document.getElementById("verdictPanel");
const verdictText = document.getElementById("verdictText");
const riskScore = document.getElementById("riskScore");
const summaryPanel = document.getElementById("summaryPanel");
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
const trustHealthPanel = document.getElementById("trustHealthPanel");
const trustHealthHint = document.getElementById("trustHealthHint");
const trustHealthList = document.getElementById("trustHealthList");
const timelinePanel = document.getElementById("timelinePanel");
const timelineHint = document.getElementById("timelineHint");
const timelineList = document.getElementById("timelineList");
const timelineMore = document.getElementById("timelineMore");
const reviewGrid = document.getElementById("reviewGrid");
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
const sourceSummary = document.getElementById("sourceSummary");
const liveSourceStatus = document.getElementById("liveSourceStatus");
const vendorLogStatus = document.getElementById("vendorLogStatus");
const kapeStatus = document.getElementById("kapeStatus");
const selectKapeRoot = document.getElementById("selectKapeRoot");
const clearKapeRoot = document.getElementById("clearKapeRoot");
const sidebarToggle = document.getElementById("sidebarToggle");
const checkUpdatesButton = document.getElementById("checkUpdates");
const updatePanel = document.getElementById("updatePanel");
const updateStatus = document.getElementById("updateStatus");
const updateTitle = document.getElementById("updateTitle");
const updateText = document.getElementById("updateText");
const updateProgress = document.getElementById("updateProgress");
const updateProgressBar = document.getElementById("updateProgressBar");
const openUpdate = document.getElementById("openUpdate");
const dismissUpdate = document.getElementById("dismissUpdate");
const desktopUpdateLog = document.getElementById("desktopUpdateLog");
const desktopUpdateLogClose = document.getElementById("desktopUpdateLogClose");
const desktopUpdateLogDismiss = document.getElementById("desktopUpdateLogDismiss");
const desktopUpdateLogRelease = document.getElementById("desktopUpdateLogRelease");
const externalLinks = {
  openIssues: "https://github.com/MDP-Studio/rmm-hunter/issues/new/choose",
  openSecurityPolicy: "https://github.com/MDP-Studio/rmm-hunter/security/policy",
  openEmail: "mailto:meidie@mdpstudio.com.au?subject=RMM%20Hunter%20feedback",
  openCoffee: "https://buymeacoffee.com/meidie",
  openRepo: "https://github.com/MDP-Studio/rmm-hunter",
  openPrivacy: "https://github.com/MDP-Studio/rmm-hunter/blob/main/PRIVACY.md",
  desktopUpdateLogRelease: "https://github.com/MDP-Studio/rmm-hunter/releases/tag/v0.2.1"
};

let currentReport = null;
let currentPaths = null;
let currentAiSettings = null;
let currentUpdate = null;
let scanProgressPercent = 0;
let desktopUpdateLogPreviousFocus = null;
let currentTimelineEntries = [];
let timelineVisibleCount = 0;
let selectedKapeRoot = "";
const timelineInitialCount = 5;
const timelineIncrement = 10;
const desktopBridge = window.rmmHunter || {
  startScan: async () => {
    throw new Error("Desktop scanner bridge is unavailable. Start the app with npm.cmd start.");
  },
  selectKapeRoot: async () => null,
  onProgress: () => () => {},
  onUpdateStatus: () => () => {},
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
  downloadUpdate: async () => {
    throw new Error("Automatic update installation is only available from the installed Windows app.");
  },
  installUpdate: async () => {
    throw new Error("No downloaded update is ready to install.");
  },
  openUpdate: async () => false,
  openExternalLink: async () => false
};

refreshAiSettings().catch((error) => {
  aiSettingsStatus.textContent = error?.message || "AI settings could not be loaded.";
});

checkForUpdates({ silent: true }).catch((error) => {
  console.info("Silent update check failed.", error?.message || error);
});

window.setTimeout(openDesktopUpdateLog, 700);

initializeSidebarState();
renderSourceStatus(null, null, { phase: "ready" });

desktopBridge.onProgress((payload) => {
  progressPanel.classList.remove("hidden");
  progressStage.textContent = payload.stage || "Scanning";
  updateScanProgress(progressForStage(payload.stage));
  appendProgress(payload.detail || payload.stage || "Working");
});

desktopBridge.onUpdateStatus((payload) => {
  if (payload?.status === "current") {
    currentUpdate = payload;
    return;
  }
  renderUpdateFromState(payload, { silentCurrent: true });
});

scanButton.addEventListener("click", async () => {
  setScanning(true);
  resetResults();

  try {
    const result = await desktopBridge.startScan({ kapeRoot: selectedKapeRoot || null });
    currentReport = result.report;
    currentPaths = result.paths;
    renderReport(currentReport, currentPaths);
  } catch (error) {
    console.error("Scan failed.", error);
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

selectKapeRoot?.addEventListener("click", async () => {
  try {
    const selection = await desktopBridge.selectKapeRoot();
    if (!selection?.path) {
      return;
    }
    selectedKapeRoot = selection.path;
    renderSourceStatus(currentReport, currentPaths, { phase: "ready" });
    appendProgress(`KAPE folder selected: ${selectedKapeRoot}`);
  } catch (error) {
    console.error("KAPE folder selection failed.", error);
    appendProgress(error?.message || "KAPE folder could not be selected.");
  }
});

clearKapeRoot?.addEventListener("click", () => {
  selectedKapeRoot = "";
  renderSourceStatus(currentReport, currentPaths, { phase: "ready" });
  appendProgress("KAPE import cleared for the next scan.");
});

for (const [buttonId, url] of Object.entries(externalLinks)) {
  const button = document.getElementById(buttonId);
  if (button) {
    button.addEventListener("click", () => {
      desktopBridge.openExternalLink(url).catch((error) => {
        appendProgress(error?.message || "Could not open external link.");
      });
    });
  }
}

document.querySelectorAll("[data-scroll-target]").forEach((button) => {
  button.addEventListener("click", () => {
    const target = document.getElementById(button.dataset.scrollTarget);
    target?.scrollIntoView({ behavior: "smooth", block: "start" });
  });
});

sidebarToggle?.addEventListener("click", () => {
  setSidebarCollapsed(!document.body.classList.contains("sidebar-collapsed"));
});

timelineMore?.addEventListener("click", () => {
  timelineVisibleCount = Math.min(currentTimelineEntries.length, timelineVisibleCount + timelineIncrement);
  renderTimelineRows();
});

checkUpdatesButton.addEventListener("click", () => {
  checkForUpdates({ silent: false });
});

openUpdate.addEventListener("click", async () => {
  if (!currentUpdate) {
    return;
  }
  openUpdate.disabled = true;
  try {
    if (currentUpdate.updateDownloaded) {
      await desktopBridge.installUpdate();
    } else if (currentUpdate.updateAvailable && currentUpdate.canAutoUpdate) {
      const state = await desktopBridge.downloadUpdate();
      renderUpdateFromState(state);
    } else if (currentUpdate.releaseUrl) {
      await desktopBridge.openUpdate(currentUpdate.releaseUrl);
    }
  } catch (error) {
    console.info("Update action failed.", error?.message || error);
    renderUpdatePanel({
      state: "error",
      title: "Update action failed",
      text: error?.message || "Open the GitHub Releases page manually from the README.",
      actionMode: "none"
    });
  } finally {
    openUpdate.disabled = false;
  }
});

dismissUpdate.addEventListener("click", () => {
  updatePanel.classList.add("hidden");
});

desktopUpdateLogClose?.addEventListener("click", closeDesktopUpdateLog);
desktopUpdateLogDismiss?.addEventListener("click", closeDesktopUpdateLog);
desktopUpdateLogRelease?.addEventListener("click", closeDesktopUpdateLog);
desktopUpdateLog?.addEventListener("click", (event) => {
  if (event.target === desktopUpdateLog) {
    closeDesktopUpdateLog();
  }
});

document.addEventListener("keydown", (event) => {
  if (event.key === "Escape" && desktopUpdateLog && !desktopUpdateLog.classList.contains("hidden")) {
    closeDesktopUpdateLog();
  }
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
    console.info("AI settings save failed.", error?.message || error);
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
    console.info("AI key clear failed.", error?.message || error);
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
    console.info("AI recommendation request failed.", error?.message || error);
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

showJsonPath?.addEventListener("click", () => {
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
      text: "Looking at the official GitHub Releases page.",
      actionMode: "none"
    });
  }

  try {
    const update = await desktopBridge.checkUpdates();
    if (update.updateAvailable || !silent) {
      renderUpdateFromState(update);
    }
  } catch (error) {
    console.info("Update check failed.", error?.message || error);
    if (!silent) {
      renderUpdatePanel({
        state: "error",
        title: "Could not check for updates",
        text: error?.message || "Check the GitHub Releases page manually.",
        actionMode: "none"
      });
    }
  } finally {
    checkUpdatesButton.disabled = false;
    checkUpdatesButton.textContent = "Check updates";
  }
}

function renderUpdateFromState(update, { silentCurrent = false } = {}) {
  currentUpdate = update || currentUpdate;
  if (!currentUpdate) {
    return;
  }
  if (silentCurrent && currentUpdate.status === "current") {
    return;
  }

  const progress = currentUpdate.downloadProgress?.percent;
  if (currentUpdate.status === "downloading") {
    renderUpdatePanel({
      state: "downloading",
      title: "Downloading update",
      text: Number.isFinite(progress)
        ? `Downloading RMM Hunter ${currentUpdate.latestVersion}: ${Math.round(progress)}%.`
        : currentUpdate.message || "Downloading the update.",
      actionMode: "none",
      progressPercent: progress
    });
    return;
  }

  if (currentUpdate.updateDownloaded || currentUpdate.status === "downloaded") {
    renderUpdatePanel({
      state: "downloaded",
      title: "Update ready to install",
      text: "Restart RMM Hunter to finish installing the downloaded update.",
      actionMode: "install"
    });
    return;
  }

  if (currentUpdate.updateAvailable) {
    renderUpdatePanel({
      state: "available",
      title: `Update available: ${currentUpdate.latestVersion}`,
      text: currentUpdate.canAutoUpdate
        ? `You are running ${currentUpdate.currentVersion}. Download and install the new release from GitHub Releases.`
        : `You are running ${currentUpdate.currentVersion}. This build cannot auto-install updates, so open GitHub Releases to download it.`,
      releaseUrl: currentUpdate.releaseUrl,
      actionMode: currentUpdate.canAutoUpdate ? "download" : "open"
    });
    return;
  }

  if (currentUpdate.status === "error") {
    renderUpdatePanel({
      state: "error",
      title: "Could not check for updates",
      text: currentUpdate.message || "Open the GitHub Releases page manually.",
      actionMode: currentUpdate.releaseUrl ? "open" : "none"
    });
    return;
  }

  renderUpdatePanel({
    state: "current",
    title: "Up to date",
    text: currentUpdate.message || `You are running ${currentUpdate.currentVersion}.`,
    releaseUrl: currentUpdate.releaseUrl,
    actionMode: "open-link"
  });
}

function renderUpdatePanel({ state, title, text, releaseUrl, actionMode = "open", progressPercent = null }) {
  updatePanel.className = `update-panel ${state || "current"}`;
  updateStatus.textContent = state === "available" ? "Update available" : state === "current" ? "Update status" : "Updates";
  updateTitle.textContent = title;
  updateText.textContent = text;
  renderUpdateProgress(progressPercent);
  if (releaseUrl) {
    currentUpdate = { ...(currentUpdate || {}), releaseUrl };
  }
  openUpdate.classList.toggle("hidden", actionMode === "none");
  openUpdate.className = actionMode === "open-link" ? "link-button" : "secondary-button";
  openUpdate.textContent = updateActionText(actionMode);
  updatePanel.classList.remove("hidden");
}

function renderUpdateProgress(progressPercent) {
  if (!Number.isFinite(progressPercent)) {
    updateProgress.classList.add("hidden");
    updateProgress.removeAttribute("aria-valuenow");
    updateProgressBar.style.width = "0%";
    return;
  }

  const clampedProgress = Math.max(0, Math.min(100, Math.round(progressPercent)));
  updateProgress.classList.remove("hidden");
  updateProgress.setAttribute("aria-valuenow", String(clampedProgress));
  updateProgressBar.style.width = `${clampedProgress}%`;
}

function progressForStage(stage) {
  const normalizedStage = String(stage || "").toLowerCase();
  if (normalizedStage.includes("preparing")) {
    return 12;
  }
  if (normalizedStage.includes("collecting")) {
    return 42;
  }
  if (normalizedStage.includes("importing kape")) {
    return 74;
  }
  if (normalizedStage.includes("scanner output")) {
    return 62;
  }
  if (normalizedStage.includes("scanner warning")) {
    return 68;
  }
  if (normalizedStage.includes("loading")) {
    return 86;
  }
  return Math.min(scanProgressPercent + 6, 92);
}

function updateScanProgress(progressPercent, { force = false } = {}) {
  const nextProgress = Number.isFinite(progressPercent) ? progressPercent : 0;
  const clampedProgress = Math.max(0, Math.min(100, Math.round(nextProgress)));
  scanProgressPercent = force ? clampedProgress : Math.max(scanProgressPercent, clampedProgress);
  scanProgress.setAttribute("aria-valuenow", String(scanProgressPercent));
  scanProgressBar.style.width = `${scanProgressPercent}%`;
}

function desktopUpdateLogStorageKey() {
  const updateId = desktopUpdateLog?.dataset.updateLogId || "";
  return updateId ? `rmm-hunter:desktop-update-log:${updateId}` : "";
}

function hasSeenDesktopUpdateLog() {
  const storageKey = desktopUpdateLogStorageKey();
  if (!storageKey) {
    return true;
  }
  try {
    return window.localStorage.getItem(storageKey) === "seen";
  } catch (error) {
    console.info("Update log storage unavailable.", error);
    appendProgress(`Update log storage unavailable: ${error?.message || error}`);
    return false;
  }
}

function rememberDesktopUpdateLog() {
  const storageKey = desktopUpdateLogStorageKey();
  if (!storageKey) {
    return;
  }
  try {
    window.localStorage.setItem(storageKey, "seen");
  } catch (error) {
    console.info("Update log preference was not saved.", error);
    appendProgress(`Update log preference was not saved: ${error?.message || error}`);
  }
}

function openDesktopUpdateLog() {
  if (!desktopUpdateLog || hasSeenDesktopUpdateLog()) {
    return;
  }
  desktopUpdateLogPreviousFocus = document.activeElement;
  desktopUpdateLog.classList.remove("hidden");
  document.body.classList.add("modal-open");
  desktopUpdateLogClose?.focus();
}

function closeDesktopUpdateLog() {
  if (!desktopUpdateLog || desktopUpdateLog.classList.contains("hidden")) {
    return;
  }
  rememberDesktopUpdateLog();
  desktopUpdateLog.classList.add("hidden");
  document.body.classList.remove("modal-open");
  if (desktopUpdateLogPreviousFocus && "focus" in desktopUpdateLogPreviousFocus) {
    desktopUpdateLogPreviousFocus.focus();
  }
}

function updateActionText(actionMode) {
  if (actionMode === "download") {
    return "Download and install";
  }
  if (actionMode === "install") {
    return "Restart and install";
  }
  if (actionMode === "open-link") {
    return "Release notes";
  }
  return "Open release page";
}

function initializeSidebarState() {
  let shouldCollapse = false;
  try {
    shouldCollapse = window.localStorage.getItem("rmm-hunter:sidebar-collapsed") === "true";
  } catch (error) {
    console.info("Sidebar preference unavailable.", error?.name || error);
  }
  setSidebarCollapsed(shouldCollapse, { remember: false });
}

function setSidebarCollapsed(shouldCollapse, { remember = true } = {}) {
  document.body.classList.toggle("sidebar-collapsed", shouldCollapse);
  if (sidebarToggle) {
    sidebarToggle.setAttribute("aria-expanded", String(!shouldCollapse));
    sidebarToggle.setAttribute("aria-label", shouldCollapse ? "Expand sidebar" : "Collapse sidebar");
    sidebarToggle.setAttribute("title", shouldCollapse ? "Expand sidebar" : "Collapse sidebar");
    sidebarToggle.textContent = shouldCollapse ? ">" : "<";
  }
  if (!remember) {
    return;
  }
  try {
    window.localStorage.setItem("rmm-hunter:sidebar-collapsed", String(shouldCollapse));
  } catch (error) {
    console.info("Sidebar preference was not saved.", error?.name || error);
  }
}

function setScanning(isScanning) {
  scanButton.disabled = isScanning;
  scanButton.textContent = isScanning ? "Scanning..." : "Scan this device";
  if (isScanning) {
    progressPanel.classList.remove("hidden");
    progressPanel.classList.remove("complete");
    progressPanel.classList.remove("failed");
    progressStage.textContent = "Preparing scanner";
    updateScanProgress(8, { force: true });
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
  trustHealthPanel.classList.add("hidden");
  trustHealthList.replaceChildren();
  timelinePanel.classList.add("hidden");
  timelineList.replaceChildren();
  timelineMore?.classList.add("hidden");
  reviewGrid?.classList.remove("timeline-visible");
  currentTimelineEntries = [];
  timelineVisibleCount = 0;
  aiPanel.classList.add("hidden");
  aiSettings.classList.add("hidden");
  hideAiSetupNotice();
  aiStatus.textContent = "Optional";
  aiSummary.textContent = "";
  aiNextSteps.replaceChildren();
  aiFindingList.replaceChildren();
  aiPrivacyNote.textContent = "";
  reportPaths?.classList.add("hidden");
  renderSourceStatus(null, null, { phase: "scanning" });
}

function renderReport(report, paths) {
  const findings = Array.isArray(report.findings) ? report.findings : [];
  const severityCounts = countSeverities(findings);
  const evidenceTotal = findings.reduce((total, finding) => total + (finding.artifact_count || 1), 0);

  progressPanel.classList.remove("hidden");
  progressPanel.classList.remove("failed");
  progressPanel.classList.add("complete");
  progressStage.textContent = "Scan complete";
  updateScanProgress(100, { force: true });
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
  renderTrustHealth(report.system_trust_health || []);
  renderTimeline(report.timeline || []);
  renderSourceStatus(report, paths, { phase: "complete" });

  evidenceList.replaceChildren(...findings.map(renderFindingCard));
  if (!findings.length) {
    evidenceList.append(renderEmptyFindingCard());
  }

  exportJson.disabled = false;
  exportPdf.disabled = false;
  aiExplain.disabled = false;
  hideAiSetupNotice();
  reportPaths?.classList.add("hidden");
  if (showJsonPath && paths?.json) {
    showJsonPath.textContent = paths.json;
  }
}

function renderSourceStatus(report, paths, { phase = "ready" } = {}) {
  const counts = sourceCounts(report);
  const kapeRoot = phase === "complete" ? paths?.kapeRoot || selectedKapeRoot : selectedKapeRoot;
  const kapeSelected = Boolean(kapeRoot);

  if (phase === "scanning") {
    setSourceText(liveSourceStatus, "Live scan running", "active");
    setSourceText(vendorLogStatus, "Vendor logs scanning", "active");
    setSourceText(kapeStatus, kapeSelected ? "KAPE queued" : "KAPE not selected", kapeSelected ? "active" : "");
    if (sourceSummary) {
      sourceSummary.textContent = kapeSelected
        ? "The desktop will collect live Windows evidence, then merge the selected KAPE output into one report."
        : "The desktop is collecting live Windows evidence and checking known RMM vendor log locations.";
    }
    clearKapeRoot?.classList.toggle("hidden", !kapeSelected);
    return;
  }

  if (phase === "complete" && report) {
    setSourceText(liveSourceStatus, `${formatCount(counts.liveTotal)} live artifacts`, "complete");
    setSourceText(vendorLogStatus, `${formatCount(counts.vendorLogs)} vendor logs`, counts.vendorLogs ? "complete" : "");
    setSourceText(
      kapeStatus,
      kapeSelected
        ? `${formatCount(counts.kapeHits)} KAPE hits`
        : "KAPE not selected",
      kapeSelected && counts.kapeHits ? "complete" : ""
    );
    if (sourceSummary) {
      sourceSummary.textContent = kapeSelected
        ? `KAPE source: ${shortPath(kapeRoot)}. Imported output was added to the same deterministic report.`
        : "This report came from live Windows collection and known RMM vendor log locations.";
    }
    clearKapeRoot?.classList.toggle("hidden", !kapeSelected);
    return;
  }

  setSourceText(liveSourceStatus, "Live scan ready", "");
  setSourceText(vendorLogStatus, "Vendor logs included", "");
  setSourceText(kapeStatus, kapeSelected ? "KAPE selected" : "KAPE optional", kapeSelected ? "active" : "");
  if (sourceSummary) {
    sourceSummary.textContent = kapeSelected
      ? `Next scan will include KAPE output from ${shortPath(kapeRoot)}. No source files are changed.`
      : "Live Windows collection, RMM vendor logs, and optional KAPE output use the same report model as the CLI.";
  }
  clearKapeRoot?.classList.toggle("hidden", !kapeSelected);
}

function setSourceText(element, text, state) {
  if (!element) {
    return;
  }
  element.textContent = text;
  element.classList.toggle("active", state === "active");
  element.classList.toggle("complete", state === "complete");
}

function sourceCounts(report) {
  const artifactCounts = report?.artifact_counts && typeof report.artifact_counts === "object"
    ? report.artifact_counts
    : {};
  let liveTotal = 0;
  for (const [key, value] of Object.entries(artifactCounts)) {
    if (!key.startsWith("kape_")) {
      liveTotal += numericCount(value);
    }
  }
  return {
    liveTotal,
    vendorLogs: numericCount(artifactCounts.rmm_vendor_logs),
    kapeHits: numericCount(artifactCounts.kape_rmm_artifacts)
  };
}

function numericCount(value) {
  const count = Number(value);
  return Number.isFinite(count) ? count : 0;
}

function formatCount(value) {
  return Number(value || 0).toLocaleString();
}

function shortPath(value) {
  const text = String(value || "");
  if (text.length <= 58) {
    return text;
  }
  return `...${text.slice(-55)}`;
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

function renderTimeline(entries) {
  timelineList.replaceChildren();
  currentTimelineEntries = Array.isArray(entries) ? entries : [];
  timelineVisibleCount = Math.min(timelineInitialCount, currentTimelineEntries.length);
  if (!currentTimelineEntries.length) {
    timelinePanel.classList.add("hidden");
    timelineMore?.classList.add("hidden");
    reviewGrid?.classList.remove("timeline-visible");
    return;
  }

  timelinePanel.classList.remove("hidden");
  reviewGrid?.classList.add("timeline-visible");
  renderTimelineRows();
}

function renderTimelineRows() {
  const visibleEntries = currentTimelineEntries.slice(0, timelineVisibleCount);
  timelineHint.textContent = currentTimelineEntries.length > visibleEntries.length
    ? `Showing ${visibleEntries.length} of ${currentTimelineEntries.length} timestamped artifacts`
    : `${currentTimelineEntries.length} timestamped artifact${currentTimelineEntries.length === 1 ? "" : "s"}`;
  timelineList.replaceChildren(...visibleEntries.map(renderTimelineEntry));
  if (timelineMore) {
    const remaining = currentTimelineEntries.length - visibleEntries.length;
    timelineMore.classList.toggle("hidden", remaining <= 0);
    timelineMore.textContent = remaining > timelineIncrement
      ? `Show ${timelineIncrement} more`
      : remaining > 0
        ? `Show ${remaining} more`
        : "Show more";
  }
}

function renderTimelineEntry(entry) {
  const item = document.createElement("li");
  item.className = `timeline-item ${entry.severity || "low"}`;

  const stamp = document.createElement("span");
  stamp.className = "timeline-time";
  stamp.textContent = formatTimelineTime(entry.time_utc, entry.timestamp_type);

  const body = document.createElement("div");
  body.className = "timeline-body";

  const title = document.createElement("strong");
  title.textContent = `${entry.title || "Finding"}${entry.tool ? ` (${entry.tool})` : ""}`;

  const detail = document.createElement("p");
  detail.textContent = entry.artifact_summary || entry.category || "Evidence artifact";

  body.append(title, detail);
  item.append(stamp, body);
  return item;
}

function formatTimelineTime(value, type) {
  const suffix = type ? `, ${type}` : "";
  if (!value) {
    return `unknown${suffix}`;
  }
  const parsed = new Date(value);
  if (Number.isNaN(parsed.getTime())) {
    return `${value}${suffix}`;
  }
  return `${parsed.toLocaleString(undefined, { hour12: false })}${suffix}`;
}

function renderTrustHealth(checks) {
  trustHealthList.replaceChildren();
  if (!Array.isArray(checks) || !checks.length) {
    trustHealthPanel.classList.add("hidden");
    return;
  }

  trustHealthPanel.classList.remove("hidden");
  const needsAttention = checks.filter((check) => ["needs_review", "high_risk"].includes(check?.status)).length;
  const unknown = checks.filter((check) => check?.status === "unknown").length;
  trustHealthHint.textContent = needsAttention
    ? `${needsAttention} check${needsAttention === 1 ? "" : "s"} need review`
    : unknown
      ? `${unknown} check${unknown === 1 ? "" : "s"} could not be confirmed`
      : "All collected trust checks look healthy";
  trustHealthList.replaceChildren(...checks.map(renderTrustHealthCheck));
}

function renderTrustHealthCheck(check) {
  const status = check?.status || "unknown";
  const card = document.createElement("article");
  card.className = `trust-health-card ${status}`;

  const header = document.createElement("div");
  header.className = "trust-health-header";

  const title = document.createElement("h4");
  title.textContent = check?.title || "Trust health check";

  const pill = document.createElement("span");
  pill.className = `pill ${status === "high_risk" ? "high" : status === "needs_review" ? "medium" : status === "ok" ? "clean" : "low"}`;
  pill.textContent = formatTrustStatus(status);

  header.append(title, pill);

  const detail = document.createElement("p");
  detail.textContent = check?.detail || "";

  const action = document.createElement("p");
  action.className = "trust-health-action";
  action.textContent = check?.recommended_action || "Review this check before making remediation decisions.";

  card.append(header, detail, action);
  return card;
}

function formatTrustStatus(status) {
  if (status === "high_risk") {
    return "high risk";
  }
  if (status === "needs_review") {
    return "needs review";
  }
  return status || "unknown";
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
  aiPanel.classList.add("hidden");
  aiSettings.classList.add("hidden");
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
  summaryPanel.scrollIntoView({ behavior: "smooth", block: "center" });
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
    .slice(0, 14)
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

  const confidence = document.createElement("p");
  confidence.className = "finding-meta";
  confidence.textContent = `Evidence ${formatEvidenceStrength(finding.evidence_strength)}. Confidence ${formatVerdict(finding.confidence_label || "unknown")}${Number.isFinite(finding.confidence) ? ` (${Math.round(finding.confidence * 100)}%)` : ""}.`;

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

  card.append(title, reason, confidence, explanation, cardActions, actions, count, artifactTable);
  return card;
}

function formatEvidenceStrength(value) {
  if (!value) {
    return "not labelled";
  }
  return String(value).replace(/_/g, " ");
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
  updateScanProgress(100, { force: true });
  appendProgress("The scanner stopped before a report was generated.");
  verdictPanel.className = "verdict-panel verdict-risk";
  verdictText.textContent = "Scan failed";
  riskScore.textContent = "No verdict generated";
  summaryText.textContent = error?.message || "The scanner failed before producing a report.";
  evidenceHint.textContent = "Error";
  exportJson.disabled = true;
  exportPdf.disabled = true;
  aiExplain.disabled = true;
  timelinePanel.classList.add("hidden");
  timelineList.replaceChildren();
  timelineMore?.classList.add("hidden");
  reviewGrid?.classList.remove("timeline-visible");
  renderSourceStatus(null, null, { phase: "ready" });

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
