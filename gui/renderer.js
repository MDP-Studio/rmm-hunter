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
const exportJson = document.getElementById("exportJson");
const exportPdf = document.getElementById("exportPdf");
const reportPaths = document.getElementById("reportPaths");
const showJsonPath = document.getElementById("showJsonPath");

let currentReport = null;
let currentPaths = null;
const desktopBridge = window.rmmHunter || {
  startScan: async () => {
    throw new Error("Desktop scanner bridge is unavailable. Start the app with npm.cmd start.");
  },
  onProgress: () => () => {},
  exportJson: async () => null,
  exportPdf: async () => null,
  explainReport: async () => ({
    available: false,
    summary: "Desktop scanner bridge is unavailable. Start the app with npm.cmd start.",
    next_steps: ["Start the Electron app before requesting AI recommendations."],
    finding_explanations: [],
    privacy_note: "No report data was sent to an AI provider."
  }),
  showPath: async () => null
};

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

aiExplain.addEventListener("click", async () => {
  if (!currentReport) {
    return;
  }

  aiExplain.disabled = true;
  aiExplain.textContent = "Generating...";
  aiPanel.classList.remove("hidden");
  aiStatus.textContent = "Preparing sanitized report";
  aiSummary.textContent = "Sending a minimized, redacted report summary to the AI explanation layer if an API key is configured.";
  aiNextSteps.replaceChildren();
  aiFindingList.replaceChildren();
  aiPrivacyNote.textContent = "";

  try {
    const explanation = await desktopBridge.explainReport(currentReport);
    currentReport.ai_explanation = explanation;
    renderAiExplanation(explanation);
  } catch (error) {
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
});

showJsonPath.addEventListener("click", () => {
  if (currentPaths?.json) {
    desktopBridge.showPath(currentPaths.json);
  }
});

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

function renderAiExplanation(explanation) {
  aiPanel.classList.remove("hidden");
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

  const count = document.createElement("p");
  count.className = "artifact-count";
  count.textContent = `${finding.artifact_count || 1} artifact${(finding.artifact_count || 1) === 1 ? "" : "s"} in this finding. The first artifact is shown below.`;

  const artifactTable = document.createElement("div");
  artifactTable.className = "artifact-table";
  artifactTable.append(...rows);

  card.append(title, reason, count, artifactTable);
  return card;
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
