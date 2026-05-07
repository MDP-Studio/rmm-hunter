const { app, BrowserWindow, dialog, ipcMain, shell } = require("electron");
const childProcess = require("node:child_process");
const fs = require("node:fs");
const https = require("node:https");
const os = require("node:os");
const path = require("node:path");
const { pathToFileURL } = require("node:url");

const ROOT_DIR = path.resolve(__dirname, "..");
const APP_FILE = path.join(__dirname, "index.html");
const DEFAULT_OPENAI_MODEL = "gpt-5-mini";
const MAX_AI_REPORT_BYTES = 120000;
const PROFILE_ROOT = path.join(
  process.env.LOCALAPPDATA || path.join(os.homedir(), "AppData", "Local"),
  "RMM Hunter"
);
const ELECTRON_USER_DATA_DIR = path.join(PROFILE_ROOT, "profile");
const ELECTRON_CACHE_DIR = path.join(PROFILE_ROOT, "cache");
const DEV_REPORTS_DIR = path.join(ROOT_DIR, "reports");
const PACKAGED_REPORTS_DIR = path.join(PROFILE_ROOT, "reports");
const REPORTS_DIR = app.isPackaged ? PACKAGED_REPORTS_DIR : DEV_REPORTS_DIR;

let mainWindow;

configureElectronStorage();

function createWindow() {
  mainWindow = new BrowserWindow({
    width: 1180,
    height: 780,
    minWidth: 980,
    minHeight: 680,
    backgroundColor: "#f6f7f9",
    title: "RMM Hunter",
    webPreferences: {
      preload: path.join(__dirname, "preload.js"),
      contextIsolation: true,
      nodeIntegration: false,
      sandbox: true
    }
  });

  const allowedUrl = pathToFileURL(APP_FILE).href;
  mainWindow.webContents.setWindowOpenHandler(() => ({ action: "deny" }));
  mainWindow.webContents.on("will-navigate", (event, nextUrl) => {
    if (nextUrl !== allowedUrl) {
      event.preventDefault();
    }
  });

  mainWindow.loadFile(APP_FILE);
}

const hasSingleInstanceLock = app.requestSingleInstanceLock();

if (!hasSingleInstanceLock) {
  app.quit();
} else {
  app.whenReady().then(createWindow);

  app.on("second-instance", () => {
    if (!mainWindow) {
      return;
    }
    if (mainWindow.isMinimized()) {
      mainWindow.restore();
    }
    mainWindow.focus();
  });

  app.on("window-all-closed", () => {
    if (process.platform !== "darwin") {
      app.quit();
    }
  });

  app.on("activate", () => {
    if (BrowserWindow.getAllWindows().length === 0) {
      createWindow();
    }
  });
}

function configureElectronStorage() {
  try {
    fs.mkdirSync(ELECTRON_USER_DATA_DIR, { recursive: true });
    fs.mkdirSync(ELECTRON_CACHE_DIR, { recursive: true });
    app.setPath("userData", ELECTRON_USER_DATA_DIR);
    app.commandLine.appendSwitch("disk-cache-dir", ELECTRON_CACHE_DIR);
  } catch (error) {
    console.error(`Could not prepare Electron profile directory. ${error.message}`);
  }

  app.commandLine.appendSwitch("disable-gpu-shader-disk-cache");
}

ipcMain.handle("scan:start", async () => {
  fs.mkdirSync(REPORTS_DIR, { recursive: true });
  const stamp = new Date().toISOString().replace(/[-:]/g, "").replace(/\.\d{3}Z$/, "Z");
  const artifactsPath = path.join(REPORTS_DIR, `rmm_hunter_artifacts_${stamp}.json`);
  const reportPath = path.join(REPORTS_DIR, `rmm_hunter_report_${stamp}.json`);
  const summaryPath = path.join(REPORTS_DIR, `rmm_hunter_summary_${stamp}.txt`);

  sendProgress("Preparing scanner", "Creating report paths and starting the local collector.");

  const args = [
    "--artifacts-out",
    artifactsPath,
    "--json-out",
    reportPath,
    "--summary-out",
    summaryPath
  ];

  await runScanner(args);

  sendProgress("Loading results", "Parsing the JSON report and preparing the dashboard.");

  const report = JSON.parse(fs.readFileSync(reportPath, "utf8"));
  return {
    report,
    paths: {
      artifacts: artifactsPath,
      json: reportPath,
      summary: summaryPath
    }
  };
});

ipcMain.handle("report:exportJson", async (_event, report) => {
  const { canceled, filePath } = await dialog.showSaveDialog(mainWindow, {
    title: "Export JSON report",
    defaultPath: `rmm_hunter_report_${safeTimestamp()}.json`,
    filters: [{ name: "JSON report", extensions: ["json"] }]
  });

  if (canceled || !filePath) {
    return null;
  }

  fs.writeFileSync(filePath, JSON.stringify(report, null, 2) + "\n", "utf8");
  return filePath;
});

ipcMain.handle("report:exportPdf", async (_event, report) => {
  const { canceled, filePath } = await dialog.showSaveDialog(mainWindow, {
    title: "Export PDF report",
    defaultPath: `rmm_hunter_report_${safeTimestamp()}.pdf`,
    filters: [{ name: "PDF report", extensions: ["pdf"] }]
  });

  if (canceled || !filePath) {
    return null;
  }

  const pdfWindow = new BrowserWindow({
    show: false,
    webPreferences: {
      contextIsolation: true,
      nodeIntegration: false,
      sandbox: true
    }
  });

  const html = buildPdfHtml(report);
  await pdfWindow.loadURL(`data:text/html;charset=utf-8,${encodeURIComponent(html)}`);
  const pdfData = await pdfWindow.webContents.printToPDF({
    printBackground: true,
    pageSize: "A4",
    margins: { marginType: "default" }
  });
  fs.writeFileSync(filePath, pdfData);
  pdfWindow.destroy();
  return filePath;
});

ipcMain.handle("ai:explainReport", async (_event, report) => {
  const apiKey = process.env.OPENAI_API_KEY;
  const model = safeModelName(process.env.RMM_HUNTER_AI_MODEL || DEFAULT_OPENAI_MODEL);
  if (!apiKey) {
    return {
      available: false,
      provider: "openai",
      model,
      summary: "AI recommendations are disabled because OPENAI_API_KEY is not set.",
      next_steps: [
        "Set OPENAI_API_KEY before starting the app if you want cloud AI explanations.",
        "Use the deterministic recommendations in the report until AI is enabled.",
        "Do not paste raw reports into public AI tools without reviewing sensitive paths, usernames, and event excerpts."
      ],
      finding_explanations: [],
      privacy_note: "No report data was sent to an AI provider."
    };
  }

  const sanitizedReport = sanitizeReportForAi(report);
  return callOpenAiExplanation({ apiKey, model, report: sanitizedReport });
});

ipcMain.handle("path:show", async (_event, targetPath) => {
  if (!isSafeReportPath(targetPath)) {
    return;
  }
  shell.showItemInFolder(targetPath);
});

function runScanner(args) {
  return new Promise((resolve, reject) => {
    const scanner = resolveScannerProcess(args);
    sendProgress("Collecting Windows evidence", "Checking installed apps, services, tasks, startup items, and event logs.");

    const child = childProcess.spawn(scanner.command, scanner.args, {
      cwd: scanner.cwd,
      windowsHide: true
    });

    let stdout = "";
    let stderr = "";

    child.stdout.on("data", (data) => {
      stdout += data.toString();
      for (const line of splitLines(data.toString())) {
        sendProgress("Scanner output", line);
      }
    });

    child.stderr.on("data", (data) => {
      stderr += data.toString();
      for (const line of splitLines(data.toString())) {
        sendProgress("Scanner warning", line);
      }
    });

    child.on("error", (error) => {
      reject(new Error(`Could not start scanner. ${error.message}`));
    });

    child.on("close", (code) => {
      if (code === 0) {
        resolve(stdout);
        return;
      }
      reject(new Error(`Scanner failed with exit code ${code}.\n${stderr || stdout}`));
    });
  });
}

function resolveScannerProcess(args) {
  if (!app.isPackaged && process.env.RMM_HUNTER_SCANNER) {
    return {
      command: process.env.RMM_HUNTER_SCANNER,
      args,
      cwd: ROOT_DIR
    };
  }

  const bundledScanner = path.join(process.resourcesPath || ROOT_DIR, "bin", "rmm-hunter-cli.exe");
  if (app.isPackaged && fs.existsSync(bundledScanner)) {
    return {
      command: bundledScanner,
      args,
      cwd: path.dirname(bundledScanner)
    };
  }

  return {
    command: !app.isPackaged && process.env.RMM_HUNTER_PYTHON ? process.env.RMM_HUNTER_PYTHON : "python",
    args: [path.join(ROOT_DIR, "rmm_hunter.py"), ...args],
    cwd: ROOT_DIR
  };
}

function sendProgress(stage, detail) {
  if (mainWindow && !mainWindow.isDestroyed()) {
    mainWindow.webContents.send("scan:progress", { stage, detail, time: new Date().toISOString() });
  }
}

function splitLines(text) {
  return text
    .split(/\r?\n/)
    .map((line) => line.trim())
    .filter(Boolean);
}

function safeTimestamp() {
  return new Date().toISOString().replace(/[-:]/g, "").replace(/\.\d{3}Z$/, "Z");
}

function safeModelName(value) {
  const text = String(value || "").trim();
  return /^[A-Za-z0-9._:-]{1,80}$/.test(text) ? text : DEFAULT_OPENAI_MODEL;
}

function buildPdfHtml(report) {
  const findings = Array.isArray(report.findings) ? report.findings : [];
  const counts = report.artifact_counts || {};
  const metadata = report.collection_metadata || {};
  const recommendations = Array.isArray(report.recommendations) ? report.recommendations : [];
  const aiExplanation = report.ai_explanation || null;
  const rows = findings
    .map((finding) => {
      const artifact = Array.isArray(finding.artifacts) && finding.artifacts[0] ? finding.artifacts[0] : {};
      const artifactBits = Object.entries(artifact)
        .filter(([key]) => !["message_excerpt", "event_data"].includes(key))
        .slice(0, 8)
        .map(([key, value]) => `<div><strong>${escapeHtml(key)}:</strong> ${escapeHtml(formatPdfValue(value))}</div>`)
        .join("");
      return `
        <section class="finding ${escapeHtml(finding.severity || "low")}">
          <h3>${escapeHtml(finding.title || "Finding")}</h3>
          <p><strong>Severity:</strong> ${escapeHtml(finding.severity || "unknown")}</p>
          <p><strong>Artifacts in finding:</strong> ${escapeHtml(String(finding.artifact_count || 1))}</p>
          <p>${escapeHtml(finding.reason || "")}</p>
          <div class="artifact">${artifactBits}</div>
        </section>
      `;
    })
    .join("");

  const countRows = Object.entries(counts)
    .sort(([a], [b]) => a.localeCompare(b))
    .map(([key, value]) => `<tr><td>${escapeHtml(key)}</td><td>${escapeHtml(String(value))}</td></tr>`)
    .join("");
  const recommendationRows = recommendations.map((item) => `<li>${escapeHtml(item)}</li>`).join("");
  const aiRows = aiExplanation
    ? `
        <h2>AI Explanation</h2>
        <p>${escapeHtml(aiExplanation.summary || "")}</p>
        <ul>${(aiExplanation.next_steps || []).map((item) => `<li>${escapeHtml(item)}</li>`).join("")}</ul>
        <p class="note">${escapeHtml(aiExplanation.privacy_note || "")}</p>
      `
    : "";

  return `
    <!doctype html>
    <html>
      <head>
        <meta charset="utf-8">
        <meta http-equiv="Content-Security-Policy" content="default-src 'none'; style-src 'unsafe-inline'; img-src data:;">
        <style>
          body { color: #17191f; font-family: Arial, sans-serif; margin: 36px; }
          h1 { font-size: 30px; margin: 0 0 8px; }
          h2 { border-bottom: 1px solid #d8dde6; font-size: 18px; margin-top: 28px; padding-bottom: 8px; }
          h3 { font-size: 15px; margin: 0 0 8px; }
          p { line-height: 1.45; margin: 6px 0; }
          .verdict { border: 1px solid #ccd3df; border-radius: 8px; margin: 22px 0; padding: 16px; }
          .verdict strong { text-transform: uppercase; }
          table { border-collapse: collapse; width: 100%; }
          td { border-bottom: 1px solid #edf0f4; padding: 7px 4px; }
          .finding { border: 1px solid #d8dde6; border-left-width: 6px; border-radius: 8px; margin: 12px 0; padding: 14px; page-break-inside: avoid; }
          .finding.high { border-left-color: #c53232; }
          .finding.medium { border-left-color: #b97800; }
          .finding.low { border-left-color: #4b6fa8; }
          .artifact { background: #f7f8fa; border-radius: 6px; font-family: Consolas, monospace; font-size: 10px; margin-top: 10px; padding: 10px; }
          .note { color: #5c6678; font-size: 12px; }
        </style>
      </head>
      <body>
        <h1>RMM Hunter Report</h1>
        <p>Generated at ${escapeHtml(report.scanner?.generated_at_utc || new Date().toISOString())}</p>
        <div class="verdict">
          <p><strong>${escapeHtml(report.verdict || "unknown")}</strong></p>
          <p>Risk score: ${escapeHtml(String(report.risk_score ?? "unknown"))}/100</p>
          <p>Host: ${escapeHtml(metadata.hostname || "unknown")}</p>
          <p>${escapeHtml(report.summary || "")}</p>
        </div>
        <h2>Recommended Next Steps</h2>
        <ul>${recommendationRows || "<li>No recommendations available.</li>"}</ul>
        ${aiRows}
        <h2>Artifact Counts</h2>
        <table>${countRows}</table>
        <h2>Findings</h2>
        ${rows || "<p>No findings.</p>"}
      </body>
    </html>
  `;
}

function formatPdfValue(value) {
  if (value === null || value === undefined) {
    return "";
  }
  if (typeof value === "object") {
    return JSON.stringify(value);
  }
  return String(value);
}

function escapeHtml(value) {
  return String(value)
    .replace(/&/g, "&amp;")
    .replace(/</g, "&lt;")
    .replace(/>/g, "&gt;")
    .replace(/"/g, "&quot;")
    .replace(/'/g, "&#039;");
}

function isSafeReportPath(targetPath) {
  if (!targetPath || typeof targetPath !== "string") {
    return false;
  }

  const resolved = path.resolve(targetPath);
  const reportsRoot = path.resolve(REPORTS_DIR);
  return resolved === reportsRoot || resolved.startsWith(reportsRoot + path.sep);
}

function sanitizeReportForAi(report) {
  const findings = Array.isArray(report?.findings) ? report.findings : [];
  return {
    verdict: sanitizeScalar(report?.verdict),
    risk_score: Number.isFinite(report?.risk_score) ? report.risk_score : null,
    summary: sanitizeScalar(report?.summary),
    recommendations: sanitizeArray(report?.recommendations).slice(0, 8),
    artifact_counts: sanitizeRecord(report?.artifact_counts || {}),
    collection: {
      lookback_days: report?.collection?.lookback_days ?? null,
      start_time_utc: sanitizeScalar(report?.collection?.start_time_utc)
    },
    findings: findings.slice(0, 20).map((finding) => ({
      id: sanitizeScalar(finding.id),
      severity: sanitizeScalar(finding.severity),
      category: sanitizeScalar(finding.category),
      title: sanitizeScalar(finding.title),
      tool: sanitizeScalar(finding.tool),
      confidence: Number.isFinite(finding.confidence) ? finding.confidence : null,
      reason: sanitizeScalar(finding.reason),
      artifact_count: Number.isFinite(finding.artifact_count) ? finding.artifact_count : 1,
      artifacts: sanitizeArtifacts(finding.artifacts).slice(0, 3)
    }))
  };
}

function sanitizeArtifacts(artifacts) {
  if (!Array.isArray(artifacts)) {
    return [];
  }

  return artifacts.map((artifact) => {
    const cleaned = {};
    const allowedKeys = [
      "source",
      "display_name",
      "name",
      "task_name",
      "task_path",
      "value_name",
      "state",
      "start_mode",
      "start_name",
      "id",
      "log_name",
      "provider",
      "publisher",
      "signature"
    ];

    for (const key of allowedKeys) {
      if (artifact && artifact[key] !== undefined) {
        cleaned[key] = sanitizeValue(artifact[key]);
      }
    }

    for (const key of ["path", "directory", "path_name", "executable_path", "install_location", "uninstall_string", "registry_path"]) {
      if (artifact && artifact[key]) {
        cleaned[`${key}_summary`] = summarizePath(artifact[key]);
      }
    }

    if (artifact?.message_excerpt) {
      cleaned.message_summary = sanitizeScalar(artifact.message_excerpt).slice(0, 220);
    }

    return cleaned;
  });
}

function sanitizeRecord(record) {
  const cleaned = {};
  for (const [key, value] of Object.entries(record || {})) {
    cleaned[sanitizeScalar(key)] = sanitizeValue(value);
  }
  return cleaned;
}

function sanitizeArray(value) {
  if (!Array.isArray(value)) {
    return [];
  }
  return value.map((item) => sanitizeScalar(item));
}

function sanitizeValue(value) {
  if (value === null || value === undefined) {
    return null;
  }
  if (Array.isArray(value)) {
    return value.slice(0, 10).map((item) => sanitizeValue(item));
  }
  if (typeof value === "object") {
    return sanitizeRecord(value);
  }
  if (typeof value === "number" || typeof value === "boolean") {
    return value;
  }
  return sanitizeScalar(value);
}

function sanitizeScalar(value) {
  return redactSensitive(String(value ?? "")).slice(0, 1000);
}

function redactSensitive(value) {
  return value
    .replace(/[A-Z]:\\Users\\[^\\\s]+/gi, "C:\\Users\\<user>")
    .replace(/[A-Z]:\/Users\/[^\/\s]+/gi, "C:/Users/<user>")
    .replace(/[A-Z0-9._%+-]+@[A-Z0-9.-]+\.[A-Z]{2,}/gi, "<email>")
    .replace(/sk-[A-Za-z0-9_-]{12,}/g, "<api-key>")
    .replace(/Bearer\s+[A-Za-z0-9._-]{12,}/gi, "Bearer <token>")
    .replace(/(?<=password[=:]\s*)\S+/gi, "<redacted>")
    .replace(/(?<=token[=:]\s*)\S+/gi, "<redacted>")
    .replace(/[A-Fa-f0-9]{48,}/g, "<hex-string>")
    .replace(/[A-Za-z0-9+/]{80,}={0,2}/g, "<encoded-string>");
}

function summarizePath(value) {
  const text = sanitizeScalar(value).replace(/\//g, "\\");
  const lowered = text.toLowerCase();
  const parts = text.split("\\").filter(Boolean);
  const basename = parts[parts.length - 1] || "";
  return {
    basename,
    under_downloads: lowered.includes("\\downloads\\"),
    under_temp: lowered.includes("\\temp\\") || lowered.includes("\\appdata\\local\\temp\\"),
    under_program_files: lowered.startsWith("c:\\program files"),
    under_windows: lowered.startsWith("c:\\windows")
  };
}

function callOpenAiExplanation({ apiKey, model, report }) {
  const reportPayload = JSON.stringify({ report });
  if (Buffer.byteLength(reportPayload, "utf8") > MAX_AI_REPORT_BYTES) {
    return Promise.reject(new Error("Sanitized report is too large for AI explanation."));
  }

  const schema = {
    type: "object",
    additionalProperties: false,
    properties: {
      available: { type: "boolean" },
      provider: { type: "string" },
      model: { type: "string" },
      summary: { type: "string" },
      next_steps: {
        type: "array",
        minItems: 3,
        maxItems: 8,
        items: { type: "string" }
      },
      finding_explanations: {
        type: "array",
        maxItems: 8,
        items: {
          type: "object",
          additionalProperties: false,
          properties: {
            finding_id: { type: "string" },
            title: { type: "string" },
            explanation: { type: "string" },
            recommended_action: { type: "string" },
            urgency: { type: "string", enum: ["low", "medium", "high"] }
          },
          required: ["finding_id", "title", "explanation", "recommended_action", "urgency"]
        }
      },
      privacy_note: { type: "string" }
    },
    required: ["available", "provider", "model", "summary", "next_steps", "finding_explanations", "privacy_note"]
  };

  const body = {
    model,
    input: [
      {
        role: "developer",
        content: [
          {
            type: "input_text",
            text: [
              "You explain RMM Hunter scan results to a Windows user.",
              "Never change or override the deterministic verdict.",
              "Do not tell the user to delete artifacts automatically.",
              "Base the answer only on the sanitized JSON report.",
              "Use concise plain English and practical incident-triage steps.",
              "If evidence is ambiguous, say it needs owner or IT-provider confirmation."
            ].join(" ")
          }
        ]
      },
      {
        role: "user",
        content: [
          {
            type: "input_text",
            text: reportPayload
          }
        ]
      }
    ],
    text: {
      format: {
        type: "json_schema",
        name: "rmm_hunter_ai_explanation",
        strict: true,
        schema
      }
    }
  };

  return new Promise((resolve, reject) => {
    const request = https.request(
      {
        hostname: "api.openai.com",
        path: "/v1/responses",
        method: "POST",
        headers: {
          Authorization: `Bearer ${apiKey}`,
          "Content-Type": "application/json"
        },
        timeout: 45000
      },
      (response) => {
        let data = "";
        response.on("data", (chunk) => {
          data += chunk;
        });
        response.on("end", () => {
          if (response.statusCode < 200 || response.statusCode >= 300) {
            reject(new Error(`AI explanation failed with HTTP ${response.statusCode}.`));
            return;
          }

          try {
            const parsed = JSON.parse(data);
            const outputText = parsed.output_text || extractResponseText(parsed);
            const explanation = JSON.parse(outputText);
            explanation.available = true;
            explanation.provider = "openai";
            explanation.model = model;
            resolve(explanation);
          } catch (error) {
            reject(new Error(`AI explanation response could not be parsed. ${error.message}`));
          }
        });
      }
    );

    request.on("timeout", () => {
      request.destroy(new Error("AI explanation request timed out."));
    });
    request.on("error", reject);
    request.write(JSON.stringify(body));
    request.end();
  });
}

function extractResponseText(response) {
  const chunks = [];
  for (const item of response.output || []) {
    for (const content of item.content || []) {
      if (content.type === "output_text" && content.text) {
        chunks.push(content.text);
      }
    }
  }
  return chunks.join("");
}
