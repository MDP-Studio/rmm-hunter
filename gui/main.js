const { app, BrowserWindow, dialog, ipcMain, safeStorage, shell } = require("electron");
const { autoUpdater } = require("electron-updater");
const childProcess = require("node:child_process");
const fs = require("node:fs");
const http = require("node:http");
const https = require("node:https");
const os = require("node:os");
const path = require("node:path");
const { pathToFileURL } = require("node:url");

const ROOT_DIR = path.resolve(__dirname, "..");
const APP_FILE = path.join(__dirname, "index.html");
const APP_ICON = path.join(__dirname, "assets", "icon.ico");
const REPOSITORY_URL = "https://github.com/MDP-Studio/rmm-hunter";
const RELEASES_URL = "https://github.com/MDP-Studio/rmm-hunter/releases";
const RELEASES_API_URL = "https://api.github.com/repos/MDP-Studio/rmm-hunter/releases?per_page=10";
const FEEDBACK_ISSUES_URL = "https://github.com/MDP-Studio/rmm-hunter/issues/new/choose";
const SECURITY_POLICY_URL = "https://github.com/MDP-Studio/rmm-hunter/security/policy";
const PRIVACY_POLICY_URL = "https://github.com/MDP-Studio/rmm-hunter/blob/main/PRIVACY.md";
const BUY_ME_A_COFFEE_URL = "https://buymeacoffee.com/meidie";
const FEEDBACK_EMAIL_URL = "mailto:meidie@mdpstudio.com.au?subject=RMM%20Hunter%20feedback";
const APP_TITLE = "RMM Hunter";
const APP_VERSION = app.getVersion();
const APP_USER_AGENT = `RMM-Hunter/${APP_VERSION}`;
const DEFAULT_AI_PROVIDER = "openai";
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
const AI_SETTINGS_PATH = path.join(PROFILE_ROOT, "ai-settings.json");
const AI_PROVIDERS = Object.freeze({
  openai: {
    id: "openai",
    label: "OpenAI",
    requestType: "responses",
    endpoint: "https://api.openai.com/v1/responses",
    defaultModel: DEFAULT_OPENAI_MODEL,
    keyEnv: "OPENAI_API_KEY",
    requiresApiKey: true,
    customEndpoint: false
  },
  openrouter: {
    id: "openrouter",
    label: "OpenRouter",
    requestType: "chat",
    endpoint: "https://openrouter.ai/api/v1/chat/completions",
    defaultModel: "openai/gpt-5-mini",
    keyEnv: "OPENROUTER_API_KEY",
    requiresApiKey: true,
    customEndpoint: false,
    extraHeaders: {
      "HTTP-Referer": REPOSITORY_URL,
      "X-Title": APP_TITLE
    }
  },
  groq: {
    id: "groq",
    label: "Groq",
    requestType: "chat",
    endpoint: "https://api.groq.com/openai/v1/chat/completions",
    defaultModel: "llama-3.3-70b-versatile",
    keyEnv: "GROQ_API_KEY",
    requiresApiKey: true,
    customEndpoint: false
  },
  custom: {
    id: "custom",
    label: "Custom OpenAI-compatible",
    requestType: "chat",
    endpoint: "",
    defaultModel: "",
    keyEnv: "RMM_HUNTER_AI_API_KEY",
    requiresApiKey: true,
    customEndpoint: true
  }
});

let mainWindow;
let updaterState = {
  status: "idle",
  currentVersion: APP_VERSION,
  latestVersion: APP_VERSION,
  updateAvailable: false,
  updateDownloaded: false,
  canAutoUpdate: app.isPackaged,
  releaseUrl: RELEASES_URL,
  message: "Update check has not run yet."
};

configureElectronStorage();
configureAutoUpdater();

function createWindow() {
  mainWindow = new BrowserWindow({
    width: 1180,
    height: 780,
    minWidth: 980,
    minHeight: 680,
    backgroundColor: "#f6f7f9",
    title: "RMM Hunter",
    icon: APP_ICON,
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

function configureAutoUpdater() {
  autoUpdater.autoDownload = false;
  autoUpdater.autoInstallOnAppQuit = true;
  autoUpdater.allowPrerelease = true;
  autoUpdater.allowDowngrade = false;

  autoUpdater.on("checking-for-update", () => {
    setUpdaterState({
      status: "checking",
      updateAvailable: false,
      updateDownloaded: false,
      message: "Checking the official GitHub Releases feed."
    });
  });

  autoUpdater.on("update-available", (info) => {
    setUpdaterState({
      status: "available",
      latestVersion: normalizeVersion(info?.version) || String(info?.version || APP_VERSION),
      updateAvailable: true,
      updateDownloaded: false,
      releaseName: String(info?.releaseName || info?.version || ""),
      releaseUrl: releasePageUrl(info?.version),
      message: `RMM Hunter ${info?.version || "update"} is available.`
    });
  });

  autoUpdater.on("update-not-available", (info) => {
    setUpdaterState({
      status: "current",
      latestVersion: normalizeVersion(info?.version) || APP_VERSION,
      updateAvailable: false,
      updateDownloaded: false,
      message: `RMM Hunter ${APP_VERSION} is up to date.`
    });
  });

  autoUpdater.on("download-progress", (progress) => {
    setUpdaterState({
      status: "downloading",
      downloadProgress: {
        percent: Number.isFinite(progress?.percent) ? Math.max(0, Math.min(100, progress.percent)) : 0,
        transferred: Number.isFinite(progress?.transferred) ? progress.transferred : 0,
        total: Number.isFinite(progress?.total) ? progress.total : 0,
        bytesPerSecond: Number.isFinite(progress?.bytesPerSecond) ? progress.bytesPerSecond : 0
      },
      message: `Downloading update ${Math.round(progress?.percent || 0)}%.`
    });
  });

  autoUpdater.on("update-downloaded", (info) => {
    setUpdaterState({
      status: "downloaded",
      latestVersion: normalizeVersion(info?.version) || updaterState.latestVersion,
      updateAvailable: true,
      updateDownloaded: true,
      message: "Update downloaded. Restart RMM Hunter to install it."
    });
  });

  autoUpdater.on("error", (error) => {
    setUpdaterState({
      status: "error",
      updateDownloaded: false,
      message: updateErrorMessage(error)
    });
  });
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

ipcMain.handle("ai:getSettings", async () => buildAiSettingsStatus());

ipcMain.handle("ai:saveSettings", async (_event, settings) => {
  saveAiSettings(settings);
  return buildAiSettingsStatus();
});

ipcMain.handle("ai:clearKey", async () => {
  const settings = loadAiSettings();
  delete settings.secret;
  writeAiSettings(settings);
  return buildAiSettingsStatus();
});

ipcMain.handle("ai:explainReport", async (_event, report) => {
  const config = resolveAiConfig({ includeSecret: true });
  if (config.setupRequired) {
    return buildAiSetupResponse(config);
  }

  const sanitizedReport = sanitizeReportForAi(report);
  return callAiExplanation({ config, report: sanitizedReport });
});

ipcMain.handle("path:show", async (_event, targetPath) => {
  if (!isSafeReportPath(targetPath)) {
    return;
  }
  shell.showItemInFolder(targetPath);
});

ipcMain.handle("updates:check", async () => checkForUpdates());

ipcMain.handle("updates:openRelease", async (_event, releaseUrl) => {
  const safeUrl = safeReleaseUrl(releaseUrl || RELEASES_URL);
  if (!safeUrl) {
    throw new Error("Update URL is not an allowed RMM Hunter release page.");
  }
  await shell.openExternal(safeUrl.href);
  return true;
});

ipcMain.handle("links:openExternal", async (_event, targetUrl) => {
  const safeUrl = safeProjectExternalUrl(targetUrl);
  if (!safeUrl) {
    throw new Error("External link is not on the RMM Hunter allowlist.");
  }
  await shell.openExternal(safeUrl.href);
  return true;
});

ipcMain.handle("updates:download", async () => downloadAvailableUpdate());

ipcMain.handle("updates:install", async () => {
  if (!updaterState.updateDownloaded) {
    throw new Error("No downloaded update is ready to install.");
  }
  autoUpdater.quitAndInstall(false, true);
  return publicUpdaterState();
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

async function checkForUpdates() {
  if (!app.isPackaged) {
    return checkForUpdatesFromGithub();
  }

  try {
    await autoUpdater.checkForUpdates();
  } catch (error) {
    setUpdaterState({
      status: "error",
      message: updateErrorMessage(error)
    });
  }
  return publicUpdaterState();
}

async function downloadAvailableUpdate() {
  if (!app.isPackaged) {
    throw new Error("Automatic update installation is only available from the installed Windows app.");
  }
  if (!updaterState.updateAvailable) {
    throw new Error("No newer RMM Hunter release is available to download.");
  }
  setUpdaterState({
    status: "downloading",
    message: "Starting update download."
  });
  try {
    await autoUpdater.downloadUpdate();
  } catch (error) {
    setUpdaterState({
      status: "error",
      message: updateErrorMessage(error)
    });
    throw error;
  }
  return publicUpdaterState();
}

async function checkForUpdatesFromGithub() {
  const releases = await fetchGithubReleases();
  const latest = selectLatestRelease(releases);
  if (!latest) {
    return {
      status: "current",
      currentVersion: APP_VERSION,
      latestVersion: APP_VERSION,
      updateAvailable: false,
      updateDownloaded: false,
      canAutoUpdate: false,
      releaseUrl: RELEASES_URL,
      message: "No public GitHub release was found."
    };
  }

  const latestVersion = releaseVersion(latest) || APP_VERSION;
  const updateAvailable = compareVersions(latestVersion, APP_VERSION) > 0;
  return {
    currentVersion: APP_VERSION,
    latestVersion,
    updateAvailable,
    updateDownloaded: false,
    canAutoUpdate: false,
    releaseName: String(latest.name || latest.tag_name || latestVersion),
    releaseUrl: safeReleaseUrl(latest.html_url)?.href || RELEASES_URL,
    publishedAt: latest.published_at || "",
    prerelease: Boolean(latest.prerelease),
    assets: sanitizeReleaseAssets(latest.assets),
    status: updateAvailable ? "available" : "current",
    message: updateAvailable
      ? `RMM Hunter ${latestVersion} is available.`
      : `RMM Hunter ${APP_VERSION} is up to date.`
  };
}

function publicUpdaterState() {
  return {
    status: updaterState.status,
    currentVersion: updaterState.currentVersion,
    latestVersion: updaterState.latestVersion,
    updateAvailable: updaterState.updateAvailable,
    updateDownloaded: updaterState.updateDownloaded,
    canAutoUpdate: updaterState.canAutoUpdate,
    releaseName: updaterState.releaseName || "",
    releaseUrl: updaterState.releaseUrl || RELEASES_URL,
    publishedAt: updaterState.publishedAt || "",
    prerelease: Boolean(updaterState.prerelease),
    downloadProgress: updaterState.downloadProgress || null,
    message: updaterState.message || ""
  };
}

function setUpdaterState(nextState) {
  updaterState = {
    ...updaterState,
    ...nextState,
    currentVersion: APP_VERSION,
    canAutoUpdate: app.isPackaged,
    releaseUrl: safeReleaseUrl(nextState.releaseUrl || updaterState.releaseUrl)?.href || RELEASES_URL
  };
  if (mainWindow && !mainWindow.isDestroyed()) {
    mainWindow.webContents.send("updates:status", publicUpdaterState());
  }
}

function updateErrorMessage(error) {
  const message = String(error?.message || error || "Update failed.");
  if (message.includes("latest.yml") || message.includes("404")) {
    return "Update metadata was not found. Publish a new GitHub release that includes latest.yml, the installer, and the blockmap.";
  }
  if (message.toLowerCase().includes("code signature")) {
    return "The update could not be verified. Publish a signed release or use the manual GitHub download.";
  }
  return message;
}

function fetchGithubReleases() {
  return new Promise((resolve, reject) => {
    const url = new URL(RELEASES_API_URL);
    const request = https.request(
      {
        protocol: url.protocol,
        hostname: url.hostname,
        path: `${url.pathname}${url.search}`,
        method: "GET",
        headers: {
          "Accept": "application/vnd.github+json",
          "User-Agent": APP_USER_AGENT
        },
        timeout: 15000
      },
      (response) => {
        let data = "";
        response.on("data", (chunk) => {
          data += chunk;
        });
        response.on("end", () => {
          if (response.statusCode < 200 || response.statusCode >= 300) {
            reject(new Error(`GitHub update check failed with HTTP ${response.statusCode}.`));
            return;
          }
          try {
            const parsed = JSON.parse(data);
            resolve(Array.isArray(parsed) ? parsed : []);
          } catch (error) {
            reject(new Error(`GitHub update response could not be parsed. ${error.message}`));
          }
        });
      }
    );
    request.on("timeout", () => {
      request.destroy(new Error("GitHub update check timed out."));
    });
    request.on("error", reject);
    request.end();
  });
}

function selectLatestRelease(releases) {
  return releases
    .filter((release) => release && !release.draft && releaseVersion(release))
    .sort((a, b) => compareVersions(releaseVersion(b), releaseVersion(a)))[0] || null;
}

function releaseVersion(release) {
  return normalizeVersion(release?.tag_name) || normalizeVersion(release?.name);
}

function normalizeVersion(value) {
  const match = String(value || "").match(/v?(\d+\.\d+\.\d+(?:[-+][0-9A-Za-z.-]+)?)/);
  return match ? match[1] : "";
}

function compareVersions(left, right) {
  const a = parseVersion(left);
  const b = parseVersion(right);
  for (let index = 0; index < 3; index += 1) {
    if (a.parts[index] !== b.parts[index]) {
      return a.parts[index] > b.parts[index] ? 1 : -1;
    }
  }
  if (a.prerelease === b.prerelease) {
    return 0;
  }
  if (!a.prerelease) {
    return 1;
  }
  if (!b.prerelease) {
    return -1;
  }
  return a.prerelease.localeCompare(b.prerelease);
}

function parseVersion(value) {
  const [core, prerelease = ""] = String(value || "0.0.0").split(/[+-]/);
  const parts = core.split(".").slice(0, 3).map((part) => {
    const parsed = Number.parseInt(part, 10);
    return Number.isFinite(parsed) ? parsed : 0;
  });
  while (parts.length < 3) {
    parts.push(0);
  }
  return { parts, prerelease };
}

function sanitizeReleaseAssets(assets) {
  if (!Array.isArray(assets)) {
    return [];
  }
  return assets.slice(0, 12).map((asset) => ({
    name: String(asset?.name || ""),
    size: Number.isFinite(asset?.size) ? asset.size : 0,
    downloadUrl: String(asset?.browser_download_url || "")
  }));
}

function releasePageUrl(version) {
  const normalized = normalizeVersion(version);
  const url = normalized ? `${RELEASES_URL}/tag/v${normalized}` : RELEASES_URL;
  return safeReleaseUrl(url)?.href || RELEASES_URL;
}

function safeReleaseUrl(value) {
  try {
    const url = new URL(value);
    const pathname = url.pathname.toLowerCase();
    if (
      url.protocol === "https:" &&
      url.hostname.toLowerCase() === "github.com" &&
      pathname.startsWith("/mdp-studio/rmm-hunter/releases")
    ) {
      return url;
    }
  } catch (_error) {
    return null;
  }
  return null;
}

function safeProjectExternalUrl(value) {
  const allowedUrls = new Set([
    REPOSITORY_URL,
    FEEDBACK_ISSUES_URL,
    SECURITY_POLICY_URL,
    PRIVACY_POLICY_URL,
    BUY_ME_A_COFFEE_URL,
    FEEDBACK_EMAIL_URL
  ]);

  try {
    const url = new URL(value);
    if (allowedUrls.has(url.href)) {
      return url;
    }
    const pathname = url.pathname.toLowerCase();
    if (
      url.protocol === "https:" &&
      url.hostname.toLowerCase() === "github.com" &&
      pathname.startsWith("/mdp-studio/rmm-hunter/")
    ) {
      return url;
    }
  } catch (_error) {
    return null;
  }
  return null;
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
  return /^[A-Za-z0-9._:/@+-]{1,120}$/.test(text) ? text : "";
}

function safeProviderId(value) {
  return Object.hasOwn(AI_PROVIDERS, value) ? value : DEFAULT_AI_PROVIDER;
}

function buildAiSettingsStatus() {
  const config = resolveAiConfig({ includeSecret: false });
  return {
    providers: Object.values(AI_PROVIDERS).map((provider) => ({
      id: provider.id,
      label: provider.label,
      endpoint: provider.endpoint,
      defaultModel: provider.defaultModel,
      customEndpoint: provider.customEndpoint,
      requiresApiKey: provider.requiresApiKey,
      keyEnv: provider.keyEnv
    })),
    selected: config.provider,
    providerLabel: config.providerLabel,
    endpoint: config.endpoint,
    model: config.model,
    hasApiKey: config.hasApiKey,
    keySource: config.keySource,
    setupRequired: config.setupRequired,
    setupReason: config.setupReason,
    requiresApiKey: config.requiresApiKey,
    secureStorageAvailable: safeStorage.isEncryptionAvailable()
  };
}

function loadAiSettings() {
  try {
    if (!fs.existsSync(AI_SETTINGS_PATH)) {
      return {};
    }
    const parsed = JSON.parse(fs.readFileSync(AI_SETTINGS_PATH, "utf8"));
    return parsed && typeof parsed === "object" ? parsed : {};
  } catch (error) {
    console.error(`Could not load AI settings. ${error.message}`);
    return {};
  }
}

function writeAiSettings(settings) {
  fs.mkdirSync(PROFILE_ROOT, { recursive: true });
  fs.writeFileSync(AI_SETTINGS_PATH, JSON.stringify(settings, null, 2) + "\n", "utf8");
}

function saveAiSettings(payload) {
  const existing = loadAiSettings();
  const provider = safeProviderId(payload?.provider);
  const preset = AI_PROVIDERS[provider];
  const endpoint = preset.customEndpoint ? safeEndpointInput(payload?.endpoint) : "";
  const model = safeModelName(payload?.model) || preset.defaultModel;
  const apiKey = String(payload?.apiKey || "").trim();
  const nextSettings = {
    provider,
    model,
    endpoint
  };

  if (apiKey) {
    nextSettings.secret = encryptApiKey(apiKey, provider);
  } else if (existing.secret?.provider === provider) {
    nextSettings.secret = existing.secret;
  }

  writeAiSettings(nextSettings);
}

function resolveAiConfig({ includeSecret }) {
  const settings = loadAiSettings();
  const provider = safeProviderId(process.env.RMM_HUNTER_AI_PROVIDER || settings.provider);
  const preset = AI_PROVIDERS[provider];
  const savedEndpoint = preset.customEndpoint ? settings.endpoint : "";
  const endpointInput = process.env.RMM_HUNTER_AI_ENDPOINT || savedEndpoint || preset.endpoint;
  const model = safeModelName(process.env.RMM_HUNTER_AI_MODEL || settings.model) || preset.defaultModel;
  const apiKey = resolveApiKey({ settings, provider, preset, includeSecret });
  const config = {
    provider,
    providerLabel: preset.label,
    requestType: preset.requestType,
    endpoint: endpointInput || "",
    model,
    apiKey,
    hasApiKey: Boolean(apiKey.present || apiKey.value),
    keySource: apiKey.source,
    requiresApiKey: preset.requiresApiKey,
    setupRequired: false,
    setupReason: "",
    extraHeaders: preset.extraHeaders || {}
  };

  try {
    config.url = normalizeAiEndpoint(config.endpoint);
  } catch (error) {
    config.setupRequired = true;
    config.setupReason = error.message;
  }

  if (!config.model) {
    config.setupRequired = true;
    config.setupReason = "Choose a model for this AI provider.";
  }

  if (config.requiresApiKey && !config.hasApiKey) {
    config.setupRequired = true;
    config.setupReason = `Add an API key for ${config.providerLabel}.`;
  }

  return config;
}

function resolveApiKey({ settings, provider, preset, includeSecret }) {
  const envValue = process.env.RMM_HUNTER_AI_API_KEY || process.env[preset.keyEnv];
  if (envValue) {
    return {
      value: includeSecret ? envValue : null,
      present: true,
      source: preset.keyEnv && process.env[preset.keyEnv] ? preset.keyEnv : "RMM_HUNTER_AI_API_KEY"
    };
  }

  if (settings.secret?.provider === provider) {
    if (includeSecret) {
      const value = decryptApiKey(settings.secret);
      return {
        value,
        present: Boolean(value),
        source: value ? "saved" : "none"
      };
    }
    return {
      value: null,
      present: true,
      source: "saved"
    };
  }

  return {
    value: "",
    present: false,
    source: "none"
  };
}

function encryptApiKey(apiKey, provider) {
  if (!safeStorage.isEncryptionAvailable()) {
    throw new Error("Secure key storage is unavailable on this Windows profile. Use an environment variable instead.");
  }

  return {
    provider,
    storage: "electron-safe-storage",
    value: safeStorage.encryptString(apiKey).toString("base64")
  };
}

function decryptApiKey(secret) {
  try {
    if (secret?.storage !== "electron-safe-storage" || !secret.value || !safeStorage.isEncryptionAvailable()) {
      return "";
    }
    return safeStorage.decryptString(Buffer.from(secret.value, "base64"));
  } catch (error) {
    console.error(`Could not decrypt AI key. ${error.message}`);
    return "";
  }
}

function safeEndpointInput(value) {
  return String(value || "").trim().slice(0, 300);
}

function normalizeAiEndpoint(value) {
  const text = safeEndpointInput(value);
  if (!text) {
    throw new Error("Add an AI endpoint URL for this provider.");
  }

  const url = new URL(text);
  if (url.protocol === "https:") {
    return url;
  }

  if (url.protocol === "http:" && isLocalhost(url.hostname)) {
    return url;
  }

  throw new Error("AI endpoint must use HTTPS unless it is a localhost endpoint.");
}

function isLocalhost(hostname) {
  return ["localhost", "127.0.0.1", "::1"].includes(String(hostname || "").toLowerCase());
}

function buildAiSetupResponse(config) {
  return {
    available: false,
    needs_setup: true,
    provider: config.providerLabel || "AI",
    model: config.model || "",
    summary: config.setupReason || "Add an AI provider API key to generate recommendations.",
    next_steps: [
      "Choose a provider in AI settings.",
      "Paste your own API key and model name, then save.",
      "Click AI Recommendations again after saving."
    ],
    finding_explanations: [],
    privacy_note: "No report data was sent to an AI provider."
  };
}

function buildPdfHtml(report) {
  const findings = Array.isArray(report.findings) ? report.findings : [];
  const counts = report.artifact_counts || {};
  const metadata = report.collection_metadata || {};
  const recommendations = Array.isArray(report.recommendations) ? report.recommendations : [];
  const trustHealth = Array.isArray(report.system_trust_health) ? report.system_trust_health : [];
  const timeline = Array.isArray(report.timeline) ? report.timeline : [];
  const aiExplanation = report.ai_explanation || null;
  const rows = findings
    .map((finding) => {
      const artifact = Array.isArray(finding.artifacts) && finding.artifacts[0] ? finding.artifacts[0] : {};
      const artifactBits = Object.entries(artifact)
        .filter(([key]) => !["message_excerpt", "event_data"].includes(key))
        .slice(0, 12)
        .map(([key, value]) => `<div><strong>${escapeHtml(key)}:</strong> ${escapeHtml(formatPdfValue(value))}</div>`)
        .join("");
      const actionRows = Array.isArray(finding.recommended_actions)
        ? finding.recommended_actions.map((item) => `<li>${escapeHtml(item)}</li>`).join("")
        : "";
      const guidance = finding.plain_language
        ? `<div class="guidance"><strong>What this means:</strong><p>${escapeHtml(finding.plain_language)}</p>${actionRows ? `<strong>Suggested review actions:</strong><ol>${actionRows}</ol>` : ""}</div>`
        : "";
      return `
        <section class="finding ${escapeHtml(finding.severity || "low")}">
          <div class="finding-summary">
            <h3>${escapeHtml(finding.title || "Finding")}</h3>
            <p><strong>Severity:</strong> ${escapeHtml(finding.severity || "unknown")}</p>
            <p><strong>Evidence:</strong> ${escapeHtml(String(finding.evidence_strength || "unknown").replace(/_/g, " "))} strength, ${escapeHtml(String(finding.confidence_label || "unknown"))} confidence</p>
            <p><strong>Artifacts in finding:</strong> ${escapeHtml(String(finding.artifact_count || 1))}</p>
            <p>${escapeHtml(finding.reason || "")}</p>
            ${guidance}
          </div>
          ${artifactBits ? `<div class="artifact"><strong>First artifact excerpt</strong>${artifactBits}</div>` : ""}
        </section>
      `;
    })
    .join("");

  const countRows = Object.entries(counts)
    .sort(([a], [b]) => a.localeCompare(b))
    .map(([key, value]) => `<tr><td>${escapeHtml(key)}</td><td>${escapeHtml(String(value))}</td></tr>`)
    .join("");
  const recommendationRows = recommendations.map((item) => `<li>${escapeHtml(item)}</li>`).join("");
  const trustRows = trustHealth
    .map((check) => `
      <section class="trust ${escapeHtml(check.status || "unknown")}">
        <h3>${escapeHtml(check.title || "Trust health check")}</h3>
        <p><strong>Status:</strong> ${escapeHtml(check.status || "unknown")}</p>
        <p>${escapeHtml(check.detail || "")}</p>
        <p class="note">${escapeHtml(check.recommended_action || "")}</p>
      </section>
    `)
    .join("");
  const timelineRows = timeline
    .slice(0, 60)
    .map((entry) => `
      <li>
        <strong>${escapeHtml(entry.time_utc || "unknown")} ${entry.timestamp_type ? `(${escapeHtml(entry.timestamp_type)})` : ""}</strong>
        <span>${escapeHtml(entry.title || "Finding")}${entry.tool ? ` (${escapeHtml(entry.tool)})` : ""}</span>
        <small>${escapeHtml(entry.artifact_summary || entry.category || "")}</small>
      </li>
    `)
    .join("");
  const aiRows = aiExplanation
    ? `
      <section class="report-section">
        <h2>AI Explanation</h2>
        <p>${escapeHtml(aiExplanation.summary || "")}</p>
        <ul>${(aiExplanation.next_steps || []).map((item) => `<li>${escapeHtml(item)}</li>`).join("")}</ul>
        <p class="note">${escapeHtml(aiExplanation.privacy_note || "")}</p>
      </section>
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
          h2 { border-bottom: 1px solid #d8dde6; font-size: 18px; margin: 0 0 12px; padding-bottom: 8px; }
          h3 { font-size: 15px; margin: 0 0 8px; }
          p { line-height: 1.45; margin: 6px 0; }
          ul { margin-bottom: 0; }
          .report-section { break-inside: avoid; break-inside: avoid-page; margin: 0 0 22px; page-break-inside: avoid; }
          .report-section:first-child { margin-top: 0; }
          .report-section:last-child { margin-bottom: 0; }
          .report-section.findings-section { break-inside: auto; page-break-inside: auto; }
          .verdict { border: 1px solid #ccd3df; border-radius: 8px; margin: 12px 0 0; padding: 16px; }
          .verdict strong { text-transform: uppercase; }
          table { border-collapse: collapse; width: 100%; }
          td { border-bottom: 1px solid #edf0f4; padding: 7px 4px; }
          .finding { border: 1px solid #d8dde6; border-left-width: 6px; border-radius: 8px; break-inside: auto; margin: 12px 0 18px; page-break-inside: auto; padding: 14px; }
          .finding.high { border-left-color: #c53232; }
          .finding.medium { border-left-color: #b97800; }
          .finding.low { border-left-color: #4b6fa8; }
          .finding-summary { break-inside: avoid; break-inside: avoid-page; page-break-inside: avoid; }
          .trust { border: 1px solid #d8dde6; border-left: 5px solid #9aa3b2; border-radius: 8px; break-inside: avoid; margin: 10px 0; page-break-inside: avoid; padding: 12px; }
          .trust.ok { border-left-color: #267a4f; }
          .trust.needs_review { border-left-color: #b97800; }
          .trust.high_risk { border-left-color: #c53232; }
          .guidance { background: #f7f8fa; border-radius: 6px; margin: 10px 0; padding: 10px; }
          .guidance ol { margin: 6px 0 0; padding-left: 20px; }
          .guidance li { margin: 4px 0; }
          .timeline { list-style: none; margin: 0; padding: 0; }
          .timeline li { border-left: 4px solid #315f9f; break-inside: avoid; margin: 0 0 10px; padding: 0 0 0 10px; page-break-inside: avoid; }
          .timeline strong, .timeline span, .timeline small { display: block; }
          .timeline small { color: #5c6678; line-height: 1.4; margin-top: 3px; overflow-wrap: anywhere; }
          .artifact { background: #f7f8fa; border-radius: 6px; break-inside: auto; font-family: Consolas, monospace; font-size: 10px; margin-top: 10px; overflow-wrap: anywhere; page-break-inside: auto; padding: 10px; white-space: pre-wrap; }
          .artifact strong { display: block; font-family: Arial, sans-serif; font-size: 11px; margin-bottom: 6px; text-transform: uppercase; }
          .artifact div { border-top: 1px solid #e3e7ee; padding: 5px 0; }
          .note { color: #5c6678; font-size: 12px; }
        </style>
      </head>
      <body>
        <section class="report-section">
          <h1>RMM Hunter Report</h1>
          <p>Generated at ${escapeHtml(report.scanner?.generated_at_utc || new Date().toISOString())}</p>
          <div class="verdict">
            <p><strong>${escapeHtml(report.verdict || "unknown")}</strong></p>
            <p>Risk score: ${escapeHtml(String(report.risk_score ?? "unknown"))}/100</p>
            <p>Host: ${escapeHtml(metadata.hostname || "unknown")}</p>
            <p>${escapeHtml(report.summary || "")}</p>
          </div>
        </section>
        <section class="report-section">
          <h2>Recommended Next Steps</h2>
          <ul>${recommendationRows || "<li>No recommendations available.</li>"}</ul>
        </section>
        ${aiRows}
        <section class="report-section">
          <h2>System Trust Health</h2>
          ${trustRows || "<p>No trust-health checks were returned.</p>"}
        </section>
        <section class="report-section">
          <h2>Timeline</h2>
          ${timelineRows ? `<ol class="timeline">${timelineRows}</ol>` : "<p>No timestamped finding artifacts were returned.</p>"}
        </section>
        <section class="report-section">
          <h2>Artifact Counts</h2>
          <table>${countRows}</table>
        </section>
        <section class="report-section findings-section">
          <h2>Findings</h2>
          ${rows || "<p>No findings.</p>"}
        </section>
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
    system_trust_health: sanitizeTrustHealth(report?.system_trust_health).slice(0, 12),
    timeline: sanitizeTimeline(report?.timeline).slice(0, 30),
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
      confidence_label: sanitizeScalar(finding.confidence_label),
      evidence_strength: sanitizeScalar(finding.evidence_strength),
      reason: sanitizeScalar(finding.reason),
      plain_language: sanitizeScalar(finding.plain_language),
      recommended_actions: sanitizeArray(finding.recommended_actions).slice(0, 5),
      artifact_count: Number.isFinite(finding.artifact_count) ? finding.artifact_count : 1,
      artifacts: sanitizeArtifacts(finding.artifacts).slice(0, 3)
    }))
  };
}

function sanitizeTrustHealth(checks) {
  if (!Array.isArray(checks)) {
    return [];
  }

  return checks.map((check) => sanitizeRecord({
    check: check?.check,
    status: check?.status,
    title: check?.title,
    detail: check?.detail,
    recommended_action: check?.recommended_action,
    affected_components: check?.affected_components,
    affected_items: check?.affected_items,
    suspicious_exclusions: check?.suspicious_exclusions,
    age_days: check?.age_days,
    signature_version: check?.signature_version,
    exclusion_count: check?.exclusion_count,
    total_roots: check?.total_roots,
    current_user_roots: check?.current_user_roots
  }));
}

function sanitizeTimeline(entries) {
  if (!Array.isArray(entries)) {
    return [];
  }

  return entries.map((entry) => sanitizeRecord({
    time_utc: entry?.time_utc,
    timestamp_type: entry?.timestamp_type,
    finding_id: entry?.finding_id,
    severity: entry?.severity,
    category: entry?.category,
    title: entry?.title,
    tool: entry?.tool,
    artifact_source: entry?.artifact_source,
    artifact_summary: entry?.artifact_summary
  }));
}

function sanitizeArtifacts(artifacts) {
  if (!Array.isArray(artifacts)) {
    return [];
  }

  return artifacts.map((artifact) => {
    const cleaned = {};
    const allowedKeys = [
      "source",
      "detail",
      "network_urls",
      "network_domains",
      "affected_urls",
      "affected_domains",
      "threat_name",
      "defender_action",
      "defender_result",
      "detection_time_utc",
      "detection_source",
      "affected_resource",
      "old_setting_path",
      "old_setting_value",
      "new_setting_path",
      "new_setting_value",
      "check",
      "status",
      "title",
      "recommended_action",
      "finding_category",
      "affected_components",
      "affected_items",
      "suspicious_exclusions",
      "age_days",
      "signature_version",
      "exclusion_count",
      "total_roots",
      "current_user_roots",
      "tool",
      "artifact_role",
      "artifact_kind",
      "evidence_question",
      "source_file",
      "row_number",
      "row_context",
      "size_bytes",
      "line_count",
      "sample_lines",
      "observed_time_utc",
      "timestamp_type",
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

    for (const key of ["path", "directory", "path_name", "executable_path", "install_location", "uninstall_string", "registry_path", "source_path", "relative_path"]) {
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

function callAiExplanation({ config, report }) {
  const reportPayload = JSON.stringify({ report });
  if (Buffer.byteLength(reportPayload, "utf8") > MAX_AI_REPORT_BYTES) {
    return Promise.reject(new Error("Sanitized report is too large for AI explanation."));
  }

  const body = config.requestType === "responses"
    ? buildResponsesApiBody({ config, reportPayload })
    : buildChatCompletionBody({ config, reportPayload });

  return sendAiRequest({ config, body }).then((parsed) => {
    const outputText = config.requestType === "responses"
      ? parsed.output_text || extractResponseText(parsed)
      : extractChatCompletionText(parsed);
    const explanation = parseAiJson(outputText);
    return normalizeAiExplanation(explanation, config);
  });
}

function buildAiSchema() {
  return {
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
}

function buildAiInstructions() {
  return [
    "You explain RMM Hunter scan results to a Windows user.",
    "Never change or override the deterministic verdict.",
    "Do not tell the user to delete artifacts automatically.",
    "Base the answer only on the sanitized JSON report.",
    "Use exact artifact context when present, including domains, URLs, Defender threat names, Defender action/result, affected resource, and old/new setting values.",
    "Use System Trust Health checks to explain whether Defender state, security intelligence age, exclusions, Windows code-signing validation, or trusted-root-store signals affect confidence in the findings.",
    "If a domain, path, or command appears related to a project or admin task, say it may be expected only if the user recognizes it; do not assume it is malicious.",
    "For Defender malware events, separate what is known from the report from what cannot be proven, such as the original website or delivery source when browser history/process telemetry is absent.",
    "Use concise plain English and practical incident-triage steps.",
    "If evidence is ambiguous, say it needs owner or IT-provider confirmation.",
    "Return only valid JSON using the requested schema."
  ].join(" ");
}

function buildResponsesApiBody({ config, reportPayload }) {
  const schema = buildAiSchema();

  return {
    model: config.model,
    input: [
      {
        role: "developer",
        content: [
          {
            type: "input_text",
            text: buildAiInstructions()
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
}

function buildChatCompletionBody({ config, reportPayload }) {
  return {
    model: config.model,
    temperature: 0.2,
    messages: [
      {
        role: "system",
        content: `${buildAiInstructions()} JSON shape: ${JSON.stringify(buildAiSchema())}`
      },
      {
        role: "user",
        content: reportPayload
      }
    ],
    response_format: {
      type: "json_object"
    }
  };
}

function sendAiRequest({ config, body }) {
  return new Promise((resolve, reject) => {
    const bodyText = JSON.stringify(body);
    const url = config.url;
    const transport = url.protocol === "http:" ? http : https;
    const headers = {
      "Accept": "application/json",
      "Content-Type": "application/json",
      "Content-Length": Buffer.byteLength(bodyText),
      "User-Agent": APP_USER_AGENT,
      ...config.extraHeaders
    };

    if (config.apiKey?.value) {
      headers.Authorization = `Bearer ${config.apiKey.value}`;
    }

    const request = transport.request(
      {
        protocol: url.protocol,
        hostname: url.hostname,
        port: url.port,
        path: `${url.pathname}${url.search}`,
        method: "POST",
        headers,
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
            resolve(JSON.parse(data));
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
    request.write(bodyText);
    request.end();
  });
}

function extractChatCompletionText(response) {
  const message = response?.choices?.[0]?.message;
  if (!message) {
    return "";
  }
  if (typeof message.content === "string") {
    return message.content;
  }
  if (Array.isArray(message.content)) {
    return message.content.map((part) => part?.text || part?.content || "").join("");
  }
  return "";
}

function parseAiJson(text) {
  const cleaned = String(text || "")
    .trim()
    .replace(/^```(?:json)?\s*/i, "")
    .replace(/\s*```$/i, "")
    .trim();

  try {
    return JSON.parse(cleaned);
  } catch (_error) {
    const start = cleaned.indexOf("{");
    const end = cleaned.lastIndexOf("}");
    if (start >= 0 && end > start) {
      return JSON.parse(cleaned.slice(start, end + 1));
    }
    throw new Error("AI explanation response did not contain valid JSON.");
  }
}

function normalizeAiExplanation(explanation, config) {
  const findingExplanations = Array.isArray(explanation?.finding_explanations)
    ? explanation.finding_explanations.slice(0, 8).map((finding) => ({
        finding_id: limitAiText(finding?.finding_id, 80),
        title: limitAiText(finding?.title, 160),
        explanation: limitAiText(finding?.explanation, 800),
        recommended_action: limitAiText(finding?.recommended_action, 500),
        urgency: ["low", "medium", "high"].includes(finding?.urgency) ? finding.urgency : "medium"
      }))
    : [];

  const nextSteps = Array.isArray(explanation?.next_steps)
    ? explanation.next_steps.slice(0, 8).map((item) => limitAiText(item, 400)).filter(Boolean)
    : [];

  return {
    available: true,
    provider: config.providerLabel,
    model: config.model,
    summary: limitAiText(explanation?.summary || "AI recommendations generated.", 1200),
    next_steps: nextSteps.length ? nextSteps : ["Review the deterministic recommendations and evidence cards."],
    finding_explanations: findingExplanations,
    privacy_note: limitAiText(
      explanation?.privacy_note || "Only the minimized, redacted report summary was sent to the selected AI provider.",
      500
    )
  };
}

function limitAiText(value, maxLength) {
  return String(value || "").trim().slice(0, maxLength);
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
