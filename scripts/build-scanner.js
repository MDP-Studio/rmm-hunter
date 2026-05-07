const childProcess = require("node:child_process");
const fs = require("node:fs");
const path = require("node:path");

const root = path.resolve(__dirname, "..");
const pyinstaller = resolvePyInstaller();
const dataSeparator = process.platform === "win32" ? ";" : ":";
const args = [
  "--clean",
  "--noconfirm",
  "--onefile",
  "--name",
  "rmm-hunter-cli",
  "--add-data",
  `${path.join(root, "collect_windows.ps1")}${dataSeparator}.`,
  "--distpath",
  path.join(root, "build", "scanner"),
  "--workpath",
  path.join(root, "build", "pyinstaller"),
  "--specpath",
  path.join(root, "build", "pyinstaller"),
  path.join(root, "rmm_hunter.py")
];

const result = childProcess.spawnSync(pyinstaller.command, [...pyinstaller.prefixArgs, ...args], {
  cwd: root,
  stdio: "inherit",
  windowsHide: true
});

if (result.error) {
  throw result.error;
}

process.exit(result.status || 0);

function resolvePyInstaller() {
  if (process.env.RMM_HUNTER_PYINSTALLER) {
    return {
      command: process.env.RMM_HUNTER_PYINSTALLER,
      prefixArgs: []
    };
  }

  const localPath = process.platform === "win32"
    ? path.join(root, ".release-venv", "Scripts", "pyinstaller.exe")
    : path.join(root, ".release-venv", "bin", "pyinstaller");

  if (fs.existsSync(localPath)) {
    return {
      command: localPath,
      prefixArgs: []
    };
  }

  return {
    command: process.env.PYTHON || "python",
    prefixArgs: ["-m", "PyInstaller"]
  };
}
