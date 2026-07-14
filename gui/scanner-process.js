"use strict";

const childProcess = require("node:child_process");

const DEFAULT_TIMEOUT_MS = 15 * 60 * 1000;
const DEFAULT_MAX_OUTPUT_BYTES = 8 * 1024 * 1024;

function startBoundedProcess(options = {}) {
  const {
    command,
    args = [],
    cwd,
    timeoutMs = DEFAULT_TIMEOUT_MS,
    maxOutputBytes = DEFAULT_MAX_OUTPUT_BYTES,
    onStdout = () => {},
    onStderr = () => {}
  } = options;

  if (typeof command !== "string" || !command) {
    throw new TypeError("A scanner command is required.");
  }
  if (!Array.isArray(args)) {
    throw new TypeError("Scanner arguments must be an array.");
  }
  if (!Number.isSafeInteger(timeoutMs) || timeoutMs <= 0) {
    throw new TypeError("Scanner timeout must be a positive integer.");
  }
  if (!Number.isSafeInteger(maxOutputBytes) || maxOutputBytes <= 0) {
    throw new TypeError("Scanner output limit must be a positive integer.");
  }

  const child = childProcess.spawn(command, args, {
    cwd,
    windowsHide: true,
    stdio: ["ignore", "pipe", "pipe"]
  });

  let settled = false;
  let outputBytes = 0;
  const stdout = [];
  const stderr = [];
  let resolvePromise;
  let rejectPromise;

  const promise = new Promise((resolve, reject) => {
    resolvePromise = resolve;
    rejectPromise = reject;
  });

  const timer = setTimeout(() => {
    fail(`Scanner timed out after ${Math.ceil(timeoutMs / 1000)} seconds.`, "SCAN_TIMEOUT");
  }, timeoutMs);

  function finish(callback, value) {
    if (settled) {
      return;
    }
    settled = true;
    clearTimeout(timer);
    callback(value);
  }

  function fail(message, code, cause) {
    if (settled) {
      return;
    }
    terminateProcessTree(child);
    const error = new Error(message, cause ? { cause } : undefined);
    error.code = code;
    finish(rejectPromise, error);
  }

  function capture(data, destination, callback) {
    if (settled) {
      return;
    }
    const chunk = Buffer.isBuffer(data) ? data : Buffer.from(data);
    outputBytes += chunk.length;
    if (outputBytes > maxOutputBytes) {
      fail(`Scanner output exceeded the ${maxOutputBytes}-byte safety limit.`, "SCAN_OUTPUT_LIMIT");
      return;
    }
    destination.push(chunk);
    try {
      callback(chunk.toString("utf8"));
    } catch (error) {
      console.error("Scanner progress callback failed.", error);
      fail("Scanner progress handling failed.", "SCAN_PROGRESS_ERROR", error);
    }
  }

  child.stdout.on("data", (data) => capture(data, stdout, onStdout));
  child.stderr.on("data", (data) => capture(data, stderr, onStderr));

  child.once("error", (error) => {
    fail(`Could not start scanner. ${error.message}`, "SCAN_START_ERROR", error);
  });

  child.once("close", (code, signal) => {
    if (settled) {
      return;
    }
    const stdoutText = Buffer.concat(stdout).toString("utf8");
    const stderrText = Buffer.concat(stderr).toString("utf8");
    if (code === 0) {
      finish(resolvePromise, stdoutText);
      return;
    }
    const exitReason = signal ? `signal ${signal}` : `exit code ${code}`;
    fail(`Scanner failed with ${exitReason}.\n${stderrText || stdoutText}`, "SCAN_FAILED");
  });

  return {
    promise,
    cancel() {
      fail("Scan cancelled by the operator.", "SCAN_CANCELLED");
    }
  };
}

function terminateProcessTree(child) {
  if (!child || !Number.isSafeInteger(child.pid) || child.pid <= 0 || child.exitCode !== null) {
    return;
  }

  if (process.platform === "win32") {
    const killer = childProcess.spawn(
      "taskkill.exe",
      ["/PID", String(child.pid), "/T", "/F"],
      { windowsHide: true, stdio: "ignore" }
    );
    killer.once("error", () => child.kill());
    killer.unref();
    return;
  }

  child.kill("SIGTERM");
  const forceKill = setTimeout(() => {
    if (child.exitCode === null) {
      child.kill("SIGKILL");
    }
  }, 1000);
  forceKill.unref();
}

module.exports = {
  DEFAULT_MAX_OUTPUT_BYTES,
  DEFAULT_TIMEOUT_MS,
  startBoundedProcess
};
