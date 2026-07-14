"use strict";

const assert = require("node:assert/strict");
const test = require("node:test");
const { startBoundedProcess } = require("../gui/scanner-process");

function runNode(source, options = {}) {
  return startBoundedProcess({
    command: process.execPath,
    args: ["-e", source],
    timeoutMs: 2000,
    maxOutputBytes: 4096,
    ...options
  });
}

test("returns bounded scanner output", async () => {
  const execution = runNode("process.stdout.write('ready')");
  await assert.doesNotReject(async () => {
    assert.equal(await execution.promise, "ready");
  });
});

test("terminates a scanner that exceeds its timeout", async () => {
  const execution = runNode("setInterval(() => {}, 1000)", { timeoutMs: 50 });
  await assert.rejects(execution.promise, (error) => error.code === "SCAN_TIMEOUT");
});

test("terminates a scanner that exceeds its output budget", async () => {
  const execution = runNode("process.stdout.write('x'.repeat(5000))", { maxOutputBytes: 128 });
  await assert.rejects(execution.promise, (error) => error.code === "SCAN_OUTPUT_LIMIT");
});

test("supports explicit operator cancellation", async () => {
  const execution = runNode("setInterval(() => {}, 1000)");
  execution.cancel();
  await assert.rejects(execution.promise, (error) => error.code === "SCAN_CANCELLED");
});
