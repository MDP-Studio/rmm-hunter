const fs = require("node:fs");
const path = require("node:path");

const root = path.resolve(__dirname, "..");
const targets = [
  path.join(root, "build"),
  path.join(root, "release"),
  path.join(root, "rmm-hunter-cli.spec")
];

for (const target of targets) {
  const resolved = path.resolve(target);
  if (!resolved.startsWith(root + path.sep)) {
    throw new Error(`Refusing to remove path outside project: ${resolved}`);
  }
  fs.rmSync(resolved, { recursive: true, force: true });
}
