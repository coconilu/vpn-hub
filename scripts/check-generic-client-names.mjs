import { execFileSync } from "node:child_process";
import { existsSync, readFileSync, statSync } from "node:fs";
import { resolve } from "node:path";
import process from "node:process";

const root = resolve(process.argv[2] ?? ".");
const tracked = execFileSync(
  "git",
  ["ls-files", "-z", "--cached", "--others", "--exclude-standard"],
  { cwd: root },
)
  .toString("utf8")
  .split("\0")
  .filter(Boolean);

// Keep the forbidden roots encoded so this scanner does not match its own source.
// Matching the roots case-insensitively also catches branded process, group, and pipe variants.
const encodedProductRoots = [
  [99, 104, 97, 111, 115, 104, 105, 104, 117, 105],
  [36229, 23454, 24800],
  [115, 112, 101, 101, 100, 99, 97, 116],
  [102, 108, 99, 108, 97, 115, 104],
];
const productRoots = encodedProductRoots.map((points) =>
  String.fromCodePoint(...points).toLocaleLowerCase("en-US"),
);
const findings = [];

for (const relativePath of tracked) {
  const normalizedPath = relativePath.toLocaleLowerCase("en-US");
  const absolutePath = resolve(root, relativePath);
  if (!existsSync(absolutePath)) continue;
  for (const productRoot of productRoots) {
    if (normalizedPath.includes(productRoot)) findings.push(`${relativePath}:filename`);
  }

  if (statSync(absolutePath).size > 50 * 1024 * 1024) continue;
  const content = readFileSync(absolutePath, "utf8").toLocaleLowerCase("en-US");
  for (const productRoot of productRoots) {
    if (content.includes(productRoot)) findings.push(`${relativePath}:content`);
  }
}

if (findings.length > 0) {
  throw new Error(`specific local client product names found: ${findings.join(", ")}`);
}
process.stdout.write(`generic client name scan passed for ${tracked.length} tracked files\n`);
