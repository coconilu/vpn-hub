import { execFileSync } from "node:child_process";
import { extname, relative, resolve } from "node:path";
import { readFileSync, readdirSync, statSync } from "node:fs";
import process from "node:process";

const root = resolve(process.argv[2] ?? ".");
const repositoryFiles = execFileSync("git", ["ls-files", "-z", "--cached", "--others", "--exclude-standard"], { cwd: root })
  .toString("utf8")
  .split("\0")
  .filter(Boolean);
const extraFiles = process.argv.slice(3).flatMap((directory) => {
  const absolute = resolve(root, directory);
  const fromRoot = relative(root, absolute);
  if (fromRoot.startsWith("..")) throw new Error("scan directory is outside the repository");
  return readdirSync(absolute, { recursive: true, withFileTypes: true })
    .filter((entry) => entry.isFile())
    .map((entry) => relative(root, resolve(entry.parentPath, entry.name)));
});
const tracked = [...new Set([...repositoryFiles, ...extraFiles])].sort();
const forbiddenExtensions = new Set([".pfx", ".p12", ".p8", ".jks", ".keystore", ".pem", ".key"]);
const binaryExtensions = new Set([".png", ".ico", ".jpg", ".jpeg", ".gif", ".webp"]);
const patterns = [
  ["private-key-header", /-----BEGIN (?:RSA |EC |OPENSSH )?PRIVATE KEY-----/],
  ["high-entropy-credential-assignment", /(?:controller[_-]?secret|subscription[_-]?(?:token|secret))\s*[:=]\s*["'][A-Za-z0-9+/=_-]{32,}["']/i],
  ["pfx-password-assignment", /pfx[_-]?password\s*[:=]\s*["'][^"'\r\n]{8,}["']/i],
  ["credential-in-url", /https:\/\/[^\s"']+(?:token|secret|key)=[^&\s"']+/i],
];
const failures = [];
for (const relative of tracked) {
  const extension = extname(relative).toLowerCase();
  if (forbiddenExtensions.has(extension)) failures.push(`${relative}:forbidden-key-file`);
  if (binaryExtensions.has(extension)) continue;
  if (statSync(resolve(root, relative)).size > 50 * 1024 * 1024) {
    failures.push(`${relative}:file-too-large-to-scan`);
    continue;
  }
  const content = readFileSync(resolve(root, relative), "utf8");
  for (const [rule, pattern] of patterns) if (pattern.test(content)) failures.push(`${relative}:${rule}`);
}
if (failures.length > 0) throw new Error(`sensitive scan failed: ${failures.join(", ")}`);
process.stdout.write(`sensitive scan passed for ${tracked.length} repository and artifact files\n`);
