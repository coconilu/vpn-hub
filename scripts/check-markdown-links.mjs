import { execFileSync } from "node:child_process";
import { existsSync, readFileSync } from "node:fs";
import { dirname, relative, resolve } from "node:path";

const root = resolve(process.argv[2] ?? ".");
const markdownFiles = execFileSync(
  "git",
  ["ls-files", "-z", "--cached", "--others", "--exclude-standard", "*.md"],
  { cwd: root },
)
  .toString("utf8")
  .split("\0")
  .filter(Boolean);
const failures = [];
const inlineLink = /!?(?:\[[^\]]*\])\(([^)]+)\)/g;

for (const markdownFile of markdownFiles) {
  if (!existsSync(resolve(root, markdownFile))) continue;
  const content = readFileSync(resolve(root, markdownFile), "utf8");
  for (const match of content.matchAll(inlineLink)) {
    const rawTarget = match[1].trim().replace(/^<|>$/g, "");
    if (
      rawTarget === "" ||
      rawTarget.startsWith("#") ||
      /^[a-z][a-z0-9+.-]*:/i.test(rawTarget) ||
      rawTarget.startsWith("//")
    ) continue;
    const pathOnly = decodeURIComponent(rawTarget.split(/[?#]/, 1)[0]);
    const target = resolve(root, dirname(markdownFile), pathOnly);
    if (relative(root, target).startsWith("..") || !existsSync(target)) {
      failures.push(`${markdownFile} -> ${rawTarget}`);
    }
  }
}

if (failures.length > 0) throw new Error(`broken Markdown links: ${failures.join(", ")}`);
process.stdout.write(`Markdown link check passed for ${markdownFiles.length} tracked files\n`);
