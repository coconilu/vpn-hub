import { existsSync, readdirSync } from "node:fs";
import { resolve } from "node:path";
import process from "node:process";
import { assertFreshBuildRoot } from "./release-lib.mjs";

const root = resolve(process.argv[2] ?? "");
if (!process.argv[2]) throw new Error("usage: assert-fresh-build-root.mjs TARGET_DIRECTORY");
assertFreshBuildRoot(existsSync(root) ? readdirSync(root) : []);
process.stdout.write(`fresh build root confirmed: ${root}\n`);
