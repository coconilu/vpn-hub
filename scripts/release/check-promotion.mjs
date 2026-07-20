import { readFileSync } from "node:fs";
import { isAbsolute, relative, resolve } from "node:path";
import process from "node:process";
import { promotionFailures } from "./release-lib.mjs";

const [evidencePath] = process.argv.slice(2);
if (!evidencePath) throw new Error("promotion is disabled: no evidence file supplied");
if (isAbsolute(evidencePath)) throw new Error("promotion evidence must be repository-relative");
const resolved = resolve(evidencePath);
const repositoryRelative = relative(process.cwd(), resolved);
if (repositoryRelative.startsWith("..") || isAbsolute(repositoryRelative)) {
  throw new Error("promotion evidence is outside the repository");
}
const evidence = JSON.parse(readFileSync(resolved, "utf8"));
const failures = promotionFailures(evidence);
if (failures.length > 0) throw new Error(`promotion blocked; missing gates: ${failures.join(", ")}`);
process.stdout.write("promotion evidence is complete; this verifier does not publish artifacts\n");
