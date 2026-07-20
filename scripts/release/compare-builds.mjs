import { readFileSync, writeFileSync } from "node:fs";
import { join, resolve } from "node:path";
import process from "node:process";
import { environmentDrift, sha256, stableJson } from "./release-lib.mjs";

const [firstArg, secondArg, outputArg] = process.argv.slice(2);
if (!firstArg || !secondArg || !outputArg) throw new Error("usage: compare-builds.mjs FIRST SECOND OUTPUT");
const first = resolve(firstArg);
const second = resolve(secondArg);
const names = ["rust-sbom.cdx.json", "frontend-sbom.cdx.json", "licenses.json", "reproducibility.json", "build-environment.json"];
const normalized = Object.fromEntries(names.map((name) => [name, fileHash(first, name) === fileHash(second, name)]));
const firstManifest = JSON.parse(readFileSync(join(first, "release-manifest.dev.json"), "utf8"));
const secondManifest = JSON.parse(readFileSync(join(second, "release-manifest.dev.json"), "utf8"));
const environmentDifferences = environmentDrift(
  JSON.parse(readFileSync(join(first, "build-environment.json"), "utf8")),
  JSON.parse(readFileSync(join(second, "build-environment.json"), "utf8")),
);
const report = {
  artifact_byte_identical: firstManifest.artifact.sha256 === secondManifest.artifact.sha256,
  artifact_hashes: [firstManifest.artifact.sha256, secondManifest.artifact.sha256],
  normalized_materials: normalized,
  normalized_materials_identical: Object.values(normalized).every(Boolean),
  environment_differences: environmentDifferences,
  note: "This is same-run normalized consistency on one recorded runner image, not formal reproducibility. Artifact differences are reported and formal promotion remains blocked.",
  schema_version: 1,
};
writeFileSync(resolve(outputArg), stableJson(report), "utf8");
if (!report.normalized_materials_identical || environmentDifferences.length > 0) throw new Error("normalized release materials or build environments differ");
process.stdout.write(`normalized materials match; artifact byte-identical=${report.artifact_byte_identical}\n`);
function fileHash(directory, name) { return sha256(readFileSync(join(directory, name))); }
