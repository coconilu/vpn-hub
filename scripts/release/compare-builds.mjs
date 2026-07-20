import { readFileSync, writeFileSync } from "node:fs";
import { join, resolve } from "node:path";
import process from "node:process";
import { sha256, stableJson } from "./release-lib.mjs";

const [firstArg, secondArg, outputArg] = process.argv.slice(2);
if (!firstArg || !secondArg || !outputArg) throw new Error("usage: compare-builds.mjs FIRST SECOND OUTPUT");
const first = resolve(firstArg);
const second = resolve(secondArg);
const names = ["rust-sbom.cdx.json", "frontend-sbom.cdx.json", "licenses.json", "reproducibility.json"];
const normalized = Object.fromEntries(names.map((name) => [name, fileHash(first, name) === fileHash(second, name)]));
const firstManifest = JSON.parse(readFileSync(join(first, "release-manifest.dev.json"), "utf8"));
const secondManifest = JSON.parse(readFileSync(join(second, "release-manifest.dev.json"), "utf8"));
const report = {
  artifact_byte_identical: firstManifest.artifact.sha256 === secondManifest.artifact.sha256,
  artifact_hashes: [firstManifest.artifact.sha256, secondManifest.artifact.sha256],
  normalized_materials: normalized,
  normalized_materials_identical: Object.values(normalized).every(Boolean),
  note: "Artifact differences are reported, never normalized away; production promotion additionally requires trusted signatures and clean-VM evidence.",
  schema_version: 1,
};
writeFileSync(resolve(outputArg), stableJson(report), "utf8");
if (!report.normalized_materials_identical) throw new Error("normalized release materials differ");
process.stdout.write(`normalized materials match; artifact byte-identical=${report.artifact_byte_identical}\n`);
function fileHash(directory, name) { return sha256(readFileSync(join(directory, name))); }
