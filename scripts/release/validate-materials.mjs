import { readFileSync, statSync } from "node:fs";
import { createRequire } from "node:module";
import { join, resolve } from "node:path";
import process from "node:process";
import { sha256 } from "./release-lib.mjs";

const directory = resolve(process.argv[2] ?? "");
if (!process.argv[2]) throw new Error("usage: validate-materials.mjs DIRECTORY");
const requireFromDesktop = createRequire(join(process.cwd(), "apps/desktop/package.json"));
const { JsonValidator } = requireFromDesktop("@cyclonedx/cyclonedx-library/Validation");
const { Version } = requireFromDesktop("@cyclonedx/cyclonedx-library/Spec");
const cycloneValidator = new JsonValidator(Version.v1dot6);
const manifest = readJson("release-manifest.dev.json");
if (
  manifest.schema_version !== 1 ||
  manifest.channel !== "dev" ||
  manifest.source_url !== "" ||
  manifest.signing_key_id !== "unconfigured" ||
  manifest.system_proxy_included !== false ||
  manifest.tun_executor_supported !== false ||
  !manifest.artifact.file_name.includes(".dev.")
) {
  throw new Error("dev manifest is promotable or enables an unsupported feature");
}
const bindings = [
  ["build-environment.json", "build_environment_sha256"],
  ["rust-sbom.cdx.json", "rust_sbom_sha256"],
  ["frontend-sbom.cdx.json", "frontend_sbom_sha256"],
  ["licenses.json", "licenses_sha256"],
  ["reproducibility.json", "reproducibility_sha256"],
];
for (const [file, field] of bindings) {
  if (sha256(readFileSync(join(directory, file))) !== manifest[field]) {
    throw new Error(`${file} is not bound to the manifest`);
  }
}
const artifactPath = join(directory, manifest.artifact.file_name);
if (
  sha256(readFileSync(artifactPath)) !== manifest.artifact.sha256 ||
  statSync(artifactPath).size !== manifest.artifact.size
) {
  throw new Error("artifact hash or size does not match the manifest");
}
for (const file of ["rust-sbom.cdx.json", "frontend-sbom.cdx.json"]) {
  const bytes = readFileSync(join(directory, file), "utf8");
  const sbom = JSON.parse(bytes);
  if (
    sbom.bomFormat !== "CycloneDX" ||
    sbom.specVersion !== "1.6" ||
    !Array.isArray(sbom.components) ||
    sbom.components.length === 0 ||
    "serialNumber" in sbom ||
    "timestamp" in (sbom.metadata ?? {})
  ) {
    throw new Error(`${file} is not a normalized CycloneDX 1.6 SBOM`);
  }
  const schemaError = await cycloneValidator.validate(bytes);
  if (schemaError !== null) throw new Error(`${file} failed the official CycloneDX 1.6 JSON schema`);
}
const frontend = readJson("frontend-sbom.cdx.json");
if (
  !Array.isArray(frontend.dependencies) || frontend.dependencies.length === 0 ||
  !Array.isArray(frontend.compositions) ||
  !["complete", "incomplete"].includes(frontend.compositions[0]?.aggregate)
) {
  throw new Error("frontend SBOM lacks a resolved dependency graph or completeness declaration");
}
const sums = readFileSync(join(directory, "SHA256SUMS"), "utf8");
if (sums !== `${manifest.artifact.sha256}  ${manifest.artifact.file_name}\n`) {
  throw new Error("SHA256SUMS is not canonical");
}
process.stdout.write(`validated ${manifest.artifact.file_name} and bound release materials\n`);
function readJson(name) { return JSON.parse(readFileSync(join(directory, name), "utf8")); }
