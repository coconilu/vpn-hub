import { execFileSync } from "node:child_process";
import { createRequire } from "node:module";
import { copyFileSync, mkdirSync, readFileSync, statSync, writeFileSync } from "node:fs";
import { basename, join, resolve } from "node:path";
import process from "node:process";
import {
  assertExpectedCommit,
  devArtifactName,
  sha256,
  stableJson,
  validateBuildEnvironment,
} from "./release-lib.mjs";
import { normalizeFrontendSbom } from "./sbom-lib.mjs";

const options = parseArgs(process.argv.slice(2));
const root = resolve(options.root ?? ".");
const sourceArtifact = resolve(required(options, "artifact"));
const output = resolve(required(options, "output"));
const commit = run("git", ["rev-parse", "HEAD"], root);
const expectedCommit = required(options, "expected-commit");
assertExpectedCommit(commit, expectedCommit);
const cargoMetadata = JSON.parse(
  run("cargo", ["metadata", "--locked", "--format-version", "1", "--filter-platform", "x86_64-pc-windows-msvc"], root),
);
const environmentSource = resolve(required(options, "environment"));
const buildEnvironment = JSON.parse(readFileSync(environmentSource, "utf8"));
validateBuildEnvironment(buildEnvironment);
const tauriConfig = JSON.parse(
  readFileSync(join(root, "apps/desktop/src-tauri/tauri.conf.json"), "utf8"),
);
const desktopPackage = JSON.parse(readFileSync(join(root, "apps/desktop/package.json"), "utf8"));
const workspaceVersion = cargoMetadata.packages.find((item) => item.name === "vpn-hub-core")?.version;
if (!workspaceVersion || workspaceVersion !== tauriConfig.version || workspaceVersion !== desktopPackage.version) {
  throw new Error("Cargo, Tauri, and frontend versions must match");
}

mkdirSync(output, { recursive: true });
const fileName = devArtifactName(workspaceVersion, commit);
const copiedArtifact = join(output, fileName);
copyFileSync(sourceArtifact, copiedArtifact);
const toolchain = {
  cargo: versionOnly(run("cargo", ["--version"], root)),
  node: process.version.slice(1),
  npm: desktopPackage.packageManager.split("@").at(-1),
  rust: versionOnly(run("rustc", ["--version"], root)),
  target: "x86_64-pc-windows-msvc",
  tauri_cli: desktopPackage.devDependencies["@tauri-apps/cli"],
};

const rustComponents = cargoMetadata.packages
  .map((item) => ({
    "bom-ref": `pkg:cargo/${encodeURIComponent(item.name)}@${item.version}`,
    licenses: item.license ? [{ expression: item.license }] : [{ expression: "NOASSERTION" }],
    name: item.name,
    purl: `pkg:cargo/${encodeURIComponent(item.name)}@${item.version}`,
    type: "library",
    version: item.version,
  }))
  .sort(componentOrder);
const rustRefs = new Set(rustComponents.map((item) => item["bom-ref"]));
const packageRef = new Map(
  cargoMetadata.packages.map((item) => [item.id, `pkg:cargo/${encodeURIComponent(item.name)}@${item.version}`]),
);
const rustDependencies = (cargoMetadata.resolve?.nodes ?? [])
  .map((node) => ({
    dependsOn: node.dependencies.map((id) => packageRef.get(id)).filter((id) => rustRefs.has(id)).sort(),
    ref: packageRef.get(node.id),
  }))
  .filter((item) => item.ref && rustRefs.has(item.ref))
  .sort((left, right) => left.ref.localeCompare(right.ref));

const desktopRoot = join(root, "apps/desktop");
const cyclonedxCli = join(desktopRoot, "node_modules/@cyclonedx/cyclonedx-npm/bin/cyclonedx-npm-cli.js");
const frontendRaw = JSON.parse(run(process.execPath, [
  cyclonedxCli,
  "--package-lock-only",
  "--flatten-components",
  "--output-reproducible",
  "--validate",
  "--spec-version", "1.6",
  "--output-format", "JSON",
  "--output-file", "-",
], desktopRoot));
const requireFromDesktop = createRequire(join(desktopRoot, "package.json"));
const { PackageURL } = requireFromDesktop("packageurl-js");
const frontendSbom = normalizeFrontendSbom(frontendRaw, (value) => PackageURL.fromString(value));
const frontendComponents = frontendSbom.components;

const rustSbom = cyclone("VPN Hub Rust workspace", workspaceVersion, rustComponents, rustDependencies);
const licenses = [...rustComponents.map((item) => licenseRow("cargo", item)), ...frontendComponents.map((item) => licenseRow("npm", item))]
  .sort((left, right) => `${left.ecosystem}:${left.name}:${left.version}`.localeCompare(`${right.ecosystem}:${right.name}:${right.version}`));
const reproducibility = {
  comparable_scope: [
    "source commit and product version",
    "pinned toolchain versions",
    "normalized Rust and npm dependency graphs",
    "normalized license inventory",
    "artifact SHA-256 and size",
  ],
  excluded_from_strict_byte_reproducibility: [
    "Authenticode signatures and RFC3161 timestamps (not present in dev artifacts)",
    "NSIS/PE container metadata emitted by upstream bundling tools",
  ],
  normalization: "No wall-clock timestamp, absolute path, username, runner name, or SBOM serial number is recorded.",
  source: { commit, version: workspaceVersion },
  toolchain,
  build_environment: buildEnvironment,
};

const rustBytes = writeStable(join(output, "rust-sbom.cdx.json"), rustSbom);
const frontendBytes = writeStable(join(output, "frontend-sbom.cdx.json"), frontendSbom);
const licenseBytes = writeStable(join(output, "licenses.json"), { schema_version: 1, components: licenses });
const reproducibilityBytes = writeStable(join(output, "reproducibility.json"), reproducibility);
const environmentBytes = writeStable(join(output, "build-environment.json"), buildEnvironment);
const artifactBytes = readFileSync(copiedArtifact);
const manifest = {
  artifact: {
    file_name: fileName,
    kind: "nsis-exe",
    sha256: sha256(artifactBytes),
    size: statSync(copiedArtifact).size,
  },
  build_environment_sha256: sha256(environmentBytes),
  channel: "dev",
  commit,
  frontend_sbom_sha256: sha256(frontendBytes),
  licenses_sha256: sha256(licenseBytes),
  product: "VPN Hub",
  reproducibility_sha256: sha256(reproducibilityBytes),
  rust_sbom_sha256: sha256(rustBytes),
  schema_version: 1,
  signing_key_id: "unconfigured",
  source_url: "",
  system_proxy_included: false,
  toolchain,
  tun_executor_supported: false,
  version: workspaceVersion,
};
writeStable(join(output, "release-manifest.dev.json"), manifest);
writeFileSync(join(output, "SHA256SUMS"), `${manifest.artifact.sha256}  ${fileName}\n`, "utf8");
process.stdout.write(`generated dev materials for ${basename(copiedArtifact)}\n`);

function parseArgs(args) {
  const parsed = {};
  for (let index = 0; index < args.length; index += 2) {
    if (!args[index].startsWith("--") || !args[index + 1]) throw new Error("arguments must be --name value pairs");
    parsed[args[index].slice(2)] = args[index + 1];
  }
  return parsed;
}
function required(value, name) { if (!value[name]) throw new Error(`missing --${name}`); return value[name]; }
function run(command, args, cwd) {
  return execFileSync(command, args, {
    cwd,
    encoding: "utf8",
    maxBuffer: 64 * 1024 * 1024,
    stdio: ["ignore", "pipe", "pipe"],
  }).trim();
}
function versionOnly(output) { return output.split(/\s+/)[1]; }
function componentOrder(left, right) { return left["bom-ref"].localeCompare(right["bom-ref"]); }
function licenseRow(ecosystem, item) {
  const entry = item.licenses?.[0];
  const license = entry?.expression ?? entry?.license?.id ?? entry?.license?.name ?? "NOASSERTION";
  const name = item.group ? `${item.group}/${item.name}` : item.name;
  return { ecosystem, license, name, version: item.version };
}
function cyclone(name, version, components, dependencies) {
  return {
    bomFormat: "CycloneDX",
    components,
    dependencies,
    metadata: { component: { name, type: "application", version }, tools: { components: [{ name: "vpn-hub-release-materials", type: "application", version: "1" }] } },
    specVersion: "1.6",
    version: 1,
  };
}
function writeStable(path, value) { const bytes = Buffer.from(stableJson(value)); writeFileSync(path, bytes); return bytes; }
