import { execFileSync } from "node:child_process";
import { copyFileSync, mkdirSync, readFileSync, statSync, writeFileSync } from "node:fs";
import { basename, join, resolve } from "node:path";
import process from "node:process";
import { devArtifactName, sha256, stableJson } from "./release-lib.mjs";

const options = parseArgs(process.argv.slice(2));
const root = resolve(options.root ?? ".");
const sourceArtifact = resolve(required(options, "artifact"));
const output = resolve(required(options, "output"));
const commit = run("git", ["rev-parse", "HEAD"], root);
const cargoMetadata = JSON.parse(
  run("cargo", ["metadata", "--locked", "--format-version", "1", "--filter-platform", "x86_64-pc-windows-msvc"], root),
);
const packageLock = JSON.parse(readFileSync(join(root, "apps/desktop/package-lock.json"), "utf8"));
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

const frontendComponents = Object.entries(packageLock.packages ?? {})
  .filter(([path, value]) => path.startsWith("node_modules/") && value.version)
  .map(([path, value]) => {
    const name = path.slice("node_modules/".length);
    return {
      "bom-ref": `pkg:npm/${encodeURIComponent(name)}@${value.version}`,
      hashes: integrityHash(value.integrity),
      licenses: value.license ? [{ expression: value.license }] : [{ expression: "NOASSERTION" }],
      name,
      purl: `pkg:npm/${encodeURIComponent(name)}@${value.version}`,
      type: "library",
      version: value.version,
    };
  })
  .sort(componentOrder)
  .map(removeUndefined);

const rustSbom = cyclone("VPN Hub Rust workspace", workspaceVersion, rustComponents, rustDependencies);
const frontendSbom = cyclone("VPN Hub frontend", workspaceVersion, frontendComponents, []);
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
};

const rustBytes = writeStable(join(output, "rust-sbom.cdx.json"), rustSbom);
const frontendBytes = writeStable(join(output, "frontend-sbom.cdx.json"), frontendSbom);
const licenseBytes = writeStable(join(output, "licenses.json"), { schema_version: 1, components: licenses });
const reproducibilityBytes = writeStable(join(output, "reproducibility.json"), reproducibility);
const artifactBytes = readFileSync(copiedArtifact);
const manifest = {
  artifact: {
    file_name: fileName,
    kind: "nsis-exe",
    sha256: sha256(artifactBytes),
    size: statSync(copiedArtifact).size,
  },
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
function removeUndefined(value) { return Object.fromEntries(Object.entries(value).filter(([, item]) => item !== undefined)); }
function integrityHash(integrity) {
  if (typeof integrity !== "string" || !integrity.startsWith("sha512-")) return undefined;
  return [{ alg: "SHA-512", content: Buffer.from(integrity.slice(7), "base64").toString("hex") }];
}
function licenseRow(ecosystem, item) { return { ecosystem, license: item.licenses[0].expression, name: item.name, version: item.version }; }
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
