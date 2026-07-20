import { createHash } from "node:crypto";

export function sha256(value) {
  return createHash("sha256").update(value).digest("hex");
}

export function stableJson(value) {
  return `${JSON.stringify(sortValue(value), null, 2)}\n`;
}

function sortValue(value) {
  if (Array.isArray(value)) return value.map(sortValue);
  if (value && typeof value === "object") {
    return Object.fromEntries(
      Object.keys(value)
        .sort()
        .map((key) => [key, sortValue(value[key])]),
    );
  }
  return value;
}

export function devArtifactName(version, commit) {
  if (!/^\d+\.\d+\.\d+(?:[-+][0-9A-Za-z.-]+)?$/.test(version)) {
    throw new Error("invalid release version");
  }
  if (!/^[0-9a-f]{40}$/.test(commit)) throw new Error("invalid commit");
  return `vpn-hub-${version}-${commit.slice(0, 12)}.dev.nsis-setup.exe`;
}

export function assertFreshBuildRoot(entries) {
  if (!Array.isArray(entries) || entries.length !== 0) {
    throw new Error("isolated build root contains stale state");
  }
}

export function assertExpectedCommit(actual, expected) {
  if (!/^[0-9a-f]{40}$/.test(expected) || actual !== expected) {
    throw new Error(`release source mismatch: expected ${expected}, got ${actual}`);
  }
}

export function validateBuildEnvironment(value) {
  const requiredStrings = [
    value?.runner?.image_os,
    value?.runner?.image_version,
    value?.msvc?.tools_version,
    value?.msvc?.cl_product_version,
    value?.msvc?.link_product_version,
    value?.windows_sdk?.version,
    value?.windows_sdk?.rc_product_version,
    value?.nsis?.version,
    value?.rust,
    value?.cargo,
    value?.node,
    value?.npm,
    value?.tauri,
  ];
  if (value?.schema_version !== 1 || requiredStrings.some((item) => typeof item !== "string" || item.length === 0)) {
    throw new Error("build environment evidence is incomplete");
  }
}

export function environmentDrift(first, second) {
  return stableJson(first) === stableJson(second) ? [] : ["build-environment.json"];
}

const missingExternalAttestations = Object.freeze([
  "machine-produced-authenticode-verification",
  "machine-produced-update-signature-verification",
  "clean-windows-vm-acceptance",
]);

export function promotionFailures(evidence = undefined) {
  if (evidence !== undefined) validateFutureAttestationContract(evidence);
  return [...missingExternalAttestations];
}

function validateFutureAttestationContract(evidence) {
  if (!isPlainObject(evidence)) throw new Error("promotion evidence schema rejected");
  const rootKeys = ["artifact_sha256", "candidate_commit", "external_attestations", "schema_version"];
  const attestationKeys = ["authenticode", "clean_windows_vm", "update_signature"];
  if (
    !hasExactKeys(evidence, rootKeys) ||
    evidence.schema_version !== 1 ||
    !/^[0-9a-f]{40}$/.test(evidence.candidate_commit) ||
    !/^[0-9a-f]{64}$/.test(evidence.artifact_sha256) ||
    !isPlainObject(evidence.external_attestations) ||
    !hasExactKeys(evidence.external_attestations, attestationKeys)
  ) {
    throw new Error("promotion evidence schema rejected");
  }
  for (const value of Object.values(evidence.external_attestations)) {
    if (value !== "missing") throw new Error("promotion evidence schema rejected");
  }
}

function hasExactKeys(value, expected) {
  const actual = Object.keys(value).sort();
  return actual.length === expected.length && actual.every((key, index) => key === expected[index]);
}

function isPlainObject(value) {
  return value !== null && typeof value === "object" && !Array.isArray(value);
}
