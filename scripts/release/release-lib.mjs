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

export function promotionFailures(evidence) {
  const requiredTrue = [
    "authenticode_chain_trusted",
    "authenticode_timestamp_valid",
    "update_signature_verified",
    "trusted_https_source_verified",
    "artifact_hash_verified",
    "rust_sbom_verified",
    "frontend_sbom_verified",
    "licenses_verified",
    "reproducible_materials_verified",
    "clean_windows_vm_acceptance",
  ];
  const failures = requiredTrue.filter((field) => evidence[field] !== true);
  if (evidence.channel !== "stable") failures.push("stable_channel");
  if (evidence.system_proxy_included !== false) failures.push("system_proxy_excluded");
  if (evidence.tun_executor_supported !== false) failures.push("tun_executor_disabled");
  if (typeof evidence.signing_key_id !== "string" || evidence.signing_key_id.length === 0) {
    failures.push("trusted_update_key_id");
  }
  if (!Array.isArray(evidence.allowed_update_hosts) || evidence.allowed_update_hosts.length === 0) {
    failures.push("allowed_update_hosts");
  }
  return [...new Set(failures)].sort();
}
