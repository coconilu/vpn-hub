import assert from "node:assert/strict";
import test from "node:test";
import {
  assertFreshBuildRoot,
  assertExpectedCommit,
  devArtifactName,
  environmentDrift,
  promotionFailures,
  stableJson,
  validateBuildEnvironment,
} from "./release-lib.mjs";

test("dev artifact name is visibly non-promotable and deterministic", () => {
  const name = devArtifactName("0.2.0", "a".repeat(40));
  assert.equal(name, "vpn-hub-0.2.0-aaaaaaaaaaaa.dev.nsis-setup.exe");
  assert.match(name, /\.dev\./);
});

test("stable JSON removes object insertion order as a source of drift", () => {
  assert.equal(stableJson({ z: 1, a: { y: 2, b: 3 } }), '{\n  "a": {\n    "b": 3,\n    "y": 2\n  },\n  "z": 1\n}\n');
});

test("isolated build roots reject stale artifacts and cached outputs", () => {
  assert.doesNotThrow(() => assertFreshBuildRoot([]));
  assert.throws(() => assertFreshBuildRoot(["release"]), /stale state/);
  assert.throws(() => assertFreshBuildRoot(["old-setup.exe"]), /stale state/);
});

test("manifest commit binding rejects merge commits and malformed expected SHAs", () => {
  const head = "a".repeat(40);
  assert.doesNotThrow(() => assertExpectedCommit(head, head));
  assert.throws(() => assertExpectedCommit(head, "b".repeat(40)), /source mismatch/);
  assert.throws(() => assertExpectedCommit(head, "a".repeat(39)), /source mismatch/);
});

test("build environment evidence requires every recorded tool family", () => {
  const environment = {
    schema_version: 1,
    runner: { image_os: "Windows", image_version: "20260720.1" },
    msvc: { tools_version: "14.44", cl_product_version: "19.44", link_product_version: "14.44" },
    windows_sdk: { version: "10.0.26100.0", rc_product_version: "10.0.26100.0" },
    nsis: { version: "v3.11" },
    rust: "rustc 1.97.0",
    cargo: "cargo 1.97.0",
    node: "v24.15.0",
    npm: "11.12.1",
    tauri: "tauri-cli 2.11.4",
  };
  assert.doesNotThrow(() => validateBuildEnvironment(environment));
  assert.throws(() => validateBuildEnvironment({ ...environment, runner: {} }), /incomplete/);
});

test("runner or compiler environment drift is a normalized-material mismatch", () => {
  const baseline = { runner: { image: "windows-2025" }, msvc: { cl: "19.44" } };
  assert.deepEqual(environmentDrift(baseline, { msvc: { cl: "19.44" }, runner: { image: "windows-2025" } }), []);
  assert.deepEqual(environmentDrift(baseline, { runner: { image: "windows-2025" }, msvc: { cl: "19.45" } }), ["build-environment.json"]);
});

test("promotion fails closed when external evidence is absent", () => {
  const failures = promotionFailures();
  assert.deepEqual(failures, [
    "machine-produced-authenticode-verification",
    "machine-produced-update-signature-verification",
    "clean-windows-vm-acceptance",
  ]);
});

test("even a fully bound future contract remains blocked", () => {
  const evidence = {
    schema_version: 1,
    candidate_commit: "a".repeat(40),
    artifact_sha256: "b".repeat(64),
    external_attestations: {
      authenticode: "missing",
      clean_windows_vm: "missing",
      update_signature: "missing",
    },
  };
  assert.equal(promotionFailures(evidence).length, 3);
  assert.throws(
    () => promotionFailures({ ...evidence, unknown: true }),
    /schema rejected/,
  );
  assert.throws(
    () => promotionFailures({
      ...evidence,
      external_attestations: {
        authenticode: true,
        clean_windows_vm: true,
        update_signature: true,
      },
    }),
    /schema rejected/,
  );
});
