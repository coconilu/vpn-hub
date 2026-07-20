import assert from "node:assert/strict";
import test from "node:test";
import { devArtifactName, promotionFailures, stableJson } from "./release-lib.mjs";

test("dev artifact name is visibly non-promotable and deterministic", () => {
  const name = devArtifactName("0.2.0", "a".repeat(40));
  assert.equal(name, "vpn-hub-0.2.0-aaaaaaaaaaaa.dev.nsis-setup.exe");
  assert.match(name, /\.dev\./);
});

test("stable JSON removes object insertion order as a source of drift", () => {
  assert.equal(stableJson({ z: 1, a: { y: 2, b: 3 } }), '{\n  "a": {\n    "b": 3,\n    "y": 2\n  },\n  "z": 1\n}\n');
});

test("promotion fails closed when external evidence is absent", () => {
  const failures = promotionFailures({ channel: "dev", system_proxy_included: false, tun_executor_supported: false });
  assert.ok(failures.includes("authenticode_chain_trusted"));
  assert.ok(failures.includes("clean_windows_vm_acceptance"));
  assert.ok(failures.includes("stable_channel"));
  assert.ok(failures.includes("trusted_update_key_id"));
});
