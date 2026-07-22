import test from "node:test";
import assert from "node:assert/strict";
import { buildEntrySwitchFoundationPreview } from "./entrySwitchModel.js";

test("valid confirmed preview becomes executable and exposes the fail-closed order", () => {
  const preview = buildEntrySwitchFoundationPreview(
    { host: "127.0.0.1", port: 41001 },
    { host: "127.0.0.8", port: 41002 },
    true,
    true,
  );
  assert.equal(preview.executable, true);
  assert.equal(preview.steps.length, 5);
  assert.match(preview.steps[2], /Controller.*Fail Closed/);
  assert.deepEqual(preview.issues, []);
});

test("non-loopback and missing confirmation are explicit accessible issues", () => {
  const preview = buildEntrySwitchFoundationPreview(
    { host: "127.0.0.1", port: 41001 },
    { host: "0.0.0.0", port: 0 },
    false,
    false,
  );
  assert.deepEqual(
    preview.issues.map((issue) => issue.code),
    ["loopback_required", "invalid_port", "confirmation_required"],
  );
  assert.equal(preview.steps.at(-1), "不调用任何系统代理 backend");
});
