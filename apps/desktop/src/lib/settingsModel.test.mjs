import assert from "node:assert/strict";
import test from "node:test";
import { buildCredentialMutations, createOutletId, moveItem } from "./settingsModel.js";

test("reordering and renaming do not regenerate stable outlet ids", () => {
  const outlets = [
    { outlet_id: "sub-a", label: "A" },
    { outlet_id: "local-a", label: "Local" },
  ];
  const moved = moveItem(outlets, 0, 1);
  moved[1] = { ...moved[1], label: "Renamed" };
  assert.deepEqual(moved.map((outlet) => outlet.outlet_id), ["local-a", "sub-a"]);
  assert.equal(moved[1].label, "Renamed");
});

test("generated ids stay within the core stable-id alphabet", () => {
  assert.equal(createOutletId("subscription", "A1B2-C3D4_E5F6"), "subscription-a1b2c3d4e5f6");
});

test("credential mutations keep raw values only in the apply request", () => {
  const result = buildCredentialMutations(
    { "sub-a": "https://example.invalid/private-value", "sub-b": "" },
    new Set(["sub-b"]),
  );
  assert.deepEqual(result, [
    { subscription_id: "sub-a", action: "set", credential: "https://example.invalid/private-value" },
    { subscription_id: "sub-b", action: "delete", credential: null },
  ]);
});
