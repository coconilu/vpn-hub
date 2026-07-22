import assert from "node:assert/strict";
import fs from "node:fs";
import test from "node:test";
import {
  buildSettingsPreviewRequest,
  consumeSettingsPreviewTicket,
  createOutletId,
  dispatchOneShotSettingsApply,
  isCurrentPreviewResponse,
  moveItem,
  settingsPreviewOutcome,
  settingsRequestFingerprint,
  settingsValidationTargetIds,
} from "./settingsModel.js";

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

const draft = { entry: { host: "127.0.0.1", port: 3666 }, outlets: [{ outlet_id: "sub-a" }] };

test("preview fingerprint is deterministic and contains only sanitized credential intent", () => {
  const first = buildSettingsPreviewRequest(draft, null, false, { "sub-b": "delete", "sub-a": "set" });
  const second = buildSettingsPreviewRequest(draft, null, false, { "sub-a": "set", "sub-b": "delete" });
  assert.equal(first.request_fingerprint, second.request_fingerprint);
  assert.equal(JSON.stringify(first).includes("private-value"), false);
  assert.deepEqual(first.credential_intents, [
    { subscription_id: "sub-a", action: "set" },
    { subscription_id: "sub-b", action: "delete" },
  ]);
});

test("overlapping and edited previews discard stale responses", () => {
  const first = buildSettingsPreviewRequest(draft, null, false, {});
  const editedDraft = { ...draft, entry: { ...draft.entry, port: 3667 } };
  const second = buildSettingsPreviewRequest(editedDraft, null, false, {});
  assert.equal(isCurrentPreviewResponse(1, 2, second.request_fingerprint, first.request_fingerprint), false);
  assert.equal(isCurrentPreviewResponse(2, 2, second.request_fingerprint, second.request_fingerprint), true);
  assert.notEqual(first.request_fingerprint, second.request_fingerprint);
});

test("credential intent invalidates a matching draft preview", () => {
  const clean = settingsRequestFingerprint(draft, null, false, []);
  const intent = buildSettingsPreviewRequest(draft, null, false, { "sub-a": "delete" });
  assert.notEqual(clean, intent.request_fingerprint);
});

test("automatic apply distinguishes errors, live apply, and reload confirmation", () => {
  const base = { issues: [], can_apply: true, requires_managed_core_restart: false };
  assert.equal(settingsPreviewOutcome(base), "live_apply");
  assert.equal(settingsPreviewOutcome({ ...base, requires_managed_core_restart: true }), "confirm_reload");
  assert.equal(settingsPreviewOutcome({ ...base, issues: [{ field: "outlets" }] }), "error");
  assert.equal(settingsPreviewOutcome({ ...base, can_apply: false }), "no_changes");
});

test("one-shot dispatch clears uncontrolled password input before rejected await", async () => {
  const secret = "https://example.invalid/private-value";
  const input = { value: secret };
  const inputs = new Map([["sub-a", input]]);
  let dispatched;
  const pending = dispatchOneShotSettingsApply(
    { draft, preview_fingerprint: "fingerprint" },
    inputs,
    { "sub-a": "set" },
    async (request) => {
      dispatched = request;
      throw new Error("synthetic failure");
    },
  );
  assert.equal(input.value, "");
  assert.equal(inputs.size, 0);
  await assert.rejects(pending, /synthetic failure/);
  assert.equal(dispatched.credential_mutations[0].credential, secret);
});

test("one-shot credential read clears every password input before validation failure", () => {
  const missing = { value: "" };
  const unrelated = { value: "must-also-be-cleared" };
  const inputs = new Map([["sub-a", missing], ["sub-b", unrelated]]);
  assert.throws(() => dispatchOneShotSettingsApply(
    { draft, preview_fingerprint: "fingerprint" },
    inputs,
    { "sub-a": "set" },
    async () => undefined,
  ), /必须输入新值/);
  assert.equal(missing.value, "");
  assert.equal(unrelated.value, "");
  assert.equal(inputs.size, 0);
});

test("browser preview ticket is consumed exactly once", () => {
  let ticket = "fingerprint";
  ticket = consumeSettingsPreviewTicket(ticket, "fingerprint");
  assert.equal(ticket, null);
  assert.throws(() => consumeSettingsPreviewTicket(ticket, "fingerprint"), /已失效或已被使用/);
});

test("settings component has no controlled or React-state credential plaintext", () => {
  const source = fs.readFileSync(new URL("../SettingsPage.tsx", import.meta.url), "utf8");
  assert.equal(source.includes("credentialValues"), false);
  assert.equal(/type="password"[^>]*\bvalue=/.test(source), false);
  assert.equal(source.includes("dispatchOneShotSettingsApply"), true);
});

test("entry switching preserves dirty drafts and resyncs committed recovery-pending state", () => {
  const source = fs.readFileSync(new URL("../SettingsPage.tsx", import.meta.url), "utf8");
  assert.equal(source.includes("if (dirty || terminalStatus.active || !entrySwitchTarget"), true);
  assert.equal(source.includes("entry_switch_recovery_pending: settings and runtime committed"), true);
  assert.equal(source.includes("getSettingsTerminalStatus()"), true);
  assert.equal(source.includes("setCredentialIntentById({})"), true);
  assert.equal(source.includes("setReplacement(null)"), true);
  assert.equal(source.includes("setFailClosed(false)"), true);
});

test("unsupported TUN stays visibly off and cannot record consent", () => {
  const source = fs.readFileSync(new URL("../SettingsPage.tsx", import.meta.url), "utf8");
  assert.equal(source.includes("checked={false} disabled aria-describedby=\"tun-unavailable-reason\" />启用 TUN"), true);
  assert.equal(source.includes("checked={false} disabled aria-describedby=\"tun-unavailable-reason\" />我已理解"), true);
  assert.equal(source.includes("windows_verified_application_identity_exclusion_unavailable"), true);
  assert.equal(source.includes("missing_executable_identity_outlet_ids"), true);
});

test("managed-core reload is one explicit confirmation with fail-closed recovery copy", () => {
  const source = fs.readFileSync(new URL("../SettingsPage.tsx", import.meta.url), "utf8");
  assert.equal(source.includes("确认并重启核心"), true);
  assert.equal(source.includes("候选校验 → 精确停止自管核心 → 原子提交 → 重启 → Controller/Guardian 权威回读"), true);
  assert.equal(source.includes("失败时恢复最后有效配置，绝不回退 DIRECT"), true);
});

test("settings primary action auto-validates and exposes accessible disabled reasons", () => {
  const source = fs.readFileSync(new URL("../SettingsPage.tsx", import.meta.url), "utf8");
  assert.equal(source.includes("const checked = await requestCurrentPreview()"), true);
  assert.equal(source.includes("settingsPreviewOutcome(checked) === \"live_apply\""), true);
  assert.equal(source.includes("aria-describedby=\"settings-action-reason\""), true);
  assert.equal(source.includes("请从问题摘要跳转到对应字段"), true);
  assert.equal(source.includes("focusValidationField(issue.field)"), true);
});

test("validation focus targets exact dynamic fields before safe section fallbacks", () => {
  assert.deepEqual(settingsValidationTargetIds("connect_timeout_ms"), ["settings-connect_timeout_ms"]);
  assert.deepEqual(settingsValidationTargetIds("recovery_threshold"), ["settings-recovery_threshold"]);
  assert.deepEqual(settingsValidationTargetIds("outlets.local-a.host"), [
    "settings-outlets.local-a.host",
    "settings-outlets",
  ]);
  assert.deepEqual(settingsValidationTargetIds("routing"), ["settings-outlets"]);
  assert.deepEqual(settingsValidationTargetIds("runtime"), ["settings-runtime"]);

  const source = fs.readFileSync(new URL("../SettingsPage.tsx", import.meta.url), "utf8");
  assert.equal(source.includes("validationAttributes(`outlets.${outlet.outlet_id}.label`)"), true);
  assert.equal(source.includes("validationAttributes(`outlets.${outlet.outlet_id}.provider_update_seconds`)"), true);
  assert.equal(source.includes("validationAttributes(`outlets.${outlet.outlet_id}.host`)"), true);
  assert.equal(source.includes("validationAttributes(`outlets.${outlet.outlet_id}.port`)"), true);
  assert.equal(source.includes('field === "routing" || field === "runtime"'), false);
});
