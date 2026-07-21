export function moveItem(items, index, direction) {
  const nextIndex = index + direction;
  if (nextIndex < 0 || nextIndex >= items.length) return items;
  const result = [...items];
  const [item] = result.splice(index, 1);
  result.splice(nextIndex, 0, item);
  return result;
}

export function createOutletId(kind, randomId = crypto.randomUUID()) {
  return `${kind}-${randomId.toLowerCase().replace(/[^a-z0-9]/g, "").slice(0, 12)}`;
}

export function credentialIntents(intentById) {
  return Object.entries(intentById)
    .filter(([, action]) => action === "set" || action === "delete")
    .map(([subscription_id, action]) => ({ subscription_id, action }))
    .sort((left, right) => left.subscription_id.localeCompare(right.subscription_id)
      || left.action.localeCompare(right.action));
}

export function settingsRequestFingerprint(
  draft,
  activeOutletReplacement,
  failClosedOnRemovedActive,
  intents,
) {
  const canonical = JSON.stringify({
    draft,
    active_outlet_replacement: activeOutletReplacement,
    fail_closed_on_removed_active: failClosedOnRemovedActive,
    credential_intents: [...intents].sort((left, right) =>
      left.subscription_id.localeCompare(right.subscription_id)
      || left.action.localeCompare(right.action)),
  });
  let hash = 0xcbf29ce484222325n;
  for (const byte of new TextEncoder().encode(canonical)) {
    hash ^= BigInt(byte);
    hash = BigInt.asUintN(64, hash * 0x100000001b3n);
  }
  return hash.toString(16).padStart(16, "0");
}

export function buildSettingsPreviewRequest(
  draft,
  activeOutletReplacement,
  failClosedOnRemovedActive,
  intentById,
) {
  const intents = credentialIntents(intentById);
  return {
    draft,
    credential_intents: intents,
    active_outlet_replacement: activeOutletReplacement,
    fail_closed_on_removed_active: failClosedOnRemovedActive,
    request_fingerprint: settingsRequestFingerprint(
      draft,
      activeOutletReplacement,
      failClosedOnRemovedActive,
      intents,
    ),
  };
}

export function isCurrentPreviewResponse(
  startedGeneration,
  currentGeneration,
  currentFingerprint,
  responseFingerprint,
) {
  return startedGeneration === currentGeneration
    && currentFingerprint === responseFingerprint;
}

export function settingsPreviewOutcome(preview) {
  if (preview.issues.length > 0) return "error";
  if (!preview.can_apply) return "no_changes";
  if (preview.requires_managed_core_restart) return "confirm_reload";
  return "live_apply";
}

export function settingsValidationTargetIds(field) {
  if (field === "routing") return ["settings-outlets"];
  if (field === "runtime") return ["settings-runtime"];
  const exact = `settings-${field}`;
  return field.startsWith("outlets.")
    ? [exact, "settings-outlets"]
    : [exact];
}

export function takeCredentialMutations(inputById, intentById) {
  const intents = credentialIntents(intentById);
  const setIds = new Set(intents
    .filter((intent) => intent.action === "set")
    .map((intent) => intent.subscription_id));
  const credentialById = new Map();
  for (const [subscriptionId, input] of inputById) {
    if (setIds.has(subscriptionId)) credentialById.set(subscriptionId, input.value);
    input.value = "";
  }
  inputById.clear();
  const mutations = [];
  for (const intent of intents) {
    if (intent.action === "set") {
      const credential = credentialById.get(intent.subscription_id) ?? "";
      if (credential.length === 0) {
        throw new Error("覆盖订阅凭据时必须输入新值");
      }
      mutations.push({ ...intent, credential });
    } else {
      mutations.push({ ...intent, credential: null });
    }
  }
  return mutations;
}

export function consumeSettingsPreviewTicket(currentTicket, requestedFingerprint) {
  if (currentTicket !== requestedFingerprint) {
    throw new Error("设置预览已失效或已被使用，请重新预览");
  }
  return null;
}

export function dispatchOneShotSettingsApply(
  requestWithoutCredentials,
  inputById,
  intentById,
  dispatch,
) {
  const credential_mutations = takeCredentialMutations(inputById, intentById);
  return dispatch({ ...requestWithoutCredentials, credential_mutations });
}
