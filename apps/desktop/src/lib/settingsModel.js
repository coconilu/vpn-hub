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

export function buildCredentialMutations(values, deletedIds) {
  const mutations = Object.entries(values)
    .filter(([, value]) => value.length > 0)
    .map(([subscription_id, credential]) => ({ subscription_id, action: "set", credential }));
  for (const subscription_id of deletedIds) {
    if (!values[subscription_id]) {
      mutations.push({ subscription_id, action: "delete", credential: null });
    }
  }
  return mutations;
}
