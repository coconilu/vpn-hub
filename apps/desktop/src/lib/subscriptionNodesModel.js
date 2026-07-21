export function filterSubscriptionNodes(nodes, query) {
  const needle = query.trim().toLowerCase();
  if (!needle) return nodes;
  return nodes.filter((node) => (
    node.name.toLowerCase().includes(needle)
      || node.proxy_type.toLowerCase().includes(needle)
  ));
}

export function replaceSubscriptionNodeGroup(catalog, updatedGroup) {
  return {
    ...catalog,
    subscriptions: catalog.subscriptions.map((group) => (
      group.subscription_id === updatedGroup.subscription_id ? updatedGroup : group
    )),
  };
}
