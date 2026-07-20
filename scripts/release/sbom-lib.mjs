export function normalizeFrontendSbom(sbom, parsePurl) {
  if (sbom?.bomFormat !== "CycloneDX" || sbom?.specVersion !== "1.6") {
    throw new Error("CycloneDX npm generator returned an unexpected schema");
  }
  const normalized = structuredClone(sbom);
  delete normalized.serialNumber;
  if (normalized.metadata) delete normalized.metadata.timestamp;

  const components = Array.isArray(normalized.components) ? normalized.components : [];
  for (const component of components) {
    if (typeof component.purl !== "string") throw new Error("npm component is missing a PURL");
    const parsed = parsePurl(component.purl);
    if (parsed.type !== "npm" || parsed.name !== component.name || (parsed.namespace ?? "") !== (component.group ?? "")) {
      throw new Error(`npm PURL does not preserve scope/name segments: ${component.purl}`);
    }
  }
  components.sort((left, right) => left["bom-ref"].localeCompare(right["bom-ref"]));

  const rootRef = normalized.metadata?.component?.["bom-ref"];
  const knownRefs = new Set([rootRef, ...components.map((component) => component["bom-ref"])]);
  const dependencies = Array.isArray(normalized.dependencies) ? normalized.dependencies : [];
  for (const dependency of dependencies) {
    dependency.dependsOn = [...(dependency.dependsOn ?? [])].sort();
  }
  dependencies.sort((left, right) => left.ref.localeCompare(right.ref));
  const dependencyRefs = new Set(dependencies.map((dependency) => dependency.ref));
  const complete =
    typeof rootRef === "string" &&
    dependencyRefs.has(rootRef) &&
    [...knownRefs].every((ref) => typeof ref === "string" && dependencyRefs.has(ref)) &&
    dependencies.every(
      (dependency) => knownRefs.has(dependency.ref) && dependency.dependsOn.every((ref) => knownRefs.has(ref)),
    );
  normalized.components = components;
  normalized.dependencies = dependencies;
  normalized.compositions = [{ aggregate: complete ? "complete" : "incomplete", assemblies: [rootRef].filter(Boolean) }];
  return normalized;
}
