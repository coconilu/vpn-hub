import assert from "node:assert/strict";
import { execFileSync } from "node:child_process";
import { createRequire } from "node:module";
import { dirname, join, resolve } from "node:path";
import { fileURLToPath } from "node:url";
import test from "node:test";
import { normalizeFrontendSbom } from "./sbom-lib.mjs";

const repository = resolve(dirname(fileURLToPath(import.meta.url)), "../..");
const desktop = join(repository, "apps/desktop");
const requireFromDesktop = createRequire(join(desktop, "package.json"));
const { PackageURL } = requireFromDesktop("packageurl-js");
const { JsonValidator } = requireFromDesktop("@cyclonedx/cyclonedx-library/Validation");
const { Version } = requireFromDesktop("@cyclonedx/cyclonedx-library/Spec");
const parsePurl = (value) => PackageURL.fromString(value);

test("official npm scoped PURL keeps namespace and name separate", () => {
  const parsed = parsePurl("pkg:npm/%40angular/animation@12.3.1");
  assert.equal(parsed.namespace, "@angular");
  assert.equal(parsed.name, "animation");
  assert.equal(parsed.version, "12.3.1");
});

test("duplicate package names at different versions remain distinct graph nodes", () => {
  const sbom = fixture([
    component("dep-v1", "one", "1.0.0"),
    component("dep-v2", "one", "2.0.0"),
  ], [
    { ref: "app", dependsOn: ["dep-v2", "dep-v1"] },
    { ref: "dep-v1", dependsOn: [] },
    { ref: "dep-v2", dependsOn: [] },
  ]);
  const normalized = normalizeFrontendSbom(sbom, parsePurl);
  assert.equal(normalized.components.length, 2);
  assert.deepEqual(normalized.dependencies[0].dependsOn, ["dep-v1", "dep-v2"]);
  assert.equal(normalized.compositions[0].aggregate, "complete");
});

test("missing dependency edges are explicitly aggregate incomplete", () => {
  const sbom = fixture([component("known", "one", "1.0.0")], [
    { ref: "app", dependsOn: ["missing"] },
    { ref: "known", dependsOn: [] },
  ]);
  assert.equal(normalizeFrontendSbom(sbom, parsePurl).compositions[0].aggregate, "incomplete");
});

test("official CycloneDX npm validates the real lockfile v3 and emits its resolved graph", async () => {
  const cli = join(desktop, "node_modules/@cyclonedx/cyclonedx-npm/bin/cyclonedx-npm-cli.js");
  const output = execFileSync(process.execPath, [
    cli,
    "--package-lock-only",
    "--flatten-components",
    "--output-reproducible",
    "--validate",
    "--spec-version", "1.6",
    "--output-format", "JSON",
    "--output-file", "-",
  ], { cwd: desktop, encoding: "utf8", maxBuffer: 64 * 1024 * 1024 });
  const normalized = normalizeFrontendSbom(JSON.parse(output), parsePurl);
  assert.ok(normalized.components.length > 0);
  assert.ok(normalized.dependencies.length > 0);
  assert.equal(normalized.compositions[0].aggregate, "complete");
  assert.ok(normalized.components.some((item) => item.purl.startsWith("pkg:npm/%40")));
  assert.equal(await new JsonValidator(Version.v1dot6).validate(JSON.stringify(normalized)), null);
});

function component(ref, name, version) {
  return { type: "library", name, version, "bom-ref": ref, purl: `pkg:npm/${name}@${version}` };
}

function fixture(components, dependencies) {
  return {
    bomFormat: "CycloneDX",
    specVersion: "1.6",
    version: 1,
    metadata: { component: { type: "application", name: "app", version: "1.0.0", "bom-ref": "app" } },
    components,
    dependencies,
  };
}
