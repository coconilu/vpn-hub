import assert from "node:assert/strict";
import { readFile } from "node:fs/promises";
import test from "node:test";

test("Guardian event triggers an immediate snapshot reload and retains polling fallback", async () => {
  const source = await readFile(new URL("../App.tsx", import.meta.url), "utf8");
  assert.match(source, /listen<[^>]+>\(\s*"guardian:\/\/updated"/s);
  assert.match(source, /\(\) => void load\(\)/);
  assert.match(source, /setInterval\(\(\) => void load\(\), 15_000\)/);
  assert.match(source, /unlisten\?\.\(\)/);
});
