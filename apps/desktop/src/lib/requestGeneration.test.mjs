import assert from "node:assert/strict";
import test from "node:test";
import { createLatestRequestGate } from "./requestGeneration.js";

const deferred = () => {
  let resolve;
  const promise = new Promise((done) => { resolve = done; });
  return { promise, resolve };
};

test("an older completion cannot overwrite the latest history request", async () => {
  const gate = createLatestRequestGate();
  const first = deferred();
  const second = deferred();
  let committed = null;

  const run = async (request) => {
    const generation = gate.begin();
    const value = await request.promise;
    if (gate.isLatest(generation)) committed = value;
  };
  const firstRun = run(first);
  const secondRun = run(second);
  second.resolve("new-filter-result");
  await secondRun;
  first.resolve("stale-filter-result");
  await firstRun;

  assert.equal(committed, "new-filter-result");
});
