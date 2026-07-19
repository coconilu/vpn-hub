export function createLatestRequestGate() {
  let generation = 0;
  return {
    begin() {
      generation += 1;
      return generation;
    },
    isLatest(candidate) {
      return candidate === generation;
    },
  };
}
