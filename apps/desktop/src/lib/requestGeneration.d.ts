export interface LatestRequestGate {
  begin(): number;
  isLatest(candidate: number): boolean;
}

export function createLatestRequestGate(): LatestRequestGate;
