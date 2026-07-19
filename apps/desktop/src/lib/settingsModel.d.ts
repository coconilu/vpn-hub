import type { CredentialMutation, SettingsOutlet } from "../types";

export function moveItem(items: SettingsOutlet[], index: number, direction: -1 | 1): SettingsOutlet[];
export function createOutletId(kind: "subscription" | "local", randomId?: string): string;
export function buildCredentialMutations(values: Record<string, string>, deletedIds: Set<string>): CredentialMutation[];
