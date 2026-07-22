import type { CredentialMutation, CredentialMutationIntent, SettingsApplyRequest, SettingsDraft, SettingsOutlet, SettingsPreview, SettingsPreviewRequest } from "../types";

export function moveItem(items: SettingsOutlet[], index: number, direction: -1 | 1): SettingsOutlet[];
export function createOutletId(kind: "subscription" | "local", randomId?: string): string;
export type CredentialIntentAction = "set" | "delete";
export function credentialIntents(intentById: Record<string, CredentialIntentAction>): CredentialMutationIntent[];
export function settingsRequestFingerprint(draft: SettingsDraft, activeOutletReplacement: string | null, failClosedOnRemovedActive: boolean, intents: CredentialMutationIntent[]): string;
export function buildSettingsPreviewRequest(draft: SettingsDraft, activeOutletReplacement: string | null, failClosedOnRemovedActive: boolean, intentById: Record<string, CredentialIntentAction>): SettingsPreviewRequest;
export function isCurrentPreviewResponse(startedGeneration: number, currentGeneration: number, currentFingerprint: string, responseFingerprint: string): boolean;
export function settingsPreviewOutcome(preview: SettingsPreview): "error" | "no_changes" | "live_apply";
export function settingsValidationTargetIds(field: string): string[];
export function takeCredentialMutations(inputById: Map<string, Pick<HTMLInputElement, "value">>, intentById: Record<string, CredentialIntentAction>): CredentialMutation[];
export function consumeSettingsPreviewTicket(currentTicket: string | null, requestedFingerprint: string): null;
export function dispatchOneShotSettingsApply<R>(requestWithoutCredentials: Omit<SettingsApplyRequest, "credential_mutations">, inputById: Map<string, Pick<HTMLInputElement, "value">>, intentById: Record<string, CredentialIntentAction>, dispatch: (request: SettingsApplyRequest) => Promise<R>): Promise<R>;
