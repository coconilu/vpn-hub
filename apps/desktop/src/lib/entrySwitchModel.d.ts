export interface EntryAddress { host: string; port: number }
export interface EntrySwitchFoundationPreview {
  apply_system_proxy: boolean;
  executable: boolean;
  issues: Array<{ code: string; message: string }>;
  steps: string[];
}
export function buildEntrySwitchFoundationPreview(current: EntryAddress, target: EntryAddress, applySystemProxy: boolean, confirmed: boolean): EntrySwitchFoundationPreview;
