import { useEffect, useRef, useState } from "react";
import { ArrowDown, ArrowUp, Eye, KeyRound, Plus, Save, Trash2 } from "lucide-react";
import { applySettings, getSettings, previewSettings } from "./lib/bridge";
import {
  buildSettingsPreviewRequest,
  createOutletId,
  dispatchOneShotSettingsApply,
  isCurrentPreviewResponse,
  moveItem,
} from "./lib/settingsModel";
import type { CredentialState, LocalProxyProtocol, SafeSettingsView, SettingsDraft, SettingsOutlet, SettingsPreview } from "./types";

interface Props { currentOutletId: string | null; onApplied: () => Promise<void>; onNotice: (message: string) => void }
type PageState = "loading" | "clean" | "dirty" | "preview" | "applying" | "success" | "error";
const credentialLabel: Record<CredentialState, string> = { configured: "已配置", missing: "未配置", unavailable: "存储不可用", corrupted: "凭据损坏" };

export function SettingsPage({ currentOutletId, onApplied, onNotice }: Props) {
  const [view, setView] = useState<SafeSettingsView | null>(null);
  const [draft, setDraft] = useState<SettingsDraft | null>(null);
  const [baseline, setBaseline] = useState("");
  const [credentialIntentById, setCredentialIntentById] = useState<Record<string, "set" | "delete">>({});
  const [replacement, setReplacement] = useState<string | null>(null);
  const [failClosed, setFailClosed] = useState(false);
  const [preview, setPreview] = useState<SettingsPreview | null>(null);
  const [pageState, setPageState] = useState<PageState>("loading");
  const [error, setError] = useState<string | null>(null);
  const errorRef = useRef<HTMLDivElement>(null);
  const credentialInputs = useRef(new Map<string, HTMLInputElement>());
  const previewGeneration = useRef(0);
  const credentialIntentCount = Object.keys(credentialIntentById).length;
  const dirty = draft !== null && (JSON.stringify(draft) !== baseline
    || credentialIntentCount > 0 || replacement !== null || failClosed);

  useEffect(() => { void getSettings().then((settings) => { setView(settings); setDraft(settings.draft); setBaseline(JSON.stringify(settings.draft)); setPageState("clean"); }).catch((reason) => { setError(String(reason)); setPageState("error"); }); }, []);
  useEffect(() => { if (pageState === "error") errorRef.current?.focus(); }, [pageState]);

  const invalidatePreview = () => {
    previewGeneration.current += 1; setPreview(null); setError(null); setPageState("dirty");
  };
  const changeDraft = (update: (current: SettingsDraft) => SettingsDraft) => {
    setDraft((current) => current ? update(current) : current); invalidatePreview();
  };
  const updateOutlet = (index: number, update: (outlet: SettingsOutlet) => SettingsOutlet) => changeDraft((current) => ({ ...current, outlets: current.outlets.map((outlet, itemIndex) => itemIndex === index ? update(outlet) : outlet) }));
  const addSubscription = () => changeDraft((current) => ({ ...current, outlets: [...current.outlets, { kind: "subscription", outlet_id: createOutletId("subscription"), label: "新订阅", enabled: true, provider_update_seconds: 180 }] }));
  const addLocal = () => {
    const count = draft?.outlets.filter((outlet) => outlet.kind === "local_proxy").length ?? 0;
    changeDraft((current) => ({ ...current, outlets: [...current.outlets, { kind: "local_proxy", outlet_id: createOutletId("local"), label: "新本地出口", enabled: true, protocol: "socks5h", host: "127.0.0.1", port: 2666 + count }] }));
  };
  const removeOutlet = (index: number) => {
    const id = draft?.outlets[index]?.outlet_id; if (!id) return;
    const input = credentialInputs.current.get(id); if (input) input.value = ""; credentialInputs.current.delete(id);
    setCredentialIntentById((current) => { const next = { ...current }; delete next[id]; return next; });
    changeDraft((current) => ({ ...current, manual_outlet: current.manual_outlet === id ? null : current.manual_outlet, outlets: current.outlets.filter((_, itemIndex) => itemIndex !== index) }));
  };

  const runPreview = async () => {
    if (!draft) return;
    const request = buildSettingsPreviewRequest(draft, replacement, failClosed, credentialIntentById);
    const generation = ++previewGeneration.current;
    setPageState("preview"); setError(null);
    try {
      const result = await previewSettings(request);
      if (!isCurrentPreviewResponse(generation, previewGeneration.current, request.request_fingerprint, result.request_fingerprint)) return;
      setPreview(result);
      if (result.issues.length > 0) { setError("预览发现需要修正的设置。所有问题已在下方列出。"); setPageState("error"); }
    }
    catch (reason) {
      if (generation !== previewGeneration.current) return;
      setError(String(reason)); setPageState("error");
    }
  };
  const runApply = async () => {
    if (!draft || !preview || preview.issues.length > 0) return;
    const request = buildSettingsPreviewRequest(draft, replacement, failClosed, credentialIntentById);
    if (request.request_fingerprint !== preview.request_fingerprint) { invalidatePreview(); return; }
    setPageState("applying"); setError(null);
    try {
      const pending = dispatchOneShotSettingsApply({
        draft,
        active_outlet_replacement: replacement,
        fail_closed_on_removed_active: failClosed,
        preview_fingerprint: preview.request_fingerprint,
      }, credentialInputs.current, credentialIntentById, applySettings);
      previewGeneration.current += 1;
      setCredentialIntentById({}); setPreview(null);
      const result = await pending;
      setView(result.settings); setDraft(result.settings.draft); setBaseline(JSON.stringify(result.settings.draft)); setReplacement(null); setFailClosed(false); setPageState("success");
      onNotice(`设置已原子应用；清理 ${result.removed_history_rows} 条过期历史。`); await onApplied();
    } catch (reason) { previewGeneration.current += 1; credentialInputs.current.clear(); setCredentialIntentById({}); setPreview(null); setError(String(reason)); setPageState("error"); }
  };

  if (!draft || !view) return <main className="settings-view" aria-busy="true"><p className="settings-loading">正在读取安全设置…</p></main>;
  const statusById = new Map(view.credentials.map((status) => [status.subscription_id, status.state]));
  const enabledOutlets = draft.outlets.filter((outlet) => outlet.enabled);
  const currentRequest = buildSettingsPreviewRequest(draft, replacement, failClosed, credentialIntentById);
  const canApply = preview !== null && preview.issues.length === 0
    && preview.request_fingerprint === currentRequest.request_fingerprint
    && (preview.diff.changes.length > 0 || credentialIntentCount > 0);

  return <main className="settings-view">
    <header className="settings-header"><div><h1>设置</h1><p>统一入口、动态出口与 Guardian 策略。普通保存不会修改系统代理、TUN、Service 或第三方客户端。</p></div><div className="settings-actions">
      <span className={`settings-stage ${dirty ? "dirty" : ""}`} role="status" aria-live="polite">{pageState === "applying" ? "正在原子应用" : dirty ? "有未应用变更" : pageState === "success" ? "应用成功" : "已同步"}</span>
      <button className="secondary-button" type="button" disabled={!dirty || pageState === "applying"} onClick={() => void runPreview()}><Eye />预览变更</button>
      <button className="primary-button" type="button" disabled={!canApply || pageState === "applying"} onClick={() => void runApply()}><Save />应用设置</button>
    </div></header>
    {error && <div className="settings-error" ref={errorRef} tabIndex={-1} role="alert"><strong>无法应用</strong><span>{error}</span></div>}
    {preview && <section className="settings-preview" aria-label="设置变更预览"><h2>变更预览</h2><ul>{preview.diff.changes.map((change) => <li key={change.code}>{change.summary}</li>)}{credentialIntentCount > 0 && <li>将更新 {credentialIntentCount} 个凭据状态；预览不读取或回显凭据。</li>}</ul>{preview.issues.length > 0 && <ul className="validation-list">{preview.issues.map((issue) => <li key={`${issue.field}-${issue.code}`}>{issue.message}</li>)}</ul>}</section>}

    <section className="settings-card"><h2>统一入口与路由</h2><div className="settings-grid">
      <label>入口地址<input value={draft.entry.host} onChange={(event) => changeDraft((current) => ({ ...current, entry: { ...current.entry, host: event.target.value } }))} /></label>
      <label>入口端口<input type="number" min="1" max="65535" value={draft.entry.port} onChange={(event) => changeDraft((current) => ({ ...current, entry: { ...current.entry, port: Number(event.target.value) } }))} /></label>
      <label>默认模式<select value={draft.route_mode} onChange={(event) => changeDraft((current) => ({ ...current, route_mode: event.target.value as SettingsDraft["route_mode"] }))}><option value="priority">按优先级</option><option value="fastest">最低延迟</option><option value="manual">手动</option></select></label>
      <label>手动出口<select value={draft.manual_outlet ?? ""} onChange={(event) => changeDraft((current) => ({ ...current, manual_outlet: event.target.value || null }))}><option value="">未选择</option>{enabledOutlets.map((outlet) => <option key={outlet.outlet_id} value={outlet.outlet_id}>{outlet.label}</option>)}</select></label>
      <label>冷却时间（秒）<input type="number" min="1" max="86400" value={draft.cooldown_seconds} onChange={(event) => changeDraft((current) => ({ ...current, cooldown_seconds: Number(event.target.value) }))} /></label>
      <label>改善阈值（毫秒）<input type="number" min="0" max="60000" value={draft.minimum_improvement_ms} onChange={(event) => changeDraft((current) => ({ ...current, minimum_improvement_ms: Number(event.target.value) }))} /></label>
    </div><label className="wide-field">HTTPS 探测目标（每行一个）<textarea rows={3} value={draft.probe_targets.join("\n")} onChange={(event) => changeDraft((current) => ({ ...current, probe_targets: event.target.value.split(/\r?\n/).map((value) => value.trim()).filter(Boolean) }))} /></label></section>

    <section className="settings-card"><h2>Guardian 与历史</h2><div className="settings-grid compact">
      {([ ["刷新周期（秒）", "refresh_interval_seconds", 5, 86400], ["连接超时（毫秒）", "connect_timeout_ms", 1, 120000], ["请求超时（毫秒）", "request_timeout_ms", 1, 120000], ["失败阈值", "failure_threshold", 1, 100], ["恢复阈值", "recovery_threshold", 1, 100], ["历史保留（天）", "retention_days", 1, 3650] ] as const).map(([label, field, min, max]) => <label key={field}>{label}<input type="number" min={min} max={max} value={draft[field]} onChange={(event) => changeDraft((current) => ({ ...current, [field]: Number(event.target.value) }))} /></label>)}
    </div></section>

    <section className="settings-card" aria-label="TUN 能力与风险确认">
      <h2>可选 TUN（当前不可用）</h2>
      <p>默认关闭。当前 Windows 后端尚不能证明按可执行文件身份排除，因此不会启用 TUN、修改路由/DNS/适配器，也不会记录风险确认。</p>
      <div className="settings-grid compact">
        <label className="check-field"><input type="checkbox" checked={false} disabled />启用 TUN</label>
        <label className="check-field"><input type="checkbox" checked={false} disabled />我已理解断网、DNS 泄漏与递归代理风险</label>
      </div>
      <p><code>{preview?.tun_plan.reason_code ?? "windows_verified_application_identity_exclusion_unavailable"}</code></p>
      {preview && <div role="status" aria-live="polite">
        <p>计划 generation：<code>{preview.tun_plan.generation}</code>；订阅出口 {preview.tun_plan.subscription_outlet_ids.length} 个，本地客户端出口 {preview.tun_plan.local_outlet_ids.length} 个。</p>
        {preview.tun_plan.missing_executable_identity_outlet_ids.length > 0 && <p>缺少经校验的本地客户端可执行身份：<code>{preview.tun_plan.missing_executable_identity_outlet_ids.join(", ")}</code>。能力就绪前保持 Fail Closed。</p>}
        <p>GUI/Helper 仅允许 loopback 控制面且外网拒绝；Core 仅限自有上游；登记的本地客户端仅允许最小基础设施 bypass。IPv4/IPv6 × TCP/UDP/DNS 当前全部拒绝直连。</p>
      </div>}
    </section>

    <section className="settings-card outlets-card"><div className="outlets-heading"><div><h2>出口</h2><p>排序即优先级。重命名、启用和排序不会改变稳定 ID。</p></div><div><button type="button" className="secondary-button" onClick={addSubscription}><Plus />订阅</button><button type="button" className="secondary-button" onClick={addLocal}><Plus />本地出口</button></div></div>
      <div className="settings-outlets">{draft.outlets.map((outlet, index) => <article className="settings-outlet" key={outlet.outlet_id}>
        <div className="outlet-order"><span>{index + 1}</span><button type="button" aria-label={`上移 ${outlet.label}`} disabled={index === 0} onClick={() => changeDraft((current) => ({ ...current, outlets: moveItem(current.outlets, index, -1) }))}><ArrowUp /></button><button type="button" aria-label={`下移 ${outlet.label}`} disabled={index === draft.outlets.length - 1} onClick={() => changeDraft((current) => ({ ...current, outlets: moveItem(current.outlets, index, 1) }))}><ArrowDown /></button></div>
        <div className="outlet-fields"><div className="outlet-title-row"><label>名称<input value={outlet.label} onChange={(event) => updateOutlet(index, (current) => ({ ...current, label: event.target.value }))} /></label><label className="check-field"><input type="checkbox" checked={outlet.enabled} onChange={(event) => updateOutlet(index, (current) => ({ ...current, enabled: event.target.checked }))} />启用</label><code title="稳定出口 ID">{outlet.outlet_id}</code></div>
        {outlet.kind === "subscription" ? <div className="credential-row"><span className={`credential-state ${statusById.get(outlet.outlet_id) ?? "missing"}`}><KeyRound />{credentialIntentById[outlet.outlet_id] === "delete" ? "将删除" : credentialIntentById[outlet.outlet_id] === "set" ? "将覆盖" : credentialLabel[statusById.get(outlet.outlet_id) ?? "missing"]}</span><label>覆盖订阅凭据<input type="password" autoComplete="off" defaultValue="" ref={(input) => { if (input) credentialInputs.current.set(outlet.outlet_id, input); else credentialInputs.current.delete(outlet.outlet_id); }} placeholder="仅输入新值；不会回显旧值" onChange={(event) => { const hasValue = event.currentTarget.value.length > 0; setCredentialIntentById((current) => { const next = { ...current }; if (hasValue) next[outlet.outlet_id] = "set"; else delete next[outlet.outlet_id]; return next; }); invalidatePreview(); }} /></label><label>更新周期（秒）<input type="number" min="60" value={outlet.provider_update_seconds} onChange={(event) => updateOutlet(index, (current) => current.kind === "subscription" ? { ...current, provider_update_seconds: Number(event.target.value) } : current)} /></label><button className="text-danger" type="button" onClick={() => { const input = credentialInputs.current.get(outlet.outlet_id); if (input) input.value = ""; setCredentialIntentById((current) => ({ ...current, [outlet.outlet_id]: "delete" })); invalidatePreview(); }}>删除凭据</button></div>
        : <div className="local-fields"><label>协议<select value={outlet.protocol} onChange={(event) => updateOutlet(index, (current) => current.kind === "local_proxy" ? { ...current, protocol: event.target.value as LocalProxyProtocol } : current)}><option value="socks5h">SOCKS5H</option><option value="socks5">SOCKS5</option><option value="http">HTTP</option></select></label><label>Loopback 地址<input value={outlet.host} onChange={(event) => updateOutlet(index, (current) => current.kind === "local_proxy" ? { ...current, host: event.target.value } : current)} /></label><label>端口<input type="number" min="1" max="65535" value={outlet.port} onChange={(event) => updateOutlet(index, (current) => current.kind === "local_proxy" ? { ...current, port: Number(event.target.value) } : current)} /></label></div>}</div>
        <button className="outlet-delete" type="button" aria-label={`删除 ${outlet.label}`} onClick={() => removeOutlet(index)}><Trash2 /></button>
      </article>)}{draft.outlets.length === 0 && <p className="empty-outlets">尚无出口。正式路由设置应用前至少需要一个启用出口。</p>}</div>
    </section>

    <section className="settings-card fail-closed-card"><h2>删除当前出口的安全选择</h2><p>当前出口：{currentOutletId ?? "无（Fail Closed）"}。删除或停用当前出口时请选择替代项，或明确保持 Fail Closed。</p><label>替代出口<select value={replacement ?? ""} onChange={(event) => { setReplacement(event.target.value || null); invalidatePreview(); }}><option value="">未选择</option>{enabledOutlets.map((outlet) => <option key={outlet.outlet_id} value={outlet.outlet_id}>{outlet.label}</option>)}</select></label><label className="check-field"><input type="checkbox" checked={failClosed} onChange={(event) => { setFailClosed(event.target.checked); invalidatePreview(); }} />没有替代项时明确进入 Fail Closed（绝不 DIRECT）</label></section>
  </main>;
}
