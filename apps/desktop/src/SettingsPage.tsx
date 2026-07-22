import { useEffect, useRef, useState } from "react";
import { ArrowDown, ArrowUp, Eye, Gauge, KeyRound, ListOrdered, Plus, RadioTower, Route, Save, ShieldAlert, ShieldCheck, Trash2 } from "lucide-react";
import { applyEntrySwitch, applySettings, getSettings, getSettingsTerminalStatus, previewEntrySwitch, previewSettings, recoverSettingsTerminal } from "./lib/bridge";
import {
  buildSettingsPreviewRequest,
  createOutletId,
  dispatchOneShotSettingsApply,
  isCurrentPreviewResponse,
  moveItem,
  settingsPreviewOutcome,
  settingsValidationTargetIds,
} from "./lib/settingsModel";
import { buildEntrySwitchFoundationPreview } from "./lib/entrySwitchModel";
import type { CredentialState, LocalProxyProtocol, SafeSettingsView, SettingsDraft, SettingsOutlet, SettingsPreview, SettingsTerminalStatus } from "./types";

interface Props { currentOutletId: string | null; onApplied: () => Promise<void>; onNotice: (message: string) => void }
type PageState = "loading" | "clean" | "dirty" | "checking" | "preview" | "confirm_reload" | "applying" | "success" | "error";
const credentialLabel: Record<CredentialState, string> = { configured: "已配置", missing: "未配置", unavailable: "存储不可用", corrupted: "凭据损坏" };

export function SettingsPage({ currentOutletId, onApplied, onNotice }: Props) {
  const [view, setView] = useState<SafeSettingsView | null>(null);
  const [terminalStatus, setTerminalStatus] = useState<SettingsTerminalStatus>({ active: false, state: null });
  const [draft, setDraft] = useState<SettingsDraft | null>(null);
  const [baseline, setBaseline] = useState("");
  const [credentialIntentById, setCredentialIntentById] = useState<Record<string, "set" | "delete">>({});
  const [replacement, setReplacement] = useState<string | null>(null);
  const [failClosed, setFailClosed] = useState(false);
  const [entrySwitchConfirmed, setEntrySwitchConfirmed] = useState(false);
  const [applySystemProxy, setApplySystemProxy] = useState(false);
  const [entrySwitchTarget, setEntrySwitchTarget] = useState<{ host: string; port: number } | null>(null);
  const [preview, setPreview] = useState<SettingsPreview | null>(null);
  const [pageState, setPageState] = useState<PageState>("loading");
  const [error, setError] = useState<string | null>(null);
  const errorRef = useRef<HTMLDivElement>(null);
  const credentialInputs = useRef(new Map<string, HTMLInputElement>());
  const previewGeneration = useRef(0);
  const operationInFlight = useRef(false);
  const credentialIntentCount = Object.keys(credentialIntentById).length;
  const dirty = draft !== null && (JSON.stringify(draft) !== baseline
    || credentialIntentCount > 0 || replacement !== null || failClosed);

  useEffect(() => { void Promise.all([getSettings(), getSettingsTerminalStatus()]).then(([settings, terminal]) => { setView(settings); setTerminalStatus(terminal); setDraft(settings.draft); setEntrySwitchTarget(settings.draft.entry); setBaseline(JSON.stringify(settings.draft)); setPageState("clean"); }).catch((reason) => { setError(String(reason)); setPageState("error"); }); }, []);
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

  const requestCurrentPreview = async () => {
    if (!draft) return null;
    const request = buildSettingsPreviewRequest(draft, replacement, failClosed, credentialIntentById);
    const generation = ++previewGeneration.current;
    setPageState("checking"); setError(null);
    try {
      const result = await previewSettings(request);
      if (!isCurrentPreviewResponse(generation, previewGeneration.current, request.request_fingerprint, result.request_fingerprint)) return null;
      setPreview(result);
      const outcome = settingsPreviewOutcome(result);
      if (outcome === "error") {
        setError("自动校验发现需要修正的设置。请从问题摘要跳转到对应字段。");
        setPageState("error");
      } else if (outcome === "no_changes") {
        setError("没有可应用的设置变更。");
        setPageState("error");
      } else {
        setPageState(outcome === "confirm_reload" ? "confirm_reload" : "preview");
      }
      return result;
    } catch (reason) {
      if (generation !== previewGeneration.current) return null;
      setError(String(reason)); setPageState("error");
      return null;
    }
  };

  const commitPreview = async (approved: SettingsPreview) => {
    if (!draft || approved.issues.length > 0) return;
    const request = buildSettingsPreviewRequest(draft, replacement, failClosed, credentialIntentById);
    if (request.request_fingerprint !== approved.request_fingerprint) { invalidatePreview(); return; }
    setPageState("applying"); setError(null);
    try {
      const pending = dispatchOneShotSettingsApply({
        draft,
        active_outlet_replacement: replacement,
        fail_closed_on_removed_active: failClosed,
        preview_fingerprint: approved.request_fingerprint,
      }, credentialInputs.current, credentialIntentById, applySettings);
      previewGeneration.current += 1;
      setCredentialIntentById({}); setPreview(null);
      const result = await pending;
      setView(result.settings); setDraft(result.settings.draft); setBaseline(JSON.stringify(result.settings.draft)); setReplacement(null); setFailClosed(false); setPageState("success");
      onNotice(result.managed_core_restarted
        ? `设置已原子应用，自管核心已安全重启并通过权威回读；清理 ${result.removed_history_rows} 条过期历史。`
        : `设置已在线应用；核心未重启，清理 ${result.removed_history_rows} 条过期历史。`);
      try { await onApplied(); } catch { onNotice("设置已应用，但仪表盘刷新失败；请稍后手动刷新。"); }
    } catch (reason) {
      previewGeneration.current += 1; credentialInputs.current.clear(); setCredentialIntentById({}); setPreview(null); setError(String(reason)); setPageState("error");
    }
  };

  const runPreview = async () => {
    if (!dirty || operationInFlight.current) return;
    operationInFlight.current = true;
    try { await requestCurrentPreview(); } finally { operationInFlight.current = false; }
  };

  const runApply = async () => {
    if (!dirty || operationInFlight.current) return;
    operationInFlight.current = true;
    try {
      const request = draft
        ? buildSettingsPreviewRequest(draft, replacement, failClosed, credentialIntentById)
        : null;
      const confirmed = pageState === "confirm_reload" && preview && request
        && preview.request_fingerprint === request.request_fingerprint;
      if (confirmed) {
        await commitPreview(preview);
        return;
      }
      const checked = await requestCurrentPreview();
      if (checked && settingsPreviewOutcome(checked) === "live_apply") await commitPreview(checked);
    } finally {
      operationInFlight.current = false;
    }
  };

  const runTerminalRecovery = async () => {
    if (operationInFlight.current) return;
    operationInFlight.current = true;
    setPageState("applying"); setError(null);
    try {
      const status = await recoverSettingsTerminal();
      setTerminalStatus(status); setPageState("clean");
      onNotice("已通过受鉴权 Controller 确认 MASTER/UDP 双 REJECT；terminal 安全门已解除，自动路由将重新评估。");
      await onApplied();
    } catch (reason) {
      setError(String(reason)); setPageState("error");
    } finally {
      operationInFlight.current = false;
    }
  };

  const runEntrySwitch = async () => {
    if (!entrySwitchTarget || !entrySwitchPreview.executable || operationInFlight.current) return;
    operationInFlight.current = true;
    setPageState("applying"); setError(null);
    try {
      const authorized = await previewEntrySwitch(
        entrySwitchTarget,
        applySystemProxy,
        entrySwitchConfirmed,
      );
      if (!authorized.can_execute || !authorized.authorization) {
        throw new Error(authorized.issues.map((issue) => issue.message).join("；")
          || "入口切换预览未签发执行授权。");
      }
      const result = await applyEntrySwitch({
        target: entrySwitchTarget,
        apply_system_proxy: applySystemProxy,
        authorization: authorized.authorization,
      });
      setView(result.settings);
      setDraft(result.settings.draft);
      setBaseline(JSON.stringify(result.settings.draft));
      setEntrySwitchTarget(result.current_entry);
      setEntrySwitchConfirmed(false);
      setPageState("success");
      onNotice(result.system_proxy_applied
        ? `入口已从 ${result.previous_entry.host}:${result.previous_entry.port} 安全切换到 ${result.current_entry.host}:${result.current_entry.port}，Windows 系统代理已回读确认。`
        : `入口已安全切换到 ${result.current_entry.host}:${result.current_entry.port}；Windows 系统代理保持不变。`);
      await onApplied();
    } catch (reason) {
      setError(String(reason)); setPageState("error");
    } finally {
      operationInFlight.current = false;
    }
  };

  if (!draft || !view) return (
    <main className="settings-view" aria-busy={pageState === "loading"}>
      {error
        ? <div className="settings-error" role="alert"><strong>无法读取设置</strong><span>{error}</span></div>
        : <p className="settings-loading">正在读取安全设置…</p>}
    </main>
  );
  const statusById = new Map(view.credentials.map((status) => [status.subscription_id, status.state]));
  const enabledOutlets = draft.outlets.filter((outlet) => outlet.enabled);
  const currentRequest = buildSettingsPreviewRequest(draft, replacement, failClosed, credentialIntentById);
  const previewMatches = preview?.request_fingerprint === currentRequest.request_fingerprint;
  const busy = pageState === "checking" || pageState === "applying";
  const actionUnavailable = !dirty || busy;
  const actionReason = pageState === "checking"
    ? "正在自动校验草稿；完成前不能重复提交。"
    : pageState === "applying"
      ? "正在应用已校验设置；完成前字段与操作保持锁定。"
      : !dirty
        ? "当前没有待应用的变更。"
        : pageState === "confirm_reload" && previewMatches
          ? "这些变更需要短暂中断连接；再次点击将确认受控重载。"
          : "点击“应用设置”会自动校验；在线变更直接应用，需要重载时再请求确认。";
  const impactLabel = {
    live_apply: "在线应用",
    managed_core_reload: "需核心重载",
    dedicated_transaction: "专用安全事务",
  } as const;
  const focusValidationField = (field: string) => {
    const target = settingsValidationTargetIds(field)
      .map((id) => document.getElementById(id))
      .find((element) => element !== null);
    target?.focus();
  };
  const validationAttributes = (field: string) => {
    const invalid = preview?.issues.some((issue) => issue.field === field
      || (field === "outlets" && issue.field.startsWith("outlets."))) ?? false;
    return {
      id: `settings-${field}`,
      "aria-invalid": invalid || undefined,
      "aria-describedby": invalid ? "settings-validation-summary" : undefined,
    };
  };
  const originalEntry = view.draft.entry;
  const entrySwitchPreview = buildEntrySwitchFoundationPreview(
    originalEntry,
    entrySwitchTarget ?? originalEntry,
    applySystemProxy,
    entrySwitchConfirmed,
  );

  return (
    <main className="settings-view" aria-busy={busy}>
      <header className="settings-header">
        <div className="settings-heading">
          <h1>设置</h1>
          <p>统一入口、动态出口与 Guardian 策略。普通保存不会修改系统代理、TUN、Service 或第三方客户端。</p>
        </div>
        <div className="settings-actions">
          <span className={`settings-stage${pageState === "applying" ? " is-busy" : dirty ? " is-dirty" : ""}`} role="status" aria-live="polite">
            <span className="stage-dot" aria-hidden="true" />
            {pageState === "checking" ? "正在自动校验" : pageState === "applying" ? "正在原子应用" : pageState === "confirm_reload" ? "等待重载确认" : dirty ? "有未应用变更" : pageState === "success" ? "应用成功" : "已同步"}
          </span>
          <button className="secondary-button" type="button" aria-disabled={actionUnavailable} aria-describedby="settings-action-reason" onClick={() => void runPreview()}>
            <Eye />查看变更
          </button>
          <button className="primary-button" type="button" aria-disabled={actionUnavailable} aria-describedby="settings-action-reason" onClick={() => void runApply()}>
            <Save />{pageState === "checking" ? "正在校验…" : pageState === "applying" ? "正在应用…" : pageState === "confirm_reload" && previewMatches ? "确认并重启核心" : "应用设置"}
          </button>
          <p className="settings-action-reason" id="settings-action-reason">{actionReason}</p>
        </div>
      </header>

      {terminalStatus.active && (
        <section className="settings-error" role="alert" aria-label="terminal Fail Closed 安全门">
          <strong>自动路由已锁定为 Fail Closed</strong>
          <span>设置恢复未能证明旧状态完整一致。定时探测和配置重载不会重新选路；只有下方显式恢复会通过受鉴权 Controller 再次确认 MASTER/UDP 双 REJECT 后解除安全门。</span>
          <button className="secondary-button" type="button" disabled={busy} onClick={() => void runTerminalRecovery()}>
            <ShieldCheck />执行受鉴权恢复
          </button>
        </section>
      )}

      {error && <div className="settings-error" ref={errorRef} tabIndex={-1} role="alert"><strong>无法应用</strong><span>{error}</span></div>}

      {preview && (
        <section className="settings-preview" aria-label="设置变更预览">
          <h2>变更预览</h2>
          <ul>
            {preview.diff.changes.map((change) => <li key={change.code}><span className={`impact-badge is-${change.impact}`}>{impactLabel[change.impact]}</span>{change.summary}</li>)}
            {preview.requires_managed_core_restart && <li className="restart-warning">确认后将短暂中断连接：候选校验 → 精确停止自管核心 → 原子提交 → 重启 → Controller/Guardian 权威回读；失败时恢复最后有效配置，绝不回退 DIRECT。</li>}
          </ul>
          {preview.issues.length > 0 && (
            <div id="settings-validation-summary" role="group" aria-label="设置问题摘要">
              <h3>请修正以下问题</h3>
              <ul className="validation-list">{preview.issues.map((issue) => <li key={`${issue.field}-${issue.code}`}><button type="button" onClick={() => focusValidationField(issue.field)}>{issue.message}</button></li>)}</ul>
            </div>
          )}
        </section>
      )}

      <fieldset className="settings-fields" disabled={busy}>
      <section className="settings-card">
        <div className="card-head">
          <div className="card-title">
            <Route aria-hidden="true" />
            <div>
              <h2>统一入口与路由</h2>
              <p>入口地址由 Core 管理，此处只读；路由参数即时预览、原子应用。</p>
            </div>
          </div>
        </div>
        <div className="field-grid">
          <label className="field"><span>当前入口地址</span><input {...validationAttributes("entry")} value={draft.entry.host} readOnly aria-readonly="true" /></label>
          <label className="field"><span>当前入口端口</span><input type="number" value={draft.entry.port} readOnly aria-readonly="true" /></label>
          <label className="field">
            <span>默认模式</span>
            <select {...validationAttributes("route_mode")} value={draft.route_mode} onChange={(event) => changeDraft((current) => ({ ...current, route_mode: event.target.value as SettingsDraft["route_mode"] }))}>
              <option value="priority">按优先级</option>
              <option value="fastest">最低延迟</option>
              <option value="manual">手动</option>
            </select>
          </label>
          <label className="field">
            <span>手动出口</span>
            <select {...validationAttributes("manual_outlet")} value={draft.manual_outlet ?? ""} onChange={(event) => changeDraft((current) => ({ ...current, manual_outlet: event.target.value || null }))}>
              <option value="">未选择</option>
              {enabledOutlets.map((outlet) => <option key={outlet.outlet_id} value={outlet.outlet_id}>{outlet.label}</option>)}
            </select>
          </label>
          <label className="field"><span>冷却时间（秒）</span><input {...validationAttributes("cooldown_seconds")} type="number" min="1" max="86400" value={draft.cooldown_seconds} onChange={(event) => changeDraft((current) => ({ ...current, cooldown_seconds: Number(event.target.value) }))} /></label>
          <label className="field"><span>改善阈值（毫秒）</span><input {...validationAttributes("minimum_improvement_ms")} type="number" min="0" max="60000" value={draft.minimum_improvement_ms} onChange={(event) => changeDraft((current) => ({ ...current, minimum_improvement_ms: Number(event.target.value) }))} /></label>
        </div>
        <label className="field wide-field">
          <span>HTTPS 探测目标（每行一个）</span>
          <textarea {...validationAttributes("probe_targets")} rows={3} value={draft.probe_targets.join("\n")} onChange={(event) => changeDraft((current) => ({ ...current, probe_targets: event.target.value.split(/\r?\n/).map((value) => value.trim()).filter(Boolean) }))} />
        </label>
      </section>

      <section className="settings-card">
        <div className="card-head">
          <div className="card-title">
            <ListOrdered aria-hidden="true" />
            <div>
              <h2>出口</h2>
              <p>排序即优先级。重命名、启用和排序不会改变稳定 ID。</p>
            </div>
          </div>
          <div className="card-actions">
            <button type="button" className="secondary-button" onClick={addSubscription}><Plus />订阅</button>
            <button type="button" className="secondary-button" onClick={addLocal}><Plus />本地出口</button>
          </div>
        </div>
        <div className="settings-outlets" {...validationAttributes("outlets")} tabIndex={-1}>
          {draft.outlets.map((outlet, index) => (
            <article className="settings-outlet" key={outlet.outlet_id}>
              <div className="outlet-rail">
                <span className="outlet-index">{index + 1}</span>
                <button type="button" aria-label={`上移 ${outlet.label}`} disabled={index === 0} onClick={() => changeDraft((current) => ({ ...current, outlets: moveItem(current.outlets, index, -1) }))}><ArrowUp /></button>
                <button type="button" aria-label={`下移 ${outlet.label}`} disabled={index === draft.outlets.length - 1} onClick={() => changeDraft((current) => ({ ...current, outlets: moveItem(current.outlets, index, 1) }))}><ArrowDown /></button>
              </div>
              <div className="outlet-body">
                <div className="outlet-head">
                  <label className="field outlet-name-field"><span>名称</span><input {...validationAttributes(`outlets.${outlet.outlet_id}.label`)} value={outlet.label} onChange={(event) => updateOutlet(index, (current) => ({ ...current, label: event.target.value }))} /></label>
                  <span className={`kind-badge ${outlet.kind === "subscription" ? "is-subscription" : "is-local"}`}>{outlet.kind === "subscription" ? "订阅" : "本地"}</span>
                  <label className="check-field"><input type="checkbox" checked={outlet.enabled} onChange={(event) => updateOutlet(index, (current) => ({ ...current, enabled: event.target.checked }))} />启用</label>
                  <code className="outlet-id" title="稳定出口 ID">{outlet.outlet_id}</code>
                  <button className="outlet-delete" type="button" aria-label={`删除 ${outlet.label}`} onClick={() => removeOutlet(index)}><Trash2 /></button>
                </div>
                {outlet.kind === "subscription" ? (
                  <div className="outlet-detail">
                    <span className={`credential-state ${credentialIntentById[outlet.outlet_id] ? "pending" : statusById.get(outlet.outlet_id) ?? "missing"}`}>
                      <KeyRound />{credentialIntentById[outlet.outlet_id] === "delete" ? "将删除" : credentialIntentById[outlet.outlet_id] === "set" ? "将覆盖" : credentialLabel[statusById.get(outlet.outlet_id) ?? "missing"]}
                    </span>
                    <label className="field credential-input">
                      <span>覆盖订阅凭据</span>
                      <input
                        type="password"
                        autoComplete="off"
                        defaultValue=""
                        ref={(input) => { if (input) credentialInputs.current.set(outlet.outlet_id, input); else credentialInputs.current.delete(outlet.outlet_id); }}
                        placeholder="仅输入新值；不会回显旧值"
                        onChange={(event) => {
                          const hasValue = event.currentTarget.value.length > 0;
                          setCredentialIntentById((current) => { const next = { ...current }; if (hasValue) next[outlet.outlet_id] = "set"; else delete next[outlet.outlet_id]; return next; });
                          invalidatePreview();
                        }}
                      />
                    </label>
                    <label className="field interval-field"><span>更新周期（秒）</span><input {...validationAttributes(`outlets.${outlet.outlet_id}.provider_update_seconds`)} type="number" min="60" value={outlet.provider_update_seconds} onChange={(event) => updateOutlet(index, (current) => current.kind === "subscription" ? { ...current, provider_update_seconds: Number(event.target.value) } : current)} /></label>
                    <button className="text-danger" type="button" onClick={() => { const input = credentialInputs.current.get(outlet.outlet_id); if (input) input.value = ""; setCredentialIntentById((current) => ({ ...current, [outlet.outlet_id]: "delete" })); invalidatePreview(); }}>删除凭据</button>
                  </div>
                ) : (
                  <div className="outlet-detail">
                    <label className="field protocol-field">
                      <span>协议</span>
                      <select value={outlet.protocol} onChange={(event) => updateOutlet(index, (current) => current.kind === "local_proxy" ? { ...current, protocol: event.target.value as LocalProxyProtocol } : current)}>
                        <option value="socks5h">SOCKS5H</option>
                        <option value="socks5">SOCKS5</option>
                        <option value="http">HTTP</option>
                      </select>
                    </label>
                    <label className="field host-field"><span>Loopback 地址</span><input {...validationAttributes(`outlets.${outlet.outlet_id}.host`)} value={outlet.host} onChange={(event) => updateOutlet(index, (current) => current.kind === "local_proxy" ? { ...current, host: event.target.value } : current)} /></label>
                    <label className="field port-field"><span>端口</span><input {...validationAttributes(`outlets.${outlet.outlet_id}.port`)} type="number" min="1" max="65535" value={outlet.port} onChange={(event) => updateOutlet(index, (current) => current.kind === "local_proxy" ? { ...current, port: Number(event.target.value) } : current)} /></label>
                  </div>
                )}
              </div>
            </article>
          ))}
          {draft.outlets.length === 0 && <p className="empty-outlets">尚无出口。正式路由设置应用前至少需要一个启用出口。</p>}
        </div>
      </section>

      <section id="settings-runtime" className="settings-card" tabIndex={-1}>
        <div className="card-head">
          <div className="card-title">
            <Gauge aria-hidden="true" />
            <div>
              <h2>Guardian 与历史</h2>
              <p>健康检查节奏与失败判定阈值，历史数据保留策略。</p>
            </div>
          </div>
        </div>
        <div className="field-grid compact">
          {([
            ["刷新周期（秒）", "refresh_interval_seconds", 5, 86400],
            ["连接超时（毫秒）", "connect_timeout_ms", 1, 120000],
            ["请求超时（毫秒）", "request_timeout_ms", 1, 120000],
            ["失败阈值", "failure_threshold", 1, 100],
            ["恢复阈值", "recovery_threshold", 1, 100],
            ["历史保留（天）", "retention_days", 1, 3650],
          ] as const).map(([label, field, min, max]) => (
            <label className="field" key={field}><span>{label}</span><input {...validationAttributes(field)} type="number" min={min} max={max} value={draft[field]} onChange={(event) => changeDraft((current) => ({ ...current, [field]: Number(event.target.value) }))} /></label>
          ))}
        </div>
      </section>

      <section className="settings-card safety-card" aria-labelledby="entry-switch-title">
        <div className="card-head">
          <div className="card-title">
            <ShieldCheck aria-hidden="true" />
            <div>
              <h2 id="entry-switch-title">安全入口切换</h2>
              <p>当前入口 {originalEntry.host}:{originalEntry.port}。普通“应用设置”不能修改入口或 Windows 系统代理。</p>
            </div>
          </div>
        </div>
        <div className="field-grid">
          <label className="field"><span>目标 loopback 地址</span><input disabled={busy} value={entrySwitchTarget?.host ?? originalEntry.host} onChange={(event) => setEntrySwitchTarget((current) => ({ host: event.target.value, port: current?.port ?? originalEntry.port }))} /></label>
          <label className="field"><span>目标端口</span><input disabled={busy} type="number" min="1" max="65535" value={entrySwitchTarget?.port ?? originalEntry.port} onChange={(event) => setEntrySwitchTarget((current) => ({ host: current?.host ?? originalEntry.host, port: Number(event.target.value) }))} /></label>
        </div>
        <div className="safety-checks">
          <label className="check-field"><input disabled={busy} type="checkbox" checked={applySystemProxy} onChange={(event) => setApplySystemProxy(event.target.checked)} />切换成功后同时应用当前用户的 Windows 系统代理</label>
          <label className="check-field"><input disabled={busy} type="checkbox" checked={entrySwitchConfirmed} onChange={(event) => setEntrySwitchConfirmed(event.target.checked)} />我确认：只有 Controller、出口和 Fail Closed 全部验证通过后才提交入口</label>
        </div>
        <div className="safety-columns">
          <div className="safety-steps">
            <h3>执行步骤</h3>
            <ol>{entrySwitchPreview.steps.map((step) => <li key={step}>{step}</li>)}</ol>
          </div>
          <div className="safety-issues" role="status" aria-live="polite">
            <h3>{entrySwitchPreview.executable ? "本地预检通过" : "当前不可执行"}</h3>
            {entrySwitchPreview.executable
              ? <p>执行时仍会重新检查端口所有权、当前核心与 Windows 系统代理快照。</p>
              : <ul>{entrySwitchPreview.issues.map((issue) => <li key={issue.code}>{issue.message}</li>)}</ul>}
          </div>
        </div>
        <p className="disabled-action-reason" id="entry-switch-unavailable">{busy ? "入口切换事务执行中；字段保持锁定。" : entrySwitchPreview.executable ? "点击后签发一次性授权，并在提交前完成权威二次检查。" : "请先修正上方问题并完成确认。"}</p>
        <button className="primary-button" type="button" disabled={busy || !entrySwitchPreview.executable} aria-disabled={busy || !entrySwitchPreview.executable} aria-describedby="entry-switch-unavailable" onClick={() => void runEntrySwitch()}>{busy ? "正在安全切换…" : "执行安全切换"}</button>
      </section>

      <section className="settings-card safety-card">
        <div className="card-head">
          <div className="card-title">
            <ShieldAlert aria-hidden="true" />
            <div>
              <h2>删除当前出口的安全选择</h2>
              <p>当前出口：{currentOutletId ?? "无（Fail Closed）"}。删除或停用当前出口时请选择替代项，或明确保持 Fail Closed。</p>
            </div>
          </div>
        </div>
        <div className="replacement-row">
          <label className="field replacement-field">
            <span>替代出口</span>
            <select value={replacement ?? ""} onChange={(event) => { setReplacement(event.target.value || null); invalidatePreview(); }}>
              <option value="">未选择</option>
              {enabledOutlets.map((outlet) => <option key={outlet.outlet_id} value={outlet.outlet_id}>{outlet.label}</option>)}
            </select>
          </label>
          <label className="check-field"><input type="checkbox" checked={failClosed} onChange={(event) => { setFailClosed(event.target.checked); invalidatePreview(); }} />没有替代项时明确进入 Fail Closed（绝不 DIRECT）</label>
        </div>
      </section>

      <section className="settings-card tun-card" aria-label="TUN 能力与风险确认">
        <div className="card-head">
          <div className="card-title">
            <RadioTower aria-hidden="true" />
            <div>
              <h2>可选 TUN（当前不可用）</h2>
              <p>默认关闭。当前 Windows 后端尚不能证明按可执行文件身份排除，因此不会启用 TUN、修改路由/DNS/适配器，也不会记录风险确认。</p>
            </div>
          </div>
        </div>
        <div className="safety-checks">
          <label className="check-field"><input type="checkbox" checked={false} disabled aria-describedby="tun-unavailable-reason" />启用 TUN</label>
          <label className="check-field"><input type="checkbox" checked={false} disabled aria-describedby="tun-unavailable-reason" />我已理解断网、DNS 泄漏与递归代理风险</label>
        </div>
        <p className="tun-reason" id="tun-unavailable-reason">当前不可用：<code>{preview?.tun_plan.reason_code ?? "windows_verified_application_identity_exclusion_unavailable"}</code></p>
        {preview && (
          <div className="tun-plan" role="status" aria-live="polite">
            <p>计划 generation：<code>{preview.tun_plan.generation}</code>；订阅出口 {preview.tun_plan.subscription_outlet_ids.length} 个，本地客户端出口 {preview.tun_plan.local_outlet_ids.length} 个。</p>
            {preview.tun_plan.missing_executable_identity_outlet_ids.length > 0 && <p>缺少经校验的本地客户端可执行身份：<code>{preview.tun_plan.missing_executable_identity_outlet_ids.join(", ")}</code>。能力就绪前保持 Fail Closed。</p>}
            <p>GUI/Helper 仅允许 loopback 控制面且外网拒绝；Core 仅限自有上游；登记的本地客户端仅允许最小基础设施 bypass。IPv4/IPv6 × TCP/UDP/DNS 当前全部拒绝直连。</p>
          </div>
        )}
      </section>
      </fieldset>
    </main>
  );
}
