import {
  CheckCircle2,
  CircleAlert,
  Gauge,
  Network,
  RefreshCw,
  Search,
  ShieldCheck,
  Square,
  Zap,
} from "lucide-react";
import { useCallback, useEffect, useMemo, useState } from "react";
import {
  cancelSubscriptionNodeLatencyBatch,
  getSubscriptionNodeCatalog,
  retrySubscriptionProvider,
  selectSubscriptionNode,
  testSubscriptionNodeLatencies,
  testSubscriptionNodeLatency,
} from "./lib/bridge";
import {
  batchStartingLatencyStates,
  filterSubscriptionNodes,
  initialNodeLatencyState,
  latencyResultToView,
  mergeBatchLatencyResults,
  nodePageCapabilities,
  nodeLatencyKey,
  replaceSubscriptionNodeGroup,
  subscriptionNodeGroupMessage,
} from "./lib/subscriptionNodesModel";
import type {
  NodeLatencyErrorCode,
  NodeLatencyViewState,
  SubscriptionNode,
  SubscriptionNodeCatalog,
} from "./types";

const errorLabel: Record<NodeLatencyErrorCode, string> = {
  core_unavailable: "隔离探测不可用",
  provider_unavailable: "Provider 未就绪",
  node_disappeared: "节点已消失",
  timeout: "测速超时",
  controller_error: "Controller 异常",
  cancelled: "已取消",
};

function latencyPresentation(node: SubscriptionNode, state?: NodeLatencyViewState) {
  const current = state ?? initialNodeLatencyState(node);
  if (current.status === "success") return { className: "is-success", label: `${current.latency_ms} ms`, detail: "本次测试" };
  if (current.status === "running") return { className: "is-running", label: "测试中", detail: "正在使用受控探测目标" };
  if (current.status === "failure") return { className: "is-failure", label: current.error_code ? errorLabel[current.error_code] : "测试失败", detail: current.message };
  if (current.status === "cancelled") return { className: "is-cancelled", label: "已取消", detail: current.message };
  if (current.status === "stale") return { className: "is-stale", label: current.latency_ms === null ? "已过期" : `${current.latency_ms} ms`, detail: "最近状态 · 已过期" };
  return { className: "is-waiting", label: "等待首次测试", detail: current.message };
}

export function NodesPage() {
  const [catalog, setCatalog] = useState<SubscriptionNodeCatalog | null>(null);
  const [activeId, setActiveId] = useState<string | null>(null);
  const [query, setQuery] = useState("");
  const [loading, setLoading] = useState(true);
  const [retryingProvider, setRetryingProvider] = useState(false);
  const [selecting, setSelecting] = useState<string | null>(null);
  const [testingNode, setTestingNode] = useState<string | null>(null);
  const [batchOperation, setBatchOperation] = useState<string | null>(null);
  const [cancelling, setCancelling] = useState(false);
  const [latencyStates, setLatencyStates] = useState<Record<string, NodeLatencyViewState>>({});
  const [error, setError] = useState<string | null>(null);
  const [notice, setNotice] = useState<string | null>(null);

  const load = useCallback(async () => {
    setLoading(true);
    setError(null);
    setNotice(null);
    try {
      const next = await getSubscriptionNodeCatalog();
      setCatalog(next);
      setLatencyStates((current) => {
        const refreshed: Record<string, NodeLatencyViewState> = {};
        for (const group of next.subscriptions) {
          for (const node of group.nodes) {
            const key = nodeLatencyKey(group.subscription_id, node.name);
            const previous = current[key];
            refreshed[key] = previous && previous.status !== "waiting"
              ? { ...previous, status: "stale", message: "刷新状态后需要重新主动测速" }
              : initialNodeLatencyState(node);
          }
        }
        return refreshed;
      });
      setActiveId((current) => (
        next.subscriptions.some((group) => group.subscription_id === current)
          ? current
          : next.subscriptions[0]?.subscription_id ?? null
      ));
    } catch (loadError) {
      setError(String(loadError));
    } finally {
      setLoading(false);
    }
  }, []);

  useEffect(() => {
    void load();
  }, [load]);

  const activeGroup = catalog?.subscriptions.find(
    (group) => group.subscription_id === activeId,
  ) ?? catalog?.subscriptions[0] ?? null;
  const visibleNodes = useMemo(
    () => filterSubscriptionNodes(activeGroup?.nodes ?? [], query),
    [activeGroup, query],
  );
  const stateMessage = subscriptionNodeGroupMessage(activeGroup);
  const capabilities = nodePageCapabilities(catalog, activeGroup);
  const testing = testingNode !== null || batchOperation !== null;
  const busy = loading || selecting !== null || testing || retryingProvider;

  const retryProvider = async () => {
    if (!activeGroup || busy) return;
    setRetryingProvider(true);
    setError(null);
    setNotice(null);
    try {
      const updated = await retrySubscriptionProvider(activeGroup.subscription_id);
      setCatalog((current) => current ? replaceSubscriptionNodeGroup(current, updated) : current);
      setNotice(updated.state === "provider_failed"
        ? "Provider 重试已明确失败；可稍后再次重试。"
        : "Provider 重试已提交，正在后台加载；无需再次保存配置。");
    } catch (retryError) {
      setError(String(retryError));
    } finally {
      setRetryingProvider(false);
    }
  };

  const chooseNode = async (nodeName: string) => {
    if (!activeGroup || nodeName === activeGroup.current_node || testing) return;
    setSelecting(nodeName);
    setError(null);
    setNotice(null);
    try {
      const updated = await selectSubscriptionNode(activeGroup.subscription_id, nodeName);
      setCatalog((current) => (
        current ? replaceSubscriptionNodeGroup(current, updated) : current
      ));
      setNotice("节点已通过本机 Mihomo Controller 切换，并重新读取确认当前状态。");
    } catch (selectionError) {
      setError(String(selectionError));
    } finally {
      setSelecting(null);
    }
  };

  const testOne = async (nodeName: string) => {
    if (!activeGroup || busy) return;
    const subscriptionId = activeGroup.subscription_id;
    const key = nodeLatencyKey(subscriptionId, nodeName);
    setTestingNode(nodeName);
    setError(null);
    setNotice(null);
    setLatencyStates((current) => ({
      ...current,
      [key]: { status: "running", latency_ms: null, tested_at: null, error_code: null, message: "正在测试" },
    }));
    try {
      const result = await testSubscriptionNodeLatency(subscriptionId, nodeName);
      setLatencyStates((current) => ({ ...current, [key]: latencyResultToView(result) }));
      setNotice(result.message);
    } catch (testError) {
      setLatencyStates((current) => ({
        ...current,
        [key]: { status: "failure", latency_ms: null, tested_at: new Date().toISOString(), error_code: "controller_error", message: "Controller 响应异常，测速结果已拒绝" },
      }));
      setError(String(testError));
    } finally {
      setTestingNode(null);
    }
  };

  const testAll = async () => {
    if (!activeGroup || busy || activeGroup.state !== "available") return;
    const subscriptionId = activeGroup.subscription_id;
    const operationId = crypto.randomUUID();
    const nodes = activeGroup.nodes;
    const starting = batchStartingLatencyStates(nodes);
    setBatchOperation(operationId);
    setError(null);
    setNotice(null);
    setLatencyStates((current) => {
      const next = { ...current };
      for (const node of nodes) next[nodeLatencyKey(subscriptionId, node.name)] = starting[node.name];
      return next;
    });
    try {
      const result = await testSubscriptionNodeLatencies(subscriptionId, operationId);
      const merged = mergeBatchLatencyResults(nodes, result);
      setLatencyStates((current) => {
        const next = { ...current };
        for (const node of nodes) next[nodeLatencyKey(subscriptionId, node.name)] = merged[node.name];
        return next;
      });
      setNotice(result.message);
    } catch (batchError) {
      setLatencyStates((current) => {
        const next = { ...current };
        for (const node of nodes) {
          next[nodeLatencyKey(subscriptionId, node.name)] = { status: "failure", latency_ms: null, tested_at: new Date().toISOString(), error_code: "controller_error", message: "Controller 响应异常，测速结果已拒绝" };
        }
        return next;
      });
      setError(String(batchError));
    } finally {
      setBatchOperation(null);
      setCancelling(false);
    }
  };

  const cancelBatch = async () => {
    if (!batchOperation || cancelling) return;
    setCancelling(true);
    setError(null);
    try {
      const accepted = await cancelSubscriptionNodeLatencyBatch(batchOperation);
      if (!accepted) setError("批量测速已经结束，无需取消");
    } catch (cancelError) {
      setError(String(cancelError));
      setCancelling(false);
    }
  };

  return (
    <main className="nodes-view">
      <header className="nodes-header">
        <div>
          <span className="eyebrow">SUBSCRIPTION RUNTIME</span>
          <h1>节点选择</h1>
          <p>主动测速不会切换节点；结果与节点名称只停留在当前运行时界面。</p>
        </div>
        <div className="nodes-header-actions">
          {batchOperation ? (
            <button className="danger-button" disabled={cancelling} onClick={() => void cancelBatch()} type="button">
              <Square aria-hidden="true" />{cancelling ? "正在取消…" : "取消批量测速"}
            </button>
          ) : (
            <button className="primary-button" disabled={busy || !capabilities.canTest} onClick={() => void testAll()} type="button">
              <Gauge aria-hidden="true" />测试全部
            </button>
          )}
          <button className="secondary-button" disabled={busy || !capabilities.canRefresh} onClick={() => void load()} type="button">
            <RefreshCw aria-hidden="true" className={loading ? "spin" : ""} />刷新状态
          </button>
        </div>
      </header>

      {catalog && (
        <div className={`node-privacy-note ${catalog.controller_ready ? "is-ready" : ""}`}>
          <ShieldCheck aria-hidden="true" /><span>{catalog.message}</span>
        </div>
      )}
      {error && <div className="node-feedback is-error" role="alert"><CircleAlert aria-hidden="true" />{error}</div>}
      {notice && <div aria-live="polite" className="node-feedback is-success" role="status"><CheckCircle2 aria-hidden="true" />{notice}</div>}

      {loading && !catalog ? (
        <div className="node-empty"><RefreshCw aria-hidden="true" className="spin" /><p>正在读取本机订阅节点…</p></div>
      ) : !catalog || catalog.subscriptions.length === 0 ? (
        <div className="node-empty"><Network aria-hidden="true" /><h2>暂无可管理的订阅</h2><p>请先在设置中启用订阅并保存有效凭据。</p></div>
      ) : (
        <>
          <section className="node-toolbar" aria-label="节点筛选">
            <label className="node-subscription-field">
              <span>订阅出口</span>
              <select disabled={testing} value={activeGroup?.subscription_id ?? ""} onChange={(event) => {
                setActiveId(event.target.value);
                setQuery("");
                setError(null);
                setNotice(null);
              }}>
                {catalog.subscriptions.map((group) => <option key={group.subscription_id} value={group.subscription_id}>{group.label}</option>)}
              </select>
            </label>
            <label className="node-search-field">
              <Search aria-hidden="true" /><span className="sr-only">搜索节点</span>
              <input onChange={(event) => setQuery(event.target.value)} placeholder="搜索节点名称或协议" type="search" value={query} />
            </label>
            <div className="node-current-summary">
              <span>当前节点（测速不会改变）</span>
              <strong>{capabilities.currentNodeLabel}</strong>
            </div>
          </section>

          {stateMessage ? (
            <div className="node-empty is-warning"><CircleAlert aria-hidden="true" /><h2>节点列表暂不可用</h2><p>{stateMessage}</p>{activeGroup?.state !== "core_unavailable" && activeGroup?.state !== "controller_error" && <button className="secondary-button" disabled={retryingProvider} onClick={() => void retryProvider()} type="button"><RefreshCw aria-hidden="true" className={retryingProvider ? "spin" : ""} />{retryingProvider ? "正在提交重试…" : "重试 Provider"}</button>}</div>
          ) : visibleNodes.length === 0 ? (
            <div className="node-empty"><Search aria-hidden="true" /><h2>没有匹配节点</h2><p>换一个关键词，或清空搜索条件。</p></div>
          ) : (
            <section className="node-grid" aria-label={`${activeGroup?.label ?? "订阅"}节点列表`}>
              {visibleNodes.map((node) => {
                const selected = node.name === activeGroup?.current_node;
                const selectingThis = selecting === node.name;
                const state = latencyStates[nodeLatencyKey(activeGroup!.subscription_id, node.name)];
                const latency = latencyPresentation(node, state);
                const testedAt = state?.tested_at ? new Date(state.tested_at).toLocaleTimeString([], { hour: "2-digit", minute: "2-digit", second: "2-digit" }) : null;
                return (
                  <article className={`node-card ${selected ? "is-selected" : ""}`} key={node.name}>
                    <div className="node-card-head">
                      <span className={`node-latency-state ${latency.className}`}><i />{latency.label}</span>
                      {selected && <span className="node-selected-mark"><CheckCircle2 aria-hidden="true" />当前</span>}
                    </div>
                    <strong title={node.name}>{node.name}</strong>
                    <div className="node-card-meta"><span>{node.proxy_type}</span><span title={latency.detail}><Zap aria-hidden="true" />{testedAt ?? latency.detail}</span></div>
                    <div className="node-card-actions">
                      <button aria-label={`重测 ${node.name}`} className="secondary-button node-test-button" disabled={busy} onClick={() => void testOne(node.name)} type="button">
                        <Gauge aria-hidden="true" />{testingNode === node.name ? "测试中…" : "单节点重测"}
                      </button>
                      <button aria-pressed={selected} className="node-select-button" disabled={busy || selected || !capabilities.canSelect} onClick={() => void chooseNode(node.name)} type="button">
                        {selectingThis ? "正在确认…" : selected ? "已选择" : capabilities.selectNodeLabel}
                      </button>
                    </div>
                  </article>
                );
              })}
            </section>
          )}
        </>
      )}
    </main>
  );
}
