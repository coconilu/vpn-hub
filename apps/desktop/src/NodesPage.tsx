import {
  CheckCircle2,
  CircleAlert,
  Network,
  RefreshCw,
  Search,
  ShieldCheck,
  Zap,
} from "lucide-react";
import { useCallback, useEffect, useMemo, useState } from "react";
import { getSubscriptionNodeCatalog, selectSubscriptionNode } from "./lib/bridge";
import {
  filterSubscriptionNodes,
  replaceSubscriptionNodeGroup,
} from "./lib/subscriptionNodesModel";
import type { SubscriptionNodeCatalog, SubscriptionNodeGroup } from "./types";

function groupStateMessage(group: SubscriptionNodeGroup) {
  if (group.state === "core_unavailable") {
    return "请先在总览中启动本应用自管 Mihomo 核心。不会连接或控制其他代理客户端。";
  }
  if (group.state === "provider_unavailable") {
    return "订阅 provider 尚未返回可选节点。请等待订阅刷新后重试，原选择保持不变。";
  }
  return null;
}

export function NodesPage() {
  const [catalog, setCatalog] = useState<SubscriptionNodeCatalog | null>(null);
  const [activeId, setActiveId] = useState<string | null>(null);
  const [query, setQuery] = useState("");
  const [loading, setLoading] = useState(true);
  const [selecting, setSelecting] = useState<string | null>(null);
  const [error, setError] = useState<string | null>(null);
  const [notice, setNotice] = useState<string | null>(null);

  const load = useCallback(async () => {
    setLoading(true);
    setError(null);
    try {
      const next = await getSubscriptionNodeCatalog();
      setCatalog(next);
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
  const stateMessage = activeGroup ? groupStateMessage(activeGroup) : null;

  const chooseNode = async (nodeName: string) => {
    if (!activeGroup || nodeName === activeGroup.current_node) return;
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

  return (
    <main className="nodes-view">
      <header className="nodes-header">
        <div>
          <span className="eyebrow">SUBSCRIPTION RUNTIME</span>
          <h1>节点选择</h1>
          <p>只管理 VPN Hub 自管 Mihomo 中的订阅节点；节点信息仅停留在当前运行时界面。</p>
        </div>
        <button className="secondary-button" disabled={loading || selecting !== null} onClick={() => void load()} type="button">
          <RefreshCw aria-hidden="true" className={loading ? "is-spinning" : ""} />
          刷新列表
        </button>
      </header>

      {catalog && (
        <div className={`node-privacy-note ${catalog.controller_ready ? "is-ready" : ""}`}>
          <ShieldCheck aria-hidden="true" />
          <span>{catalog.message}</span>
        </div>
      )}
      {error && <div className="node-feedback is-error" role="alert"><CircleAlert aria-hidden="true" />{error}</div>}
      {notice && <div className="node-feedback is-success" role="status"><CheckCircle2 aria-hidden="true" />{notice}</div>}

      {loading && !catalog ? (
        <div className="node-empty"><RefreshCw aria-hidden="true" className="is-spinning" /><p>正在读取本机订阅节点…</p></div>
      ) : !catalog || catalog.subscriptions.length === 0 ? (
        <div className="node-empty"><Network aria-hidden="true" /><h2>暂无可管理的订阅</h2><p>请先在设置中启用订阅并保存有效凭据。</p></div>
      ) : (
        <>
          <section className="node-toolbar" aria-label="节点筛选">
            <label className="node-subscription-field">
              <span>订阅出口</span>
              <select value={activeGroup?.subscription_id ?? ""} onChange={(event) => {
                setActiveId(event.target.value);
                setQuery("");
                setError(null);
                setNotice(null);
              }}>
                {catalog.subscriptions.map((group) => (
                  <option key={group.subscription_id} value={group.subscription_id}>{group.label}</option>
                ))}
              </select>
            </label>
            <label className="node-search-field">
              <Search aria-hidden="true" />
              <span className="sr-only">搜索节点</span>
              <input onChange={(event) => setQuery(event.target.value)} placeholder="搜索节点名称或协议" type="search" value={query} />
            </label>
            <div className="node-current-summary">
              <span>当前节点</span>
              <strong>{activeGroup?.current_node ?? "尚未选择"}</strong>
            </div>
          </section>

          {stateMessage ? (
            <div className="node-empty is-warning"><CircleAlert aria-hidden="true" /><h2>节点列表暂不可用</h2><p>{stateMessage}</p></div>
          ) : visibleNodes.length === 0 ? (
            <div className="node-empty"><Search aria-hidden="true" /><h2>没有匹配节点</h2><p>换一个关键词，或清空搜索条件。</p></div>
          ) : (
            <section className="node-grid" aria-label={`${activeGroup?.label ?? "订阅"}节点列表`}>
              {visibleNodes.map((node) => {
                const selected = node.name === activeGroup?.current_node;
                const busy = selecting === node.name;
                const healthClass = node.alive === true ? "is-healthy" : node.alive === false ? "is-down" : "is-unknown";
                const healthLabel = node.alive === true ? "可用" : node.alive === false ? "不可用" : "未探测";
                return (
                  <button
                    aria-pressed={selected}
                    className={`node-card ${selected ? "is-selected" : ""}`}
                    disabled={selecting !== null}
                    key={node.name}
                    onClick={() => void chooseNode(node.name)}
                    type="button"
                  >
                    <span className="node-card-head">
                      <span className={`node-health ${healthClass}`}><i />{healthLabel}</span>
                      {selected && <span className="node-selected-mark"><CheckCircle2 aria-hidden="true" />当前</span>}
                    </span>
                    <strong title={node.name}>{node.name}</strong>
                    <span className="node-card-meta">
                      <span>{node.proxy_type}</span>
                      <span><Zap aria-hidden="true" />{node.latency_ms === null ? "未测速" : `${node.latency_ms} ms`}</span>
                    </span>
                    <span className="node-card-action">{busy ? "正在确认…" : selected ? "已选择" : "选择此节点"}</span>
                  </button>
                );
              })}
            </section>
          )}
        </>
      )}
    </main>
  );
}
