import { AlertCircle, CheckCircle2, CircleDot, Route } from "lucide-react";
import type { RouteSwitchEvent, StateEvent } from "../types";

const formatTime = (value: string) => new Intl.DateTimeFormat("zh-CN", {
  hour: "2-digit", minute: "2-digit", second: "2-digit", hour12: false,
}).format(new Date(value));

type TimelineItem =
  | { kind: "state"; at: string; event: StateEvent }
  | { kind: "switch"; at: string; event: RouteSwitchEvent };

export function EventTimeline({ events, switches }: { events: StateEvent[]; switches: RouteSwitchEvent[] }) {
  const items: TimelineItem[] = [
    ...events.map((event) => ({ kind: "state" as const, at: event.occurred_at, event })),
    ...switches.map((event) => ({ kind: "switch" as const, at: event.occurred_at, event })),
  ].sort((a, b) => b.at.localeCompare(a.at)).slice(0, 4);

  return (
    <section className="events-panel" aria-labelledby="events-title">
      <h2 id="events-title">最近事件</h2>
      <div className="event-list">
        {items.length === 0 ? <p className="empty-events">还没有状态变化或切换记录</p> : items.map((item, index) => {
          if (item.kind === "switch") {
            return (
              <article className="event-item info" key={`switch-${item.at}-${index}`}>
                <span className="event-icon"><Route aria-hidden="true" /></span>
                <div><strong>真实出口切换至 {item.event.to_outlet}</strong><p>{item.event.mode} · {item.event.reason} · {item.event.duration_ms} ms</p></div>
                <time>{formatTime(item.at)}</time>
              </article>
            );
          }
          const isDown = item.event.to_status === "down";
          const isRecovery = item.event.from_status === "down" && item.event.to_status !== "down";
          const Icon = isDown ? AlertCircle : isRecovery ? CheckCircle2 : CircleDot;
          return (
            <article className={`event-item ${isDown ? "down" : isRecovery ? "recovery" : "info"}`} key={`state-${item.at}-${index}`}>
              <span className="event-icon"><Icon aria-hidden="true" /></span>
              <div><strong>{item.event.outlet_id} · {isDown ? "达到失败阈值" : isRecovery ? "达到恢复阈值" : "状态更新"}</strong><p>{item.event.reason}</p></div>
              <time>{formatTime(item.at)}</time>
            </article>
          );
        })}
      </div>
    </section>
  );
}
