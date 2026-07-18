import { AlertCircle, CheckCircle2, CircleDot } from "lucide-react";
import type { StateEvent } from "../types";

const formatTime = (value: string) => new Intl.DateTimeFormat("zh-CN", { hour: "2-digit", minute: "2-digit", second: "2-digit", hour12: false }).format(new Date(value));

export function EventTimeline({ events }: { events: StateEvent[] }) {
  return (
    <section className="events-panel" aria-labelledby="events-title">
      <h2 id="events-title">最近事件</h2>
      <div className="event-list">
        {events.length === 0 ? <p className="empty-events">还没有状态变化记录</p> : events.slice(0, 4).map((event, index) => {
          const isDown = event.to_status === "down";
          const isRecovery = event.from_status === "down" && event.to_status !== "down";
          const Icon = isDown ? AlertCircle : isRecovery ? CheckCircle2 : CircleDot;
          return (
            <article className={`event-item ${isDown ? "down" : isRecovery ? "recovery" : "info"}`} key={`${event.occurred_at}-${index}`}>
              <span className="event-icon"><Icon aria-hidden="true" /></span>
              <div><strong>超实惠 · {isDown ? "连接超时" : isRecovery ? "连接恢复" : "状态更新"}</strong><p>{event.reason === "request_timeout" ? "代理路径响应超时" : event.reason}</p></div>
              <time>{formatTime(event.occurred_at)}</time>
            </article>
          );
        })}
      </div>
    </section>
  );
}
