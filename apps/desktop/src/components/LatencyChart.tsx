import type { LatencySample } from "../types";

const WIDTH = 650;
const HEIGHT = 220;
const PADDING = { left: 48, right: 22, top: 22, bottom: 34 };

const formatTick = (value: string) => new Intl.DateTimeFormat("zh-CN", { hour: "2-digit", minute: "2-digit", hour12: false }).format(new Date(value));

export function LatencyChart({ samples }: { samples: LatencySample[] }) {
  const points = samples.filter((item) => item.outlet_id === "chaoshihui").slice(-36);
  const maxLatency = Math.max(300, ...points.map((point) => point.latency_ms ?? 0));
  const innerWidth = WIDTH - PADDING.left - PADDING.right;
  const innerHeight = HEIGHT - PADDING.top - PADDING.bottom;
  const x = (index: number) => PADDING.left + (points.length <= 1 ? 0 : index / (points.length - 1)) * innerWidth;
  const y = (value: number) => PADDING.top + innerHeight - (value / maxLatency) * innerHeight;
  const segments: string[] = [];
  let current = "";
  points.forEach((point, index) => {
    if (point.latency_ms == null) {
      if (current) segments.push(current);
      current = "";
      return;
    }
    current += `${current ? " L" : "M"}${x(index).toFixed(1)},${y(point.latency_ms).toFixed(1)}`;
  });
  if (current) segments.push(current);
  const yTicks = [0, Math.round(maxLatency / 2), maxLatency];
  const xTicks = points.length ? [0, Math.floor((points.length - 1) / 2), points.length - 1] : [];

  return (
    <section className="chart-panel" aria-labelledby="latency-title">
      <div className="panel-title-row">
        <h2 id="latency-title">延迟趋势</h2>
        <div className="chart-legend"><span className="muted-series">订阅 A</span><span className="active-series">超实惠</span><span className="warning-series">SpeedCat</span></div>
      </div>
      {points.length === 0 ? <div className="empty-chart">运行一次检测后显示延迟样本</div> : (
        <svg className="latency-svg" viewBox={`0 0 ${WIDTH} ${HEIGHT}`} role="img" aria-label="超实惠延迟趋势">
          {yTicks.map((tick) => <g key={tick}><line x1={PADDING.left} x2={WIDTH - PADDING.right} y1={y(tick)} y2={y(tick)} className="grid-line"/><text x={PADDING.left - 10} y={y(tick) + 4} textAnchor="end">{tick}</text></g>)}
          {segments.map((path, index) => <path className="latency-line" d={path} fill="none" key={index} />)}
          {points.map((point, index) => point.latency_ms == null ? <circle className="timeout-dot" cx={x(index)} cy={y(maxLatency * 0.08)} r="3" key={point.observed_at} /> : <circle className="sample-dot" cx={x(index)} cy={y(point.latency_ms)} r="2.6" key={point.observed_at} />)}
          {xTicks.map((tick) => <text className="x-label" x={x(tick)} y={HEIGHT - 8} textAnchor={tick === 0 ? "start" : tick === points.length - 1 ? "end" : "middle"} key={tick}>{formatTick(points[tick].observed_at)}</text>)}
        </svg>
      )}
    </section>
  );
}
