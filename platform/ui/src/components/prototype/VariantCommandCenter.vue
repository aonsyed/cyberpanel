<script setup lang="ts">
// PROTOTYPE Variant B — "Command Center": dense three-column mission-control
// layout. Left rail = live metrics strip; center = hero status + services
// matrix; right = activity/alert feed. Structurally opposite of the card-grid
// dashboard: information-dense, terminal-inspired, minimal chrome.
import { PhActivity as Activity, PhArrowClockwise as ArrowClockwise, PhBell as Bell, PhCheckCircle as CheckCircle, PhCpu as Cpu, PhDatabase as Database, PhGauge as Gauge, PhHardDrives as HardDrives, PhPulse as Pulse, PhWarning as Warning } from "@phosphor-icons/vue";

defineProps<{
  node: Record<string, unknown>;
  metrics: Array<{ name?: string; label?: string; value?: number; unit?: string; available?: boolean; complete?: boolean; missing_reason?: string; observed_at?: string }>;
  usage: Array<{ dimension?: string; used?: number; limit?: number; unit?: string; available?: boolean; limit_state?: string; updated_at?: string }>;
  services: Array<Record<string, unknown>>;
  alerts: Array<Record<string, unknown>>;
  loading: boolean;
}>();

function text(value: unknown, fallback = "—"): string { return value === undefined || value === null || value === "" ? fallback : String(value); }
function humanize(value: unknown): string { return text(value, "unknown").replaceAll("_", " "); }
function metricValue(metric: { available?: boolean; value?: number; unit?: string }): string {
  if (!metric.available || !Number.isFinite(metric.value)) return "—";
  const value = Number(metric.value);
  if (metric.unit === "percent") return `${value.toFixed(value >= 10 ? 0 : 1)}%`;
  if (metric.unit === "ratio") return `${(value * 100).toFixed(value >= .1 ? 0 : 1)}%`;
  if (metric.unit === "bytes" || metric.unit === "bytes_per_second") return formatBytes(value) + (metric.unit === "bytes_per_second" ? "/s" : "");
  return new Intl.NumberFormat(undefined, { maximumFractionDigits: 2 }).format(value);
}
function formatBytes(value: number): string {
  if (!Number.isFinite(value) || value < 0) return "—";
  const units = ["B", "K", "M", "G", "T", "P"];
  let amount = value, index = 0;
  while (amount >= 1024 && index < units.length - 1) { amount /= 1024; index++; }
  return `${amount >= 10 || index === 0 ? amount.toFixed(0) : amount.toFixed(1)}${units[index]}`;
}
function barPercent(item: { used?: number; limit?: number; available?: boolean }): number {
  if (!item.available || !Number.isFinite(Number(item.used)) || !Number.isFinite(Number(item.limit)) || Number(item.limit) === 0) return 0;
  return Math.min(100, (Number(item.used) / Number(item.limit)) * 100);
}
function barTone(item: { limit_state?: string }): string {
  const state = String(item.limit_state || "").toLowerCase();
  if (state.includes("crit") || state.includes("exceed")) return "critical";
  if (state.includes("warn") || state.includes("near")) return "warning";
  return "healthy";
}
</script>

<template>
  <main class="cc">
    <!-- Left rail: metric strip -->
    <aside class="cc-rail">
      <header><Pulse :size="16"/><span>LIVE</span></header>
      <div v-for="(metric, index) in metrics.slice(0, 8)" :key="metric.name || metric.label || index" class="cc-metric">
        <span class="cc-metric-label">{{ text(metric.label, 'Metric') }}</span>
        <strong class="cc-metric-value">{{ loading ? '··' : metricValue(metric) }}</strong>
        <div class="cc-metric-bar"><i :class="metric.available ? 'on' : ''"/></div>
      </div>
      <div v-if="!loading && !metrics.length" class="cc-rail-empty">No telemetry published.</div>
    </aside>

    <!-- Center: node hero + services matrix -->
    <section class="cc-main">
      <header class="cc-hero">
        <div>
          <p class="cc-eyebrow">{{ text(node.hostname, 'LOCAL NODE') }} · {{ humanize(node.health) }}</p>
          <h2>Command<br/>Center</h2>
        </div>
        <button class="cc-refresh" type="button" :disabled="loading"><ArrowClockwise :size="15" :class="{ spinning: loading }"/></button>
      </header>

      <div class="cc-usage-strip">
        <div v-for="(item, index) in usage.slice(0, 5)" :key="item.dimension || index" class="cc-usage">
          <span>{{ humanize(item.dimension) }}</span>
          <div class="cc-bar-track"><div class="cc-bar-fill" :class="`tone-${barTone(item)}`" :style="{ width: barPercent(item) + '%' }"/></div>
          <small>{{ formatBytes(Number(item.used ?? 0)) }} / {{ formatBytes(Number(item.limit ?? 0)) }}</small>
        </div>
        <div v-if="!loading && !usage.length" class="cc-rail-empty">No usage collector output.</div>
      </div>

      <div class="cc-services">
        <p class="cc-section-label">FUNCTIONAL HEALTH MATRIX</p>
        <div class="cc-service-grid">
          <div v-for="(item, index) in services.slice(0, 12)" :key="index" class="cc-service" :class="`health-${text(item.health, 'unknown').toLowerCase()}`">
            <i/><span>{{ text(item.name) }}</span>
          </div>
          <div v-if="!loading && !services.length" class="cc-rail-empty">No cached service observation.</div>
        </div>
      </div>
    </section>

    <!-- Right: activity feed -->
    <aside class="cc-feed">
      <header><Bell :size="15"/><span>ACTIVITY</span><CheckCircle v-if="!alerts.length && !loading" :size="14"/></header>
      <div v-if="loading" class="cc-feed-loading"><span v-for="i in 5" :key="i" class="skeleton" style="height:18px"/></div>
      <template v-else>
        <article v-for="(item, index) in alerts.slice(0, 8)" :key="index" class="cc-alert">
          <i :class="`severity-${text(item.severity, 'info').toLowerCase()}`"/>
          <div>
            <strong>{{ text(item.subject) }}</strong>
            <small>{{ humanize(item.kind) }} · {{ text(item.updated_at, '') }}</small>
          </div>
        </article>
        <div v-if="!alerts.length" class="cc-feed-clear">
          <CheckCircle :size="22"/>
          <span>All clear — no alerts require attention.</span>
        </div>
      </template>
    </aside>
  </main>
</template>

<style scoped>
.cc{display:grid;grid-template-columns:200px minmax(0,1fr) 260px;gap:0;min-height:calc(100dvh - var(--topbar))}
/* Left rail */
.cc-rail{border-right:1px solid var(--border);background:var(--bg-raised);padding:16px 14px;display:flex;flex-direction:column;gap:14px}
.cc-rail header{display:flex;align-items:center;gap:7px;color:var(--accent);font:600 9px/1 var(--font-mono);letter-spacing:.14em;padding-bottom:10px;border-bottom:1px solid var(--border)}
.cc-metric{display:grid;gap:4px}
.cc-metric-label{font-size:10px;color:var(--subtle);text-transform:uppercase;letter-spacing:.06em;font-weight:600}
.cc-metric-value{font:600 20px/1 var(--font-mono);letter-spacing:-.03em}
.cc-metric-bar{height:2px;background:var(--surface-2);border-radius:1px;overflow:hidden}
.cc-metric-bar i{display:block;height:100%;width:20%;background:var(--surface-3)}
.cc-metric-bar i.on{background:var(--accent);box-shadow:0 0 4px var(--accent-glow)}
.cc-rail-empty{color:var(--subtle);font-size:11px;padding:14px 0;line-height:1.5}
/* Center */
.cc-main{padding:28px 30px;display:flex;flex-direction:column;gap:22px;overflow:auto}
.cc-hero{display:flex;justify-content:space-between;align-items:flex-start}
.cc-eyebrow{margin:0 0 8px;color:var(--subtle);font:600 10px/1 var(--font-mono);letter-spacing:.12em}
.cc-hero h2{margin:0;font-size:clamp(38px,4vw,56px);line-height:.95;letter-spacing:-.055em;font-weight:750}
.cc-refresh{width:36px;height:36px;border:1px solid var(--border);border-radius:var(--radius-sm);background:var(--surface);color:var(--muted);display:grid;place-items:center;cursor:pointer}
.cc-usage-strip{display:grid;grid-template-columns:repeat(auto-fit,minmax(160px,1fr));gap:16px;padding:18px;border:1px solid var(--border);border-radius:var(--radius-lg);background:var(--surface)}
.cc-usage{display:grid;gap:6px}
.cc-usage>span{font-size:10px;color:var(--subtle);text-transform:capitalize;font-weight:600}
.cc-usage small{color:var(--subtle);font:500 10px/1 var(--font-mono)}
.cc-bar-track{height:4px;background:var(--surface-2);border-radius:2px;overflow:hidden}
.cc-bar-fill{height:100%;border-radius:2px;transition:width .3s ease}
.tone-healthy{background:var(--healthy)}
.tone-warning{background:var(--warning)}
.tone-critical{background:var(--critical)}
.cc-section-label{margin:0 0 10px;color:var(--subtle);font:600 9px/1 var(--font-mono);letter-spacing:.14em}
.cc-service-grid{display:grid;grid-template-columns:repeat(auto-fill,minmax(150px,1fr));gap:6px}
.cc-service{display:flex;align-items:center;gap:9px;padding:9px 12px;border:1px solid var(--border);border-radius:var(--radius-sm);background:var(--surface);font-size:11px;transition:border-color .12s ease}
.cc-service:hover{border-color:var(--border-bright)}
.cc-service i{width:7px;height:7px;border-radius:50%;flex:0 0 auto}
.health-healthy i,.health-active i,.health-ready i{background:var(--healthy);box-shadow:0 0 5px var(--healthy)}
.health-warning i,.health-degraded i,.health-pending i{background:var(--warning);box-shadow:0 0 5px var(--warning)}
.health-critical i,.health-failed i,.health-offline i{background:var(--critical);box-shadow:0 0 5px var(--critical)}
.health-unknown i{background:var(--subtle)}
/* Right feed */
.cc-feed{border-left:1px solid var(--border);background:var(--bg-raised);padding:16px;display:flex;flex-direction:column;gap:0}
.cc-feed header{display:flex;align-items:center;gap:7px;color:var(--subtle);font:600 9px/1 var(--font-mono);letter-spacing:.14em;padding-bottom:12px;border-bottom:1px solid var(--border);margin-bottom:8px}
.cc-feed header svg:last-child{margin-left:auto;color:var(--healthy)}
.cc-alert{display:flex;gap:10px;padding:10px 4px;border-bottom:1px solid var(--border)}
.cc-alert i{width:6px;height:6px;border-radius:50%;margin-top:5px;flex:0 0 auto}
.severity-critical,.severity-error{background:var(--critical)}
.severity-warning{background:var(--warning)}
.severity-info{background:var(--info)}
.cc-alert div{display:grid;gap:3px}
.cc-alert strong{font-size:11px;line-height:1.3}
.cc-alert small{color:var(--subtle);font-size:9px}
.cc-feed-clear{display:grid;place-items:center;gap:10px;padding:40px 16px;color:var(--subtle);text-align:center}
.cc-feed-clear svg{color:var(--healthy)}
.cc-feed-clear span{font-size:11px;line-height:1.5}
.cc-feed-loading{display:grid;gap:8px;padding:8px 0}
.spinning{animation:spin .8s linear infinite}@keyframes spin{to{transform:rotate(1turn)}}
@media(max-width:1100px){.cc{grid-template-columns:1fr}.cc-rail{flex-direction:row;overflow-x:auto;border-right:0;border-bottom:1px solid var(--border)}.cc-feed{border-left:0;border-top:1px solid var(--border)}}
</style>
