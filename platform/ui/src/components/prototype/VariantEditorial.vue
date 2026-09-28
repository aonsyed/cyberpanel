<script setup lang="ts">
// PROTOTYPE Variant C — "Editorial": typography-driven, generous whitespace,
// no cards or boxes — just well-typeset sections with hairline dividers.
// Think Vercel meets Stripe: the numbers ARE the interface.
import { PhArrowUpRight as ArrowUpRight, PhCheckCircle as CheckCircle, PhWarning as Warning } from "@phosphor-icons/vue";

defineProps<{
  node: Record<string, unknown>;
  metrics: Array<{ name?: string; label?: string; value?: number; unit?: string; available?: boolean; complete?: boolean; missing_reason?: string }>;
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
  if (metric.unit === "percent") return `${value.toFixed(0)}`;
  if (metric.unit === "ratio") return `${(value * 100).toFixed(0)}`;
  if (metric.unit === "bytes" || metric.unit === "bytes_per_second") return formatBytes(value);
  return new Intl.NumberFormat(undefined, { maximumFractionDigits: 1 }).format(value);
}
function metricUnit(metric: { unit?: string }): string {
  if (metric.unit === "percent" || metric.unit === "ratio") return "%";
  if (metric.unit === "bytes_per_second") return "/s";
  if (metric.unit === "bytes") return "B";
  return metric.unit || "";
}
function formatBytes(value: number): string {
  if (!Number.isFinite(value) || value < 0) return "—";
  const units = ["B", "K", "M", "G", "T"];
  let amount = value, index = 0;
  while (amount >= 1024 && index < units.length - 1) { amount /= 1024; index++; }
  return `${amount >= 10 || index === 0 ? amount.toFixed(0) : amount.toFixed(1)}`;
}
function ratio(item: { used?: number; limit?: number; available?: boolean }): number {
  if (!item.available || !Number.isFinite(Number(item.used)) || !Number.isFinite(Number(item.limit)) || Number(item.limit) === 0) return 0;
  return Number(item.used) / Number(item.limit);
}
</script>

<template>
  <main class="ed">
    <!-- Masthead -->
    <header class="ed-mast">
      <p class="ed-eyebrow">{{ text(node.hostname, 'Local node') }} — operational overview</p>
    </header>

    <!-- Hero metrics — typeset as a broadsheet front page -->
    <section class="ed-hero">
      <article v-for="(metric, index) in metrics.slice(0, 4)" :key="metric.name || metric.label || index" class="ed-stat">
        <span class="ed-stat-label">{{ text(metric.label, 'Metric') }}</span>
        <div class="ed-stat-row">
          <strong class="ed-stat-value">{{ loading ? '—' : metricValue(metric) }}</strong>
          <em v-if="metricUnit(metric)" class="ed-stat-unit">{{ metricUnit(metric) }}</em>
        </div>
        <span class="ed-stat-note">{{ metric.available ? (metric.complete ? 'Complete interval' : 'Partial interval') : humanize(metric.missing_reason) }}</span>
      </article>
      <article v-if="!loading && !metrics.length" class="ed-stat ed-stat-empty">
        <span class="ed-stat-label">Telemetry</span>
        <strong class="ed-stat-value">—</strong>
        <span class="ed-stat-note">No metric series has been published.</span>
      </article>
    </section>

    <hr class="ed-rule"/>

    <!-- Two-column body: usage ledger + service list -->
    <section class="ed-body">
      <div class="ed-col">
        <h3 class="ed-heading">Usage & limits</h3>
        <dl class="ed-usage">
          <div v-for="(item, index) in usage.slice(0, 8)" :key="item.dimension || index" class="ed-usage-row">
            <dt>{{ humanize(item.dimension) }}</dt>
            <dd>
              <span class="ed-usage-used">{{ formatBytes(Number(item.used ?? 0)) }}</span>
              <span class="ed-usage-sep">of</span>
              <span class="ed-usage-limit">{{ formatBytes(Number(item.limit ?? 0)) }}</span>
              <span class="ed-usage-pct" :class="{ critical: ratio(item) > .85, warning: ratio(item) > .7 && ratio(item) <= .85 }">{{ (ratio(item) * 100).toFixed(0) }}%</span>
            </dd>
          </div>
        </dl>
        <p v-if="!loading && !usage.length" class="ed-empty-note">The materialized usage collector has not published this tenant.</p>
      </div>

      <div class="ed-col">
        <h3 class="ed-heading">Managed services</h3>
        <ul class="ed-services">
          <li v-for="(item, index) in services.slice(0, 10)" :key="index">
            <span class="ed-service-name">{{ text(item.name) }}</span>
            <span class="ed-service-state" :class="`tone-${text(item.health, 'unknown').toLowerCase()}`">{{ humanize(item.health) }}</span>
          </li>
        </ul>
        <p v-if="!loading && !services.length" class="ed-empty-note">No cached service observation is available.</p>
      </div>
    </section>

    <hr class="ed-rule"/>

    <!-- Alerts as footnotes -->
    <section class="ed-footnotes">
      <h3 class="ed-heading">Alert inbox</h3>
      <ul v-if="alerts.length" class="ed-alerts">
        <li v-for="(item, index) in alerts.slice(0, 5)" :key="index">
          <Warning v-if="String(item.severity).toLowerCase().includes('warn') || String(item.severity).toLowerCase().includes('crit')" :size="14" class="ed-alert-warn"/>
          <CheckCircle v-else :size="14" class="ed-alert-ok"/>
          <div><strong>{{ text(item.subject) }}</strong><small>{{ humanize(item.kind) }} · {{ text(item.updated_at) }}</small></div>
          <span class="ed-alert-sev">{{ text(item.severity, 'info') }}</span>
        </li>
      </ul>
      <p v-else class="ed-empty-note">No delivered alerts. <a href="/alerts" class="ed-link">Open the inbox <ArrowUpRight :size="12"/></a></p>
    </section>
  </main>
</template>

<style scoped>
.ed{max-width:1200px;margin:0 auto;padding:44px clamp(20px,4vw,64px) 80px}

/* Masthead */
.ed-mast{margin-bottom:36px}
.ed-eyebrow{margin:0;color:var(--subtle);font:400 13px/1.4 var(--font);letter-spacing:.01em}

/* Hero stats — the front page */
.ed-hero{display:grid;grid-template-columns:repeat(4,1fr);gap:0;border-top:2px solid var(--text)}
.ed-stat{padding:20px 20px 24px 0;display:flex;flex-direction:column;gap:8px}
.ed-stat + .ed-stat{padding-left:24px;border-left:1px solid var(--border)}
.ed-stat-label{font-size:11px;color:var(--subtle);font-weight:550;text-transform:uppercase;letter-spacing:.06em}
.ed-stat-row{display:flex;align-items:baseline;gap:4px}
.ed-stat-value{font:300 clamp(40px,4.5vw,64px)/1 var(--font);letter-spacing:-.05em}
.ed-stat-unit{font:400 16px/1 var(--font);color:var(--subtle);font-style:normal}
.ed-stat-note{font-size:11px;color:var(--faint)}

/* Rules */
.ed-rule{border:0;border-top:1px solid var(--border);margin:36px 0}

/* Body columns */
.ed-body{display:grid;grid-template-columns:1fr 1fr;gap:48px}
.ed-heading{margin:0 0 18px;font-size:13px;font-weight:650;letter-spacing:.02em;color:var(--muted);text-transform:uppercase}
.ed-usage{margin:0;display:flex;flex-direction:column}
.ed-usage-row{display:flex;align-items:baseline;justify-content:space-between;padding:11px 0;border-bottom:1px solid var(--border)}
.ed-usage-row:last-child{border-bottom:0}
.ed-usage dt{font-size:13px;color:var(--text);font-weight:450}
.ed-usage dd{margin:0;display:flex;align-items:baseline;gap:6px;font-family:var(--font-mono);font-size:12px}
.ed-usage-used{font-weight:600;color:var(--text)}
.ed-usage-sep{color:var(--faint);font-family:var(--font);font-size:11px}
.ed-usage-limit{color:var(--muted)}
.ed-usage-pct{margin-left:8px;font-weight:600;color:var(--muted)}
.ed-usage-pct.warning{color:var(--warning)}
.ed-usage-pct.critical{color:var(--critical)}

.ed-services{list-style:none;margin:0;padding:0;display:flex;flex-direction:column}
.ed-services li{display:flex;align-items:baseline;justify-content:space-between;padding:10px 0;border-bottom:1px solid var(--border)}
.ed-services li:last-child{border-bottom:0}
.ed-service-name{font-size:13px}
.ed-service-state{font:500 11px/1 var(--font-mono);text-transform:capitalize}
.tone-healthy,.tone-active,.tone-ready{color:var(--healthy)}
.tone-warning,.tone-degraded,.tone-pending{color:var(--warning)}
.tone-critical,.tone-failed,.tone-offline{color:var(--critical)}
.tone-unknown{color:var(--subtle)}

/* Footnotes (alerts) */
.ed-footnotes .ed-heading{margin-bottom:14px}
.ed-alerts{list-style:none;margin:0;padding:0;display:flex;flex-direction:column}
.ed-alerts li{display:flex;align-items:flex-start;gap:10px;padding:12px 0;border-bottom:1px solid var(--border)}
.ed-alerts li:last-child{border-bottom:0}
.ed-alerts svg{margin-top:2px;flex:0 0 auto}
.ed-alert-ok{color:var(--healthy)}
.ed-alert-warn{color:var(--warning)}
.ed-alerts div{display:grid;gap:3px;flex:1}
.ed-alerts strong{font-size:13px}
.ed-alerts small{color:var(--subtle);font-size:11px}
.ed-alert-sev{font:500 10px/1 var(--font-mono);text-transform:uppercase;color:var(--subtle);margin-top:3px}
.ed-empty-note{color:var(--subtle);font-size:13px;margin:0;line-height:1.6}
.ed-link{color:var(--accent);display:inline-flex;align-items:center;gap:3px;font-weight:550}
.ed-empty-note .ed-link{margin-left:6px}

@media(max-width:1000px){.ed-hero{grid-template-columns:repeat(2,1fr)}.ed-stat + .ed-stat:nth-child(3){padding-left:0;border-left:0}.ed-body{grid-template-columns:1fr;gap:32px}}
@media(max-width:640px){.ed-hero{grid-template-columns:1fr}.ed-stat + .ed-stat{padding-left:0;border-left:0;padding-top:16px;border-top:1px solid var(--border)}}
</style>
