<script setup lang="ts">
import { computed, inject, onMounted, ref } from "vue";
import { PhArrowClockwise, PhChartLineUp, PhHardDrives, PhPulse, PhSpeedometer } from "@phosphor-icons/vue";
import type { APIClient } from "../api";
import { sessionStore } from "../store";
import Sparkline from "./Sparkline.vue";

const api = inject<APIClient>("api")!;
const loading = ref(true);
const metrics = ref<Array<{ name?: string; label?: string; value?: number; unit?: string; available?: boolean }>>([]);
const usage = ref<Array<{ dimension?: string; used?: number; limit?: number; unit?: string; available?: boolean }>>([]);

const tenantId = computed(() => sessionStore.state.tenantId || undefined);
onMounted(() => void load());

async function load(): Promise<void> {
  loading.value = true;
  try {
    if (api.available("observability.dashboard.get")) {
      const response = await api.invoke<unknown>("observability.dashboard.get", { tenantId: tenantId.value, payload: {} });
      const result = response.result;
      if (result && typeof result === "object") {
        const r = result as Record<string, unknown>;
        const m = r.metrics;
        const u = r.usage;
        metrics.value = Array.isArray(m) ? m as typeof metrics.value : [];
        usage.value = Array.isArray(u) ? u as typeof usage.value : [];
      }
    }
  } catch { /* show empty */ }
  finally { loading.value = false; }
}

function fmtVal(metric: { available?: boolean; value?: number; unit?: string }): string {
  if (!metric.available || !Number.isFinite(metric.value)) return "—";
  const v = Number(metric.value);
  if (metric.unit === "percent") return `${v.toFixed(v >= 10 ? 0 : 1)}%`;
  if (metric.unit === "ratio") return `${(v * 100).toFixed(0)}%`;
  if (metric.unit === "bytes" || metric.unit === "bytes_per_second") return fmtBytes(v) + (metric.unit === "bytes_per_second" ? "/s" : "");
  return new Intl.NumberFormat(undefined, { maximumFractionDigits: 2 }).format(v);
}
function fmtBytes(value: number): string {
  if (!Number.isFinite(value) || value < 0) return "—";
  const units = ["B", "KB", "MB", "GB", "TB"]; let amount = value, i = 0;
  while (amount >= 1024 && i < units.length - 1) { amount /= 1024; i++; }
  return `${amount >= 10 || i === 0 ? amount.toFixed(0) : amount.toFixed(1)} ${units[i]}`;
}
function usagePercent(item: { used?: number; limit?: number }): number {
  if (!Number.isFinite(Number(item.used)) || !Number.isFinite(Number(item.limit)) || Number(item.limit) === 0) return 0;
  return Math.min(100, (Number(item.used) / Number(item.limit)) * 100);
}
function usageTone(pct: number): string {
  if (pct > 85) return "critical";
  if (pct > 70) return "warning";
  return "healthy";
}
</script>

<template>
  <main class="metrics-page">
    <header class="page-header">
      <div><h2>Usage & Stats</h2><p>Resource usage and limits for your account</p></div>
      <div class="header-actions">
        <button class="button" type="button" :disabled="loading" @click="load"><PhArrowClockwise :size="15" :class="{ spinning: loading }"/> Refresh</button>
      </div>
    </header>

    <div v-if="loading" class="loading"><span v-for="i in 4" :key="i" class="skeleton" style="height:120px;border-radius:var(--radius-lg)"/></div>

    <template v-if="!loading">
      <!-- Metric cards -->
      <section v-if="metrics.length" class="metric-grid">
        <article v-for="(metric, i) in metrics.slice(0, 6)" :key="i" class="metric-card">
          <div class="metric-head">
            <span class="metric-label">{{ metric.label ?? metric.name ?? 'Metric' }}</span>
            <component :is="i % 3 === 0 ? PhSpeedometer : i % 3 === 1 ? PhPulse : PhHardDrives" :size="16" class="metric-icon"/>
          </div>
          <strong class="metric-value">{{ fmtVal(metric) }}</strong>
          <div class="metric-bar">
            <div class="metric-fill" :style="{ width: metric.unit === 'percent' || metric.unit === 'ratio' ? `${Math.min(100, Number(metric.value ?? 0) * (metric.unit === 'ratio' ? 100 : 1))}%` : '0%' }"/>
          </div>
        </article>
      </section>

      <!-- Usage limits -->
      <section v-if="usage.length" class="usage-section">
        <h3>Resource Limits</h3>
        <div class="usage-list">
          <article v-for="(item, i) in usage" :key="i" class="usage-row">
            <span class="usage-label">{{ String(item.dimension ?? '').replace(/_/g, ' ') }}</span>
            <div class="usage-bar">
              <div class="usage-fill" :class="usageTone(usagePercent(item))" :style="{ width: usagePercent(item) + '%' }"/>
            </div>
            <span class="usage-value">
              {{ item.unit === 'bytes' ? fmtBytes(Number(item.used ?? 0)) : item.used ?? '0' }}
              <span class="usage-limit">/ {{ item.unit === 'bytes' ? fmtBytes(Number(item.limit ?? 0)) : item.limit ?? '∞' }}</span>
            </span>
          </article>
        </div>
      </section>

      <div v-if="!metrics.length && !usage.length" class="empty-state">
        <PhChartLineUp :size="48" weight="duotone"/>
        <h3>No usage data yet</h3>
        <p>Usage statistics appear here once your websites start receiving traffic.</p>
      </div>
    </template>
  </main>
</template>

<style scoped>
.metrics-page{padding:32px clamp(18px,3vw,48px) 64px;max-width:1400px;margin:0 auto}
.page-header{display:flex;justify-content:space-between;align-items:center;gap:20px;margin-bottom:24px}
.page-header h2{margin:0 0 4px;font-size:clamp(24px,2.5vw,32px);letter-spacing:-.04em;font-weight:700}
.page-header p{margin:0;color:var(--muted);font-size:14px}
.header-actions{display:flex;gap:8px}
.loading{display:grid;grid-template-columns:repeat(3,1fr);gap:12px}

.metric-grid{display:grid;grid-template-columns:repeat(auto-fill,minmax(220px,1fr));gap:12px;margin-bottom:24px}
.metric-card{border:1px solid var(--border);border-radius:var(--radius-lg);background:var(--surface);padding:18px;box-shadow:var(--shadow-sm);display:flex;flex-direction:column;gap:10px}
.metric-head{display:flex;justify-content:space-between;align-items:center}
.metric-label{font-size:12px;color:var(--subtle);font-weight:600;text-transform:capitalize}
.metric-icon{color:var(--faint)}
.metric-value{font:600 28px/1 var(--font-mono);letter-spacing:-.04em}
.metric-bar{height:4px;background:var(--surface-2);border-radius:2px;overflow:hidden}
.metric-fill{height:100%;background:var(--accent);border-radius:2px;transition:width .3s ease}

.usage-section h3{margin:0 0 14px;font-size:16px;font-weight:650;letter-spacing:-.02em}
.usage-list{display:flex;flex-direction:column;gap:0;border:1px solid var(--border);border-radius:var(--radius-lg);background:var(--surface);box-shadow:var(--shadow-sm);overflow:hidden}
.usage-row{display:grid;grid-template-columns:140px 1fr 200px;gap:16px;align-items:center;padding:14px 20px;border-bottom:1px solid var(--border)}
.usage-row:last-child{border-bottom:0}
.usage-label{font-size:13px;font-weight:550;text-transform:capitalize;color:var(--text)}
.usage-bar{height:6px;background:var(--surface-2);border-radius:3px;overflow:hidden}
.usage-fill{height:100%;border-radius:3px;transition:width .3s ease}
.usage-fill.healthy{background:var(--healthy)}
.usage-fill.warning{background:var(--warning)}
.usage-fill.critical{background:var(--critical)}
.usage-value{font:600 13px/1 var(--font-mono);text-align:right;color:var(--text)}
.usage-limit{color:var(--subtle);font-weight:400}

.empty-state{display:grid;place-items:center;gap:14px;padding:64px 24px;text-align:center;border:1px dashed var(--border-strong);border-radius:var(--radius-lg)}
.empty-state svg{color:var(--faint)}
.empty-state h3{margin:0;font-size:18px}
.empty-state p{margin:0;color:var(--muted);font-size:13px;max-width:44ch;line-height:1.5}
.spinning{animation:spin .8s linear infinite}
@keyframes spin{to{transform:rotate(1turn)}}
</style>
