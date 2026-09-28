<script setup lang="ts">
import { computed, inject, onMounted, ref } from "vue";
import { PhArrowClockwise, PhBug, PhShieldCheck, PhShieldWarning } from "@phosphor-icons/vue";
import type { APIClient } from "../api";
import { sessionStore } from "../store";

const api = inject<APIClient>("api")!;
const loading = ref(true);
const findings = ref<Record<string, unknown>[]>([]);

const tenantId = computed(() => sessionStore.state.tenantId || undefined);
onMounted(() => void load());

async function load(): Promise<void> {
  loading.value = true;
  try {
    if (api.available("security.finding.list")) {
      const response = await api.invoke<unknown>("security.finding.list", { tenantId: tenantId.value, payload: { limit: 100 } });
      const result = response.result;
      findings.value = Array.isArray(result) ? result as Record<string, unknown>[] : (result as { items?: Record<string, unknown>[] })?.items ?? [];
    }
  } catch { findings.value = []; }
  finally { loading.value = false; }
}

function sevClass(sev: string): string {
  const s = sev.toLowerCase();
  if (s.includes("crit") || s.includes("high")) return "critical";
  if (s.includes("med") || s.includes("warn")) return "warning";
  return "info";
}
function fmtDate(value: unknown): string {
  if (!value) return ""; const d = new Date(String(value));
  return isNaN(d.valueOf()) ? "" : d.toLocaleDateString(undefined, { month: "short", day: "numeric" });
}
</script>

<template>
  <main class="findings-page">
    <header class="page-header">
      <div><h2>Security</h2><p>{{ findings.length }} finding{{ findings.length === 1 ? '' : 's' }}</p></div>
      <div class="header-actions">
        <button class="button" type="button" :disabled="loading" @click="load"><PhArrowClockwise :size="15" :class="{ spinning: loading }"/> Refresh</button>
        <button class="button button-primary" type="button"><PhBug :size="15"/> Run Scan</button>
      </div>
    </header>

    <div v-if="loading" class="loading"><span v-for="i in 3" :key="i" class="skeleton" style="height:80px;border-radius:var(--radius-lg)"/></div>

    <div v-if="!loading && findings.length" class="finding-list">
      <article v-for="(finding, i) in findings" :key="i" class="finding-card" :class="sevClass(String(finding.severity ?? ''))">
        <div class="finding-head">
          <span class="sev-badge">{{ finding.severity ?? 'info' }}</span>
          <strong>{{ finding.kind ?? finding.title ?? 'Finding' }}</strong>
        </div>
        <div class="finding-body">
          <span class="finding-resource">{{ finding.resource ?? finding.source ?? '' }}</span>
          <span class="finding-date">{{ fmtDate(finding.observed_at) }}</span>
        </div>
        <div class="finding-actions">
          <span class="status" :class="`status-${String(finding.state ?? 'open').toLowerCase()}`">{{ finding.state ?? 'open' }}</span>
          <button class="button button-small" type="button">Fix</button>
          <button class="button button-small button-quiet" type="button">Ignore</button>
        </div>
      </article>
    </div>

    <div v-if="!loading && !findings.length" class="empty-state">
      <PhShieldCheck :size="48" weight="duotone"/>
      <h3>No security findings</h3>
      <p>Everything looks good. Run a scan to check for malware, vulnerabilities, and configuration issues.</p>
      <button class="button button-primary" type="button"><PhBug :size="16"/> Run a Scan</button>
    </div>
  </main>
</template>

<style scoped>
.findings-page{padding:32px clamp(18px,3vw,48px) 64px;max-width:1400px;margin:0 auto}
.page-header{display:flex;justify-content:space-between;align-items:center;gap:20px;margin-bottom:24px}
.page-header h2{margin:0 0 4px;font-size:clamp(24px,2.5vw,32px);letter-spacing:-.04em;font-weight:700}
.page-header p{margin:0;color:var(--muted);font-size:14px}
.header-actions{display:flex;gap:8px}
.loading{display:grid;gap:12px}
.finding-list{display:flex;flex-direction:column;gap:10px}
.finding-card{padding:16px 20px;border:1px solid var(--border);border-radius:var(--radius-lg);background:var(--surface);box-shadow:var(--shadow-sm);display:grid;gap:10px}
.finding-card.critical{border-left:3px solid var(--critical)}
.finding-card.warning{border-left:3px solid var(--warning)}
.finding-card.info{border-left:3px solid var(--info)}
.finding-head{display:flex;align-items:center;gap:12px}
.sev-badge{padding:2px 10px;border-radius:99px;font:700 10px/1.4 var(--font-mono);text-transform:uppercase;letter-spacing:.08em}
.finding-card.critical .sev-badge{color:var(--critical);background:var(--critical-soft)}
.finding-card.warning .sev-badge{color:var(--warning);background:var(--warning-soft)}
.finding-card.info .sev-badge{color:var(--info);background:var(--info-soft)}
.finding-head strong{font-size:14px}
.finding-body{display:flex;justify-content:space-between;gap:12px;color:var(--subtle);font-size:12px}
.finding-resource{font-family:var(--font-mono)}
.finding-actions{display:flex;align-items:center;gap:8px}
.empty-state{display:grid;place-items:center;gap:14px;padding:64px 24px;text-align:center;border:1px dashed var(--border-strong);border-radius:var(--radius-lg)}
.empty-state svg{color:var(--healthy)}
.empty-state h3{margin:0;font-size:18px}
.empty-state p{margin:0;color:var(--muted);font-size:13px;max-width:44ch;line-height:1.5}
.spinning{animation:spin .8s linear infinite}
@keyframes spin{to{transform:rotate(1turn)}}
</style>
