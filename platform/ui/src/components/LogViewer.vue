<script setup lang="ts">
import { computed, inject, onMounted, ref } from "vue";
import { PhArrowClockwise, PhFileMagnifyingGlass, PhMagnifyingGlass, PhWarning, PhXCircle } from "@phosphor-icons/vue";
import type { APIClient } from "../api";
import { sessionStore } from "../store";

const api = inject<APIClient>("api")!;
const loading = ref(true);
const entries = ref<Record<string, unknown>[]>([]);
const search = ref("");
const severityFilter = ref("");

const tenantId = computed(() => sessionStore.state.tenantId || undefined);
onMounted(() => void load());

async function load(): Promise<void> {
  loading.value = true;
  try {
    if (api.available("operations.logs.query")) {
      const response = await api.invoke<unknown>("operations.logs.query", { tenantId: tenantId.value, payload: { limit: 100, minimum_severity: 0 } });
      const result = response.result;
      entries.value = Array.isArray(result) ? result as Record<string, unknown>[] : (result as { items?: Record<string, unknown>[] })?.items ?? [];
    }
  } catch { entries.value = []; }
  finally { loading.value = false; }
}

function severityClass(sev: unknown): string {
  const s = String(sev ?? "").toLowerCase();
  if (s.includes("error") || s.includes("critical") || s.includes("fatal")) return "critical";
  if (s.includes("warn")) return "warning";
  if (s.includes("info") || s.includes("debug")) return "info";
  return "neutral";
}
function fmtTime(value: unknown): string {
  if (!value) return ""; const d = new Date(String(value));
  return isNaN(d.valueOf()) ? "" : d.toLocaleTimeString(undefined, { hour: "2-digit", minute: "2-digit", second: "2-digit" });
}

const filtered = computed(() => {
  let result = entries.value;
  if (severityFilter.value) {
    result = result.filter(e => severityClass(e.severity ?? e.level) === severityFilter.value);
  }
  if (search.value.trim()) {
    const term = search.value.trim().toLowerCase();
    result = result.filter(e => JSON.stringify(e).toLowerCase().includes(term));
  }
  return result;
});
</script>

<template>
  <main class="logs-page">
    <header class="page-header">
      <div><h2>Logs</h2><p>{{ filtered.length }} of {{ entries.length }} entries</p></div>
      <div class="header-actions">
        <button class="button" type="button" :disabled="loading" @click="load"><PhArrowClockwise :size="15" :class="{ spinning: loading }"/> Refresh</button>
      </div>
    </header>

    <div class="toolbar">
      <label class="search-box">
        <PhMagnifyingGlass :size="15"/>
        <input v-model="search" type="search" placeholder="Search logs…"/>
      </label>
      <div class="severity-filters">
        <button v-for="sev in ['critical', 'warning', 'info']" :key="sev"
          :class="{ active: severityFilter === sev }"
          type="button" class="sev-filter" @click="severityFilter = severityFilter === sev ? '' : sev">
          {{ sev }}
        </button>
      </div>
    </div>

    <div v-if="loading" class="loading"><span v-for="i in 6" :key="i" class="skeleton" style="height:40px"/></div>

    <div v-if="!loading && filtered.length" class="log-list">
      <div v-for="(entry, i) in filtered.slice(0, 100)" :key="i" class="log-row" :class="severityClass(entry.severity ?? entry.level)">
        <span class="log-time">{{ fmtTime(entry.timestamp ?? entry.observed_at ?? entry.time) }}</span>
        <span class="log-sev">{{ entry.severity ?? entry.level ?? 'info' }}</span>
        <span class="log-msg">{{ entry.message ?? entry.body ?? entry.summary ?? JSON.stringify(entry).slice(0, 200) }}</span>
      </div>
    </div>

    <div v-if="!loading && !filtered.length" class="empty-state">
      <PhFileMagnifyingGlass :size="48" weight="duotone"/>
      <h3>No log entries</h3>
      <p>System and application logs will appear here as your websites generate activity.</p>
    </div>
  </main>
</template>

<style scoped>
.logs-page{padding:32px clamp(18px,3vw,48px) 64px;max-width:1400px;margin:0 auto;display:flex;flex-direction:column;min-height:calc(100dvh - var(--topbar))}
.page-header{display:flex;justify-content:space-between;align-items:center;gap:20px;margin-bottom:16px}
.page-header h2{margin:0 0 4px;font-size:clamp(24px,2.5vw,32px);letter-spacing:-.04em;font-weight:700}
.page-header p{margin:0;color:var(--muted);font-size:14px}
.header-actions{display:flex;gap:8px}

.toolbar{display:flex;gap:12px;align-items:center;margin-bottom:14px;flex-wrap:wrap}
.search-box{flex:1;min-width:240px;display:flex;align-items:center;gap:8px;height:38px;padding:0 12px;border:1px solid var(--border);border-radius:var(--radius);background:var(--surface);color:var(--subtle)}
.search-box:focus-within{border-color:var(--accent);box-shadow:0 0 0 3px var(--accent-soft)}
.search-box input{flex:1;border:0;outline:0;background:transparent;color:var(--text);font-size:13px}
.severity-filters{display:flex;gap:6px}
.sev-filter{padding:6px 14px;border:1px solid var(--border);border-radius:99px;background:transparent;color:var(--muted);font-size:12px;font-weight:600;text-transform:capitalize;cursor:pointer;transition:all .12s ease}
.sev-filter:hover{border-color:var(--border-bright)}
.sev-filter.active.critical{color:var(--critical);border-color:var(--critical);background:var(--critical-soft)}
.sev-filter.active.warning{color:var(--warning);border-color:var(--warning);background:var(--warning-soft)}
.sev-filter.active.info{color:var(--info);border-color:var(--info);background:var(--info-soft)}

.loading{display:grid;gap:8px}
.log-list{flex:1;border:1px solid var(--border);border-radius:var(--radius-lg);background:var(--surface);box-shadow:var(--shadow-sm);overflow:auto;max-height:calc(100dvh - 320px)}
.log-row{display:grid;grid-template-columns:90px 80px 1fr;gap:12px;padding:8px 16px;border-bottom:1px solid var(--border);font-size:12px;align-items:baseline}
.log-row:last-child{border-bottom:0}
.log-row:hover{background:var(--surface-2)}
.log-row.critical{border-left:3px solid var(--critical)}
.log-row.warning{border-left:3px solid var(--warning)}
.log-row.info{border-left:3px solid var(--info)}
.log-row.neutral{border-left:3px solid var(--border)}
.log-time{color:var(--subtle);font-family:var(--font-mono);font-size:11px}
.log-sev{font:600 10px/1.4 var(--font-mono);text-transform:uppercase}
.log-row.critical .log-sev{color:var(--critical)}
.log-row.warning .log-sev{color:var(--warning)}
.log-row.info .log-sev{color:var(--info)}
.log-row.neutral .log-sev{color:var(--muted)}
.log-msg{color:var(--text);word-break:break-word;line-height:1.4}

.empty-state{display:grid;place-items:center;gap:14px;padding:64px 24px;text-align:center;border:1px dashed var(--border-strong);border-radius:var(--radius-lg);margin-top:auto}
.empty-state svg{color:var(--faint)}
.empty-state h3{margin:0;font-size:18px}
.empty-state p{margin:0;color:var(--muted);font-size:13px;max-width:44ch;line-height:1.5}
.spinning{animation:spin .8s linear infinite}
@keyframes spin{to{transform:rotate(1turn)}}
</style>
