<script setup lang="ts">
import { computed, inject, onMounted, ref } from "vue";
import { PhArrowClockwise, PhBell, PhCheckCircle, PhWarning } from "@phosphor-icons/vue";
import type { APIClient } from "../api";
import { sessionStore } from "../store";

const api = inject<APIClient>("api")!;
const loading = ref(true);
const alerts = ref<Record<string, unknown>[]>([]);

const tenantId = computed(() => sessionStore.state.tenantId || undefined);
onMounted(() => void load());

async function load(): Promise<void> {
  loading.value = true;
  try {
    if (api.available("notification.inbox.list")) {
      const response = await api.invoke<unknown>("notification.inbox.list", { tenantId: tenantId.value, payload: { limit: 100 } });
      const result = response.result;
      alerts.value = Array.isArray(result) ? result as Record<string, unknown>[] : (result as { items?: Record<string, unknown>[] })?.items ?? [];
    }
  } catch { alerts.value = []; }
  finally { loading.value = false; }
}

function sevClass(sev: string): string {
  const s = sev.toLowerCase();
  if (s.includes("crit") || s.includes("error")) return "critical";
  if (s.includes("warn")) return "warning";
  return "info";
}
function fmtDate(value: unknown): string {
  if (!value) return ""; const d = new Date(String(value));
  return isNaN(d.valueOf()) ? "" : d.toLocaleString(undefined, { month: "short", day: "numeric", hour: "2-digit", minute: "2-digit" });
}
</script>

<template>
  <main class="alerts-page">
    <header class="page-header">
      <div><h2>Alerts</h2><p>{{ alerts.length }} alert{{ alerts.length === 1 ? '' : 's' }}</p></div>
      <div class="header-actions">
        <button class="button" type="button" :disabled="loading" @click="load"><PhArrowClockwise :size="15" :class="{ spinning: loading }"/> Refresh</button>
      </div>
    </header>

    <div v-if="loading" class="loading"><span v-for="i in 3" :key="i" class="skeleton" style="height:80px;border-radius:var(--radius-lg)"/></div>

    <div v-if="!loading && alerts.length" class="alert-list">
      <article v-for="(alert, i) in alerts" :key="i" class="alert-card" :class="sevClass(String(alert.severity ?? 'info'))">
        <div class="alert-icon">
          <PhWarning v-if="sevClass(String(alert.severity ?? '')) !== 'info'" :size="18" weight="fill"/>
          <PhBell v-else :size="18"/>
        </div>
        <div class="alert-body">
          <strong>{{ alert.subject ?? alert.title ?? 'Alert' }}</strong>
          <small>{{ alert.kind ?? '' }} · {{ fmtDate(alert.updated_at ?? alert.created_at) }}</small>
        </div>
        <button class="button button-small" type="button">Acknowledge</button>
      </article>
    </div>

    <div v-if="!loading && !alerts.length" class="empty-state">
      <PhCheckCircle :size="48" weight="duotone"/>
      <h3>All clear</h3>
      <p>No alerts need your attention. You'll see notifications here when something needs a look.</p>
    </div>
  </main>
</template>

<style scoped>
.alerts-page{padding:32px clamp(18px,3vw,48px) 64px;max-width:1400px;margin:0 auto}
.page-header{display:flex;justify-content:space-between;align-items:center;gap:20px;margin-bottom:24px}
.page-header h2{margin:0 0 4px;font-size:clamp(24px,2.5vw,32px);letter-spacing:-.04em;font-weight:700}
.page-header p{margin:0;color:var(--muted);font-size:14px}
.loading{display:grid;gap:12px}
.alert-list{display:flex;flex-direction:column;gap:10px}
.alert-card{display:flex;align-items:center;gap:14px;padding:16px 20px;border:1px solid var(--border);border-radius:var(--radius-lg);background:var(--surface);box-shadow:var(--shadow-sm)}
.alert-card.critical{border-left:3px solid var(--critical)}
.alert-card.warning{border-left:3px solid var(--warning)}
.alert-card.info{border-left:3px solid var(--info)}
.alert-icon{width:36px;height:36px;display:grid;place-items:center;border-radius:var(--radius-sm);flex:0 0 auto}
.alert-card.critical .alert-icon{color:var(--critical);background:var(--critical-soft)}
.alert-card.warning .alert-icon{color:var(--warning);background:var(--warning-soft)}
.alert-card.info .alert-icon{color:var(--info);background:var(--info-soft)}
.alert-body{flex:1;min-width:0}
.alert-body strong{display:block;font-size:14px;letter-spacing:-.01em}
.alert-body small{color:var(--subtle);font-size:11px}
.empty-state{display:grid;place-items:center;gap:14px;padding:64px 24px;text-align:center;border:1px dashed var(--border-strong);border-radius:var(--radius-lg)}
.empty-state svg{color:var(--healthy)}
.empty-state h3{margin:0;font-size:18px}
.empty-state p{margin:0;color:var(--muted);font-size:13px;max-width:44ch;line-height:1.5}
.spinning{animation:spin .8s linear infinite}
@keyframes spin{to{transform:rotate(1turn)}}
</style>
