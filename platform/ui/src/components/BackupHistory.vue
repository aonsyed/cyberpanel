<script setup lang="ts">
// Backup history — visual run cards with status timeline, size, and actions.
import { computed, inject, onMounted, ref } from "vue";
import {
  PhArrowClockwise, PhCheckCircle, PhCloudArrowDown, PhGap,
  PhHardDrive, PhPlus, PhRestore, PhX,
} from "@phosphor-icons/vue";
import type { APIClient } from "../api";
import { sessionStore } from "../store";

const api = inject<APIClient>("api")!;
const loading = ref(true);
const error = ref("");
const runs = ref<Record<string, unknown>[]>([]);
const policies = ref<Record<string, unknown>[]>([]);

const tenantId = computed(() => sessionStore.state.tenantId || undefined);
onMounted(() => void load());

async function load(): Promise<void> {
  loading.value = true; error.value = "";
  try {
    if (api.available("backup.run.list")) {
      const response = await api.invoke<unknown>("backup.run.list", { tenantId: tenantId.value, payload: { limit: 50 } });
      const result = response.result;
      runs.value = Array.isArray(result) ? result as Record<string, unknown>[] : (result as { items?: Record<string, unknown>[] })?.items ?? [];
    }
    if (api.available("backup.policy.list")) {
      const response = await api.invoke<unknown>("backup.policy.list", { tenantId: tenantId.value, payload: { limit: 50 } });
      const result = response.result;
      policies.value = Array.isArray(result) ? result as Record<string, unknown>[] : (result as { items?: Record<string, unknown>[] })?.items ?? [];
    }
  } catch (cause) { error.value = cause instanceof Error ? cause.message : "Failed to load backups."; }
  finally { loading.value = false; }
}

function fmtBytes(value: unknown): string {
  const num = Number(value); if (!Number.isFinite(num) || num < 0) return "—";
  const units = ["B", "KB", "MB", "GB", "TB"]; let amount = num, i = 0;
  while (amount >= 1024 && i < units.length - 1) { amount /= 1024; i++; }
  return `${amount >= 10 || i === 0 ? amount.toFixed(0) : amount.toFixed(1)} ${units[i]}`;
}
function fmtDate(value: unknown): string {
  if (!value) return "—"; const d = new Date(String(value));
  return isNaN(d.valueOf()) ? "—" : d.toLocaleString(undefined, { month: "short", day: "numeric", hour: "2-digit", minute: "2-digit" });
}
function statusClass(status: string): string {
  const s = status.toLowerCase();
  if (s.includes("complete") || s.includes("success") || s.includes("commit")) return "healthy";
  if (s.includes("fail") || s.includes("error")) return "critical";
  if (s.includes("run") || s.includes("progress") || s.includes("active")) return "info";
  return "neutral";
}
</script>

<template>
  <main class="backup-page">
    <header class="page-header">
      <div>
        <h2>Backups</h2>
        <p>{{ runs.length }} backup run{{ runs.length === 1 ? '' : 's' }} · {{ policies.length }} polic{{ policies.length === 1 ? 'y' : 'ies' }}</p>
      </div>
      <div class="header-actions">
        <button class="button" type="button" :disabled="loading" @click="load">
          <PhArrowClockwise :size="15" :class="{ spinning: loading }"/> Refresh
        </button>
        <button class="button button-primary" type="button">
          <PhPlus :size="16" weight="bold"/> Run Backup
        </button>
      </div>
    </header>

    <p v-if="error" class="error-banner">{{ error }}</p>
    <div v-if="loading" class="loading"><span v-for="i in 3" :key="i" class="skeleton" style="height:100px;border-radius:var(--radius-lg)"/></div>

    <div v-if="!loading && runs.length" class="run-list">
      <article v-for="(run, i) in runs" :key="i" class="run-card">
        <div class="run-status" :class="statusClass(String(run.status ?? run.state ?? ''))">
          <PhCheckCircle v-if="statusClass(String(run.status ?? run.state ?? '')) === 'healthy'" :size="20" weight="fill"/>
          <PhX v-else-if="statusClass(String(run.status ?? run.state ?? '')) === 'critical'" :size="20" weight="fill"/>
          <PhArrowClockwise v-else :size="20"/>
        </div>
        <div class="run-info">
          <div class="run-title">
            <strong>{{ run.site_id ?? run.site ?? run.id ?? 'Backup' }}</strong>
            <span class="status" :class="`status-${statusClass(String(run.status ?? run.state ?? ''))}`">{{ run.status ?? run.state ?? 'unknown' }}</span>
          </div>
          <div class="run-meta">
            <span><PhHardDrive :size="13"/> {{ fmtBytes(run.bytes ?? run.size) }}</span>
            <span>{{ fmtDate(run.started_at ?? run.created_at) }}</span>
            <span v-if="run.type" class="run-type">{{ run.type }}</span>
          </div>
        </div>
        <div class="run-actions">
          <button class="button button-small" type="button" title="Restore"><PhRestore :size="14"/> Restore</button>
          <button class="button button-small" type="button" title="Download"><PhCloudArrowDown :size="14"/></button>
        </div>
      </article>
    </div>

    <div v-if="!loading && !runs.length && !error" class="empty-state">
      <PhHardDrive :size="48" weight="duotone"/>
      <h3>No backups yet</h3>
      <p>Run your first backup to create a restorable recovery point. Backups capture your site files and databases.</p>
      <button class="button button-primary" type="button"><PhPlus :size="16"/> Run Your First Backup</button>
    </div>
  </main>
</template>

<style scoped>
.backup-page{padding:32px clamp(18px,3vw,48px) 64px;max-width:1400px;margin:0 auto}
.page-header{display:flex;justify-content:space-between;align-items:center;gap:20px;margin-bottom:24px}
.page-header h2{margin:0 0 4px;font-size:clamp(24px,2.5vw,32px);letter-spacing:-.04em;font-weight:700}
.page-header p{margin:0;color:var(--muted);font-size:14px}
.header-actions{display:flex;gap:8px}
.error-banner{padding:14px 16px;border-left:3px solid var(--critical);border-radius:var(--radius-xs);background:var(--critical-soft);color:var(--critical);margin:0 0 16px}
.loading{display:grid;gap:12px}

.run-list{display:flex;flex-direction:column;gap:10px}
.run-card{display:flex;align-items:center;gap:16px;padding:16px 20px;border:1px solid var(--border);border-radius:var(--radius-lg);background:var(--surface);box-shadow:var(--shadow-sm);transition:border-color .12s ease}
.run-card:hover{border-color:var(--border-bright)}

.run-status{width:44px;height:44px;display:grid;place-items:center;border-radius:var(--radius);flex:0 0 auto}
.run-status.healthy{color:var(--healthy);background:var(--healthy-soft)}
.run-status.critical{color:var(--critical);background:var(--critical-soft)}
.run-status.info{color:var(--info);background:var(--info-soft)}
.run-status.neutral{color:var(--subtle);background:var(--surface-2)}

.run-info{flex:1;min-width:0}
.run-title{display:flex;align-items:center;gap:10px;flex-wrap:wrap}
.run-title strong{font-size:14px;letter-spacing:-.01em}
.run-meta{display:flex;gap:14px;margin-top:6px;color:var(--subtle);font-size:12px}
.run-meta span{display:flex;align-items:center;gap:4px}
.run-type{background:var(--surface-2);padding:2px 8px;border-radius:var(--radius-xs);font-size:10px;font-weight:600;text-transform:uppercase;letter-spacing:.06em}

.run-actions{display:flex;gap:6px;flex:0 0 auto}

.empty-state{display:grid;place-items:center;gap:14px;padding:64px 24px;text-align:center;border:1px dashed var(--border-strong);border-radius:var(--radius-lg)}
.empty-state svg{color:var(--faint)}
.empty-state h3{margin:0;font-size:18px}
.empty-state p{margin:0;color:var(--muted);font-size:13px;max-width:44ch;line-height:1.5}
.spinning{animation:spin .8s linear infinite}
@keyframes spin{to{transform:rotate(1turn)}}
</style>
