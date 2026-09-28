<script setup lang="ts">
import { computed, inject, onMounted, ref } from "vue";
import { PhArrowClockwise, PhArrowsLeftRight, PhCheckCircle, PhPlus, PhXCircle } from "@phosphor-icons/vue";
import type { APIClient } from "../api";
import { sessionStore } from "../store";

const api = inject<APIClient>("api")!;
const loading = ref(true);
const migrations = ref<Record<string, unknown>[]>([]);

const tenantId = computed(() => sessionStore.state.tenantId || undefined);
onMounted(() => void load());

async function load(): Promise<void> {
  loading.value = true;
  try {
    if (api.available("migration.list")) {
      const response = await api.invoke<unknown>("migration.list", { payload: { limit: 50 } });
      const result = response.result;
      migrations.value = Array.isArray(result) ? result as Record<string, unknown>[] : (result as { items?: Record<string, unknown>[]; migrations?: Record<string, unknown>[] })?.items ?? (result as { migrations?: Record<string, unknown>[] })?.migrations ?? [];
    }
  } catch { migrations.value = []; }
  finally { loading.value = false; }
}

const phases = ["created", "inventoried", "planned", "base_sync", "quiescing", "cutover", "committed", "cleanup"];
function phaseIndex(phase: string): number {
  return phases.indexOf(phase.toLowerCase());
}
function phaseLabel(phase: string): string {
  return String(phase ?? "").replace(/_/g, " ");
}
function statusColor(migration: Record<string, unknown>): string {
  const phase = String(migration.phase ?? "").toLowerCase();
  const state = String(migration.state ?? "").toLowerCase();
  if (state.includes("complete") || phase.includes("committed") || phase.includes("cleanup")) return "healthy";
  if (state.includes("fail") || state.includes("pause")) return "critical";
  if (state.includes("block")) return "warning";
  return "info";
}
function fmtDate(value: unknown): string {
  if (!value) return ""; const d = new Date(String(value));
  return isNaN(d.valueOf()) ? "" : d.toLocaleString(undefined, { month: "short", day: "numeric", hour: "2-digit", minute: "2-digit" });
}
</script>

<template>
  <main class="mig-page">
    <header class="page-header">
      <div><h2>Migrations</h2><p>{{ migrations.length }} migration{{ migrations.length === 1 ? '' : 's' }}</p></div>
      <div class="header-actions">
        <button class="button" type="button" :disabled="loading" @click="load"><PhArrowClockwise :size="15" :class="{ spinning: loading }"/> Refresh</button>
        <button class="button button-primary" type="button"><PhPlus :size="16" weight="bold"/> Start Migration</button>
      </div>
    </header>

    <div v-if="loading" class="loading"><span v-for="i in 2" :key="i" class="skeleton" style="height:140px;border-radius:var(--radius-lg)"/></div>

    <div v-if="!loading && migrations.length" class="mig-list">
      <article v-for="(migration, i) in migrations" :key="i" class="mig-card">
        <header class="mig-head">
          <div class="mig-icon" :class="statusColor(migration)">
            <PhArrowsLeftRight :size="20" weight="duotone"/>
          </div>
          <div class="mig-title">
            <strong>{{ migration.id ?? 'Migration' }}</strong>
            <span class="mig-source">from {{ migration.source ?? 'legacy backup' }}</span>
          </div>
          <span class="status" :class="`status-${statusColor(migration)}`">{{ phaseLabel(String(migration.phase ?? 'unknown')) }}</span>
        </header>

        <!-- Phase progress bar -->
        <div class="phase-track">
          <div v-for="(phase, pi) in phases" :key="phase" class="phase-step" :class="{ done: phaseIndex(String(migration.phase ?? '')) >= pi, current: phaseIndex(String(migration.phase ?? '')) === pi }">
            <span class="phase-dot"/>
            <span class="phase-name">{{ phaseLabel(phase) }}</span>
          </div>
        </div>

        <footer class="mig-meta">
          <span>Started {{ fmtDate(migration.created_at) }}</span>
          <span v-if="migration.updated_at">Updated {{ fmtDate(migration.updated_at) }}</span>
        </footer>
      </article>
    </div>

    <div v-if="!loading && !migrations.length" class="empty-state">
      <PhArrowsLeftRight :size="48" weight="duotone"/>
      <h3>No migrations</h3>
      <p>Move websites, databases, and email from another server or a CyberPanel backup. Everything is tested before going live.</p>
      <button class="button button-primary" type="button"><PhPlus :size="16"/> Start a Migration</button>
    </div>
  </main>
</template>

<style scoped>
.mig-page{padding:32px clamp(18px,3vw,48px) 64px;max-width:1400px;margin:0 auto}
.page-header{display:flex;justify-content:space-between;align-items:center;gap:20px;margin-bottom:24px}
.page-header h2{margin:0 0 4px;font-size:clamp(24px,2.5vw,32px);letter-spacing:-.04em;font-weight:700}
.page-header p{margin:0;color:var(--muted);font-size:14px}
.header-actions{display:flex;gap:8px}
.loading{display:grid;gap:12px}
.mig-list{display:flex;flex-direction:column;gap:14px}

.mig-card{border:1px solid var(--border);border-radius:var(--radius-lg);background:var(--surface);box-shadow:var(--shadow-sm);overflow:hidden}
.mig-head{display:flex;align-items:center;gap:14px;padding:18px 20px;border-bottom:1px solid var(--border)}
.mig-icon{width:44px;height:44px;display:grid;place-items:center;border-radius:var(--radius);flex:0 0 auto}
.mig-icon.healthy{color:var(--healthy);background:var(--healthy-soft)}
.mig-icon.critical{color:var(--critical);background:var(--critical-soft)}
.mig-icon.warning{color:var(--warning);background:var(--warning-soft)}
.mig-icon.info{color:var(--info);background:var(--info-soft)}
.mig-title{flex:1;min-width:0}
.mig-title strong{display:block;font-size:14px;font-family:var(--font-mono);letter-spacing:-.02em;word-break:break-all}
.mig-source{color:var(--subtle);font-size:12px}

.phase-track{display:flex;padding:16px 20px;gap:0;overflow-x:auto}
.phase-step{display:flex;flex-direction:column;align-items:center;gap:6px;flex:1;min-width:80px;position:relative}
.phase-step::before{content:"";position:absolute;top:5px;left:-50%;width:100%;height:2px;background:var(--border)}
.phase-step:first-child::before{display:none}
.phase-step.done::before{background:var(--healthy)}
.phase-dot{width:12px;height:12px;border-radius:50%;border:2px solid var(--border-strong);background:var(--surface);z-index:1}
.phase-step.done .phase-dot{border-color:var(--healthy);background:var(--healthy)}
.phase-step.current .phase-dot{border-color:var(--accent);background:var(--accent);box-shadow:0 0 6px var(--accent-glow)}
.phase-name{font-size:10px;color:var(--subtle);text-transform:capitalize;white-space:nowrap}
.phase-step.done .phase-name{color:var(--muted)}
.phase-step.current .phase-name{color:var(--accent);font-weight:650}

.mig-meta{display:flex;gap:16px;padding:12px 20px;border-top:1px solid var(--border);color:var(--subtle);font-size:12px}

.empty-state{display:grid;place-items:center;gap:14px;padding:64px 24px;text-align:center;border:1px dashed var(--border-strong);border-radius:var(--radius-lg)}
.empty-state svg{color:var(--faint)}
.empty-state h3{margin:0;font-size:18px}
.empty-state p{margin:0;color:var(--muted);font-size:13px;max-width:44ch;line-height:1.5}
.spinning{animation:spin .8s linear infinite}
@keyframes spin{to{transform:rotate(1turn)}}
</style>
