<script setup lang="ts">
// Container app cards — visual grid with image, status, ports, and resources.
import { computed, inject, onMounted, ref } from "vue";
import {
  PhArrowClockwise, PhCube, PhGlobe, PhPlay, PhPlus,
  PhStop, PhTerminalWindow,
} from "@phosphor-icons/vue";
import type { APIClient } from "../api";
import { sessionStore } from "../store";

const api = inject<APIClient>("api")!;
const loading = ref(true);
const error = ref("");
const containers = ref<Record<string, unknown>[]>([]);

const tenantId = computed(() => sessionStore.state.tenantId || undefined);
onMounted(() => void load());

async function load(): Promise<void> {
  loading.value = true; error.value = "";
  try {
    if (api.available("container.workload.list")) {
      const response = await api.invoke<unknown>("container.workload.list", { tenantId: tenantId.value, payload: { limit: 100 } });
      const result = response.result;
      containers.value = Array.isArray(result) ? result as Record<string, unknown>[] : (result as { items?: Record<string, unknown>[] })?.items ?? [];
    } else if (api.available("container.application.list")) {
      const response = await api.invoke<unknown>("container.application.list", { tenantId: tenantId.value, payload: { limit: 100 } });
      const result = response.result;
      containers.value = Array.isArray(result) ? result as Record<string, unknown>[] : (result as { items?: Record<string, unknown>[] })?.items ?? [];
    }
  } catch (cause) { error.value = cause instanceof Error ? cause.message : "Failed to load containers."; }
  finally { loading.value = false; }
}
</script>

<template>
  <main class="container-page">
    <header class="page-header">
      <div>
        <h2>Containers</h2>
        <p>{{ containers.length }} container app{{ containers.length === 1 ? '' : 's' }}</p>
      </div>
      <div class="header-actions">
        <button class="button" type="button" :disabled="loading" @click="load">
          <PhArrowClockwise :size="15" :class="{ spinning: loading }"/> Refresh
        </button>
        <button class="button button-primary" type="button">
          <PhPlus :size="16" weight="bold"/> New Container
        </button>
      </div>
    </header>

    <p v-if="error" class="error-banner">{{ error }}</p>
    <div v-if="loading" class="loading"><span v-for="i in 2" :key="i" class="skeleton" style="height:160px;border-radius:var(--radius-lg)"/></div>

    <div v-if="!loading && containers.length" class="container-grid">
      <article v-for="(container, i) in containers" :key="i" class="container-card">
        <header class="container-head">
          <div class="container-icon"><PhCube :size="22" weight="duotone"/></div>
          <div class="container-title">
            <strong>{{ container.name ?? container.id ?? 'Container' }}</strong>
            <small>{{ container.image ?? container.image_ref ?? '—' }}</small>
          </div>
          <span class="status" :class="`status-${String(container.status ?? container.state ?? 'unknown').toLowerCase()}`">
            {{ container.status ?? container.state ?? 'unknown' }}
          </span>
        </header>
        <div class="container-stats">
          <div v-if="container.ports" class="container-stat">
            <PhGlobe :size="13"/>
            <span>{{ container.ports }}</span>
          </div>
          <div v-if="container.cpu_percent !== undefined" class="container-stat">
            CPU {{ container.cpu_percent }}%
          </div>
          <div v-if="container.memory_used" class="container-stat">
            MEM {{ container.memory_used }}
          </div>
        </div>
        <footer class="container-actions">
          <button class="button button-small" type="button" title="Start"><PhPlay :size="14"/></button>
          <button class="button button-small" type="button" title="Stop"><PhStop :size="14"/></button>
          <button class="button button-small" type="button" title="Terminal"><PhTerminalWindow :size="14"/></button>
        </footer>
      </article>
    </div>

    <div v-if="!loading && !containers.length && !error" class="empty-state">
      <PhCube :size="48" weight="duotone"/>
      <h3>No containers yet</h3>
      <p>Run apps in isolated containers with networking and health monitoring included.</p>
      <button class="button button-primary" type="button"><PhPlus :size="16"/> Deploy a Container</button>
    </div>
  </main>
</template>

<style scoped>
.container-page{padding:32px clamp(18px,3vw,48px) 64px;max-width:1400px;margin:0 auto}
.page-header{display:flex;justify-content:space-between;align-items:center;gap:20px;margin-bottom:24px}
.page-header h2{margin:0 0 4px;font-size:clamp(24px,2.5vw,32px);letter-spacing:-.04em;font-weight:700}
.page-header p{margin:0;color:var(--muted);font-size:14px}
.header-actions{display:flex;gap:8px}
.error-banner{padding:14px 16px;border-left:3px solid var(--critical);border-radius:var(--radius-xs);background:var(--critical-soft);color:var(--critical);margin:0 0 16px}
.loading{display:grid;gap:12px}

.container-grid{display:grid;grid-template-columns:repeat(auto-fill,minmax(380px,1fr));gap:14px}
.container-card{border:1px solid var(--border);border-radius:var(--radius-lg);background:var(--surface);box-shadow:var(--shadow-sm);display:flex;flex-direction:column;transition:transform .16s ease,box-shadow .16s ease}
.container-card:hover{transform:translateY(-2px);box-shadow:var(--shadow)}

.container-head{display:flex;align-items:center;gap:14px;padding:18px 20px;border-bottom:1px solid var(--border)}
.container-icon{width:44px;height:44px;display:grid;place-items:center;border-radius:var(--radius);background:var(--warning-soft);color:var(--warning);flex:0 0 auto}
.container-title{flex:1;min-width:0}
.container-title strong{display:block;font-size:15px;letter-spacing:-.02em}
.container-title small{color:var(--subtle);font-size:11px;word-break:break-all}

.container-stats{display:flex;gap:14px;padding:14px 20px;flex-wrap:wrap}
.container-stat{display:flex;align-items:center;gap:5px;color:var(--muted);font-size:12px;font-weight:550}
.container-stat svg{color:var(--subtle)}

.container-actions{display:flex;gap:6px;padding:12px 20px;border-top:1px solid var(--border);margin-top:auto}

.empty-state{display:grid;place-items:center;gap:14px;padding:64px 24px;text-align:center;border:1px dashed var(--border-strong);border-radius:var(--radius-lg)}
.empty-state svg{color:var(--faint)}
.empty-state h3{margin:0;font-size:18px}
.empty-state p{margin:0;color:var(--muted);font-size:13px;max-width:44ch;line-height:1.5}
.spinning{animation:spin .8s linear infinite}
@keyframes spin{to{transform:rotate(1turn)}}
</style>
