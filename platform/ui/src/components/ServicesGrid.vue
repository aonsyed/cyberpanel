<script setup lang="ts">
// Services health grid — visual tiles with status, controls, and diagnostics.
import { computed, inject, onMounted, ref } from "vue";
import {
  PhArrowClockwise, PhDatabase, PhEnvelopeSimple, PhGlobe,
  PhHardDrives, PhLock, PhPlay, PhShieldCheck, PhStop, PhWrench,
} from "@phosphor-icons/vue";
import type { APIClient } from "../api";
import { sessionStore } from "../store";

const api = inject<APIClient>("api")!;
const loading = ref(true);
const error = ref("");
const services = ref<Record<string, unknown>[]>([]);

const tenantId = computed(() => sessionStore.state.tenantId || undefined);
onMounted(() => void load());

async function load(): Promise<void> {
  loading.value = true; error.value = "";
  try {
    if (api.available("observability.dashboard.get")) {
      const response = await api.invoke<unknown>("observability.dashboard.get", { tenantId: tenantId.value, payload: {} });
      const result = response.result;
      if (result && typeof result === "object") {
        const svcs = (result as Record<string, unknown>).services;
        if (Array.isArray(svcs)) services.value = svcs as Record<string, unknown>[];
      }
    }
  } catch (cause) { error.value = cause instanceof Error ? cause.message : "Failed to load services."; }
  finally { loading.value = false; }
}

function healthClass(health: string): string {
  const h = health.toLowerCase();
  if (h.includes("healthy") || h.includes("active") || h.includes("ready")) return "healthy";
  if (h.includes("degraded") || h.includes("warning") || h.includes("pending")) return "warning";
  if (h.includes("failed") || h.includes("critical") || h.includes("offline")) return "critical";
  return "unknown";
}
function iconFor(name: string): unknown {
  const n = name.toLowerCase();
  if (n.includes("web") || n.includes("litespeed") || n.includes("ols") || n.includes("nginx")) return PhGlobe;
  if (n.includes("database") || n.includes("mysql") || n.includes("maria")) return PhDatabase;
  if (n.includes("mail") || n.includes("smtp") || n.includes("imap") || n.includes("dovecot") || n.includes("postfix")) return PhEnvelopeSimple;
  if (n.includes("dns") || n.includes("powerdns")) return PhGlobe;
  if (n.includes("security") || n.includes("firewall") || n.includes("waf")) return PhShieldCheck;
  if (n.includes("redis") || n.includes("cache")) return PhHardDrives;
  if (n.includes("ssl") || n.includes("cert") || n.includes("tls")) return PhLock;
  return PhWrench;
}
</script>

<template>
  <main class="services-page">
    <header class="page-header">
      <div>
        <h2>Services</h2>
        <p>{{ services.filter(s => healthClass(String(s.health ?? '')) === 'healthy').length }} of {{ services.length }} healthy</p>
      </div>
      <div class="header-actions">
        <button class="button" type="button" :disabled="loading" @click="load">
          <PhArrowClockwise :size="15" :class="{ spinning: loading }"/> Refresh
        </button>
      </div>
    </header>

    <div v-if="error" class="notice">Couldn't load live service status. Check back in a moment.</div>
    <div v-if="loading" class="loading-grid">
      <div v-for="i in 6" :key="i" class="skeleton" style="height:120px;border-radius:var(--radius-lg)"/>
    </div>

    <!-- Service tiles grid -->
    <div v-if="!loading && services.length" class="service-grid">
      <article v-for="(service, i) in services" :key="i" class="service-tile" :class="healthClass(String(service.health ?? ''))">
        <div class="service-head">
          <component :is="iconFor(String(service.name ?? ''))" :size="20" class="service-icon"/>
          <strong>{{ service.name ?? 'Service' }}</strong>
        </div>
        <div class="service-status">
          <span class="status-dot"/>
          <span class="status-text">{{ service.health ?? 'unknown' }}</span>
        </div>
        <div v-if="service.missing_reason" class="service-note">{{ service.missing_reason }}</div>
        <div class="service-controls">
          <button class="ctrl-btn" type="button" title="Start"><PhPlay :size="13"/></button>
          <button class="ctrl-btn" type="button" title="Stop"><PhStop :size="13"/></button>
          <button class="ctrl-btn" type="button" title="Restart"><PhArrowClockwise :size="13"/></button>
        </div>
      </article>
    </div>

    <div v-if="!loading && !services.length" class="empty-state">
      <PhWrench :size="48" weight="duotone"/>
      <h3>No service observations</h3>
      <p>We're still checking your services. This page fills in automatically.</p>
    </div>
  </main>
</template>

<style scoped>
.services-page{padding:32px clamp(18px,3vw,48px) 64px;max-width:1400px;margin:0 auto}
.page-header{display:flex;justify-content:space-between;align-items:center;gap:20px;margin-bottom:24px}
.page-header h2{margin:0 0 4px;font-size:clamp(24px,2.5vw,32px);letter-spacing:-.04em;font-weight:700}
.page-header p{margin:0;color:var(--muted);font-size:14px}
.header-actions{display:flex;gap:8px}
.notice{padding:12px 16px;border-left:3px solid var(--warning);border-radius:var(--radius-xs);background:var(--warning-soft);color:var(--warning);margin:0 0 16px;font-size:13px}
.error-banner{padding:14px 16px;border-left:3px solid var(--critical);border-radius:var(--radius-xs);background:var(--critical-soft);color:var(--critical);margin:0 0 16px}
.loading-grid{display:grid;grid-template-columns:repeat(auto-fill,minmax(200px,1fr));gap:12px}

.service-grid{display:grid;grid-template-columns:repeat(auto-fill,minmax(220px,1fr));gap:12px}
.service-tile{border:1px solid var(--border);border-radius:var(--radius-lg);background:var(--surface);padding:16px;display:flex;flex-direction:column;gap:10px;box-shadow:var(--shadow-sm);transition:transform .16s ease,box-shadow .16s ease;position:relative;overflow:hidden}
.service-tile:hover{transform:translateY(-2px);box-shadow:var(--shadow)}
.service-tile::before{content:"";position:absolute;top:0;left:0;right:0;height:3px}
.service-tile.healthy::before{background:var(--healthy)}
.service-tile.warning::before{background:var(--warning)}
.service-tile.critical::before{background:var(--critical)}
.service-tile.unknown::before{background:var(--border-strong)}

.service-head{display:flex;align-items:center;gap:10px}
.service-icon{color:var(--muted);flex:0 0 auto}
.service-head strong{font-size:13px;letter-spacing:-.01em;word-break:break-word}

.service-status{display:flex;align-items:center;gap:7px}
.status-dot{width:8px;height:8px;border-radius:50%;flex:0 0 auto}
.service-tile.healthy .status-dot{background:var(--healthy);box-shadow:0 0 6px var(--healthy)}
.service-tile.warning .status-dot{background:var(--warning);box-shadow:0 0 6px var(--warning)}
.service-tile.critical .status-dot{background:var(--critical);box-shadow:0 0 6px var(--critical)}
.service-tile.unknown .status-dot{background:var(--subtle)}
.status-text{font-size:12px;color:var(--muted);text-transform:capitalize}

.service-note{color:var(--subtle);font-size:10px;line-height:1.3;padding:6px 10px;background:var(--surface-2);border-radius:var(--radius-xs);word-break:break-word}

.service-controls{display:flex;gap:6px;margin-top:auto;padding-top:8px;border-top:1px solid var(--border)}
.ctrl-btn{width:30px;height:30px;border:1px solid var(--border);border-radius:var(--radius-xs);background:transparent;color:var(--muted);display:grid;place-items:center;cursor:pointer;transition:background .1s ease,color .1s ease,border-color .1s ease}
.ctrl-btn:hover{background:var(--surface-2);color:var(--text);border-color:var(--border-bright)}

.empty-state{display:grid;place-items:center;gap:14px;padding:64px 24px;text-align:center;border:1px dashed var(--border-strong);border-radius:var(--radius-lg)}
.empty-state svg{color:var(--faint)}
.empty-state h3{margin:0;font-size:18px}
.empty-state p{margin:0;color:var(--muted);font-size:13px;max-width:44ch;line-height:1.5}
.spinning{animation:spin .8s linear infinite}
@keyframes spin{to{transform:rotate(1turn)}}
</style>
