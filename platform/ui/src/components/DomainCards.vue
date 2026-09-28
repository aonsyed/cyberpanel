<script setup lang="ts">
import { computed, inject, onMounted, ref } from "vue";
import { PhArrowClockwise, PhGlobe, PhLock, PhPlus, PhSignpost } from "@phosphor-icons/vue";
import type { APIClient } from "../api";
import { sessionStore } from "../store";

const api = inject<APIClient>("api")!;
const loading = ref(true);
const bindings = ref<Record<string, unknown>[]>([]);

const tenantId = computed(() => sessionStore.state.tenantId || undefined);
onMounted(() => void load());

async function load(): Promise<void> {
  loading.value = true;
  try {
    if (api.available("hosting.binding.list")) {
      const response = await api.invoke<unknown>("hosting.binding.list", { tenantId: tenantId.value, payload: { limit: 200 } });
      const result = response.result;
      bindings.value = Array.isArray(result) ? result as Record<string, unknown>[] : (result as { items?: Record<string, unknown>[] })?.items ?? [];
    }
  } catch { bindings.value = []; }
  finally { loading.value = false; }
}

function relLabel(rel: string): string {
  const r = rel.toLowerCase();
  if (r.includes("alias")) return "Alias";
  if (r.includes("redirect")) return "Redirect";
  if (r.includes("child")) return "Sub-site";
  if (r.includes("primary")) return "Primary";
  return rel || "Domain";
}
</script>

<template>
  <main class="domains-page">
    <header class="page-header">
      <div><h2>Domains</h2><p>{{ bindings.length }} domain{{ bindings.length === 1 ? '' : 's' }} across your websites</p></div>
      <div class="header-actions">
        <button class="button" type="button" :disabled="loading" @click="load"><PhArrowClockwise :size="15" :class="{ spinning: loading }"/> Refresh</button>
        <button class="button button-primary" type="button"><PhPlus :size="16" weight="bold"/> Add Domain</button>
      </div>
    </header>

    <div v-if="loading" class="loading"><span v-for="i in 3" :key="i" class="skeleton" style="height:80px;border-radius:var(--radius-lg)"/></div>

    <div v-if="!loading && bindings.length" class="domain-list">
      <article v-for="(binding, i) in bindings" :key="i" class="domain-card">
        <div class="domain-icon">
          <PhGlobe :size="20" weight="duotone"/>
        </div>
        <div class="domain-info">
          <strong>{{ binding.hostname ?? binding.name ?? 'domain' }}</strong>
          <div class="domain-meta">
            <span class="rel-badge">{{ relLabel(String(binding.relationship ?? binding.kind ?? '')) }}</span>
            <span class="site-ref">→ {{ binding.site ?? binding.site_id ?? '' }}</span>
          </div>
        </div>
        <div class="domain-status">
          <span v-if="binding.tls" class="status status-healthy"><PhLock :size="12"/> SSL</span>
          <span v-else class="status status-warning">No SSL</span>
        </div>
      </article>
    </div>

    <div v-if="!loading && !bindings.length" class="empty-state">
      <PhSignpost :size="48" weight="duotone"/>
      <h3>No extra domains</h3>
      <p>Add an alias or redirect domain to point additional addresses at your websites.</p>
      <button class="button button-primary" type="button"><PhPlus :size="16"/> Add a Domain</button>
    </div>
  </main>
</template>

<style scoped>
.domains-page{padding:32px clamp(18px,3vw,48px) 64px;max-width:1400px;margin:0 auto}
.page-header{display:flex;justify-content:space-between;align-items:center;gap:20px;margin-bottom:24px}
.page-header h2{margin:0 0 4px;font-size:clamp(24px,2.5vw,32px);letter-spacing:-.04em;font-weight:700}
.page-header p{margin:0;color:var(--muted);font-size:14px}
.header-actions{display:flex;gap:8px}
.loading{display:grid;gap:12px}
.domain-list{display:flex;flex-direction:column;gap:10px}
.domain-card{display:flex;align-items:center;gap:16px;padding:16px 20px;border:1px solid var(--border);border-radius:var(--radius-lg);background:var(--surface);box-shadow:var(--shadow-sm);transition:border-color .12s ease}
.domain-card:hover{border-color:var(--border-bright)}
.domain-icon{width:44px;height:44px;display:grid;place-items:center;border-radius:var(--radius);color:var(--accent);background:var(--accent-soft);flex:0 0 auto}
.domain-info{flex:1;min-width:0}
.domain-info strong{font-size:14px;display:block;letter-spacing:-.01em;word-break:break-all}
.domain-meta{display:flex;gap:10px;align-items:center;margin-top:6px;flex-wrap:wrap}
.rel-badge{padding:2px 8px;border-radius:var(--radius-xs);font:600 10px/1.4 var(--font-mono);background:var(--surface-2);color:var(--muted);text-transform:uppercase;letter-spacing:.06em}
.site-ref{color:var(--subtle);font-size:12px;font-family:var(--font-mono)}
.domain-status{flex:0 0 auto}
.empty-state{display:grid;place-items:center;gap:14px;padding:64px 24px;text-align:center;border:1px dashed var(--border-strong);border-radius:var(--radius-lg)}
.empty-state svg{color:var(--faint)}
.empty-state h3{margin:0;font-size:18px}
.empty-state p{margin:0;color:var(--muted);font-size:13px;max-width:44ch;line-height:1.5}
.spinning{animation:spin .8s linear infinite}
@keyframes spin{to{transform:rotate(1turn)}}
</style>
