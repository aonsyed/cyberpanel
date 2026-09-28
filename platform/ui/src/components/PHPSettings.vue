<script setup lang="ts">
import { computed, inject, onMounted, ref } from "vue";
import { PhArrowClockwise, PhCode, PhPackage } from "@phosphor-icons/vue";
import type { APIClient } from "../api";
import { sessionStore } from "../store";

const api = inject<APIClient>("api")!;
const loading = ref(true);
const profiles = ref<Record<string, unknown>[]>([]);

const tenantId = computed(() => sessionStore.state.tenantId || undefined);
onMounted(() => void load());

async function load(): Promise<void> {
  loading.value = true;
  try {
    // Try the PHP profile list operation
    if (api.available("webengine.php.list")) {
      const response = await api.invoke<unknown>("webengine.php.list", { payload: { limit: 20 } });
      const result = response.result;
      profiles.value = Array.isArray(result) ? result as Record<string, unknown>[] : (result as { items?: Record<string, unknown>[] })?.items ?? [];
    }
  } catch { profiles.value = []; }
  finally { loading.value = false; }
}
</script>

<template>
  <main class="php-page">
    <header class="page-header">
      <div><h2>PHP Settings</h2><p>{{ profiles.length }} PHP profile{{ profiles.length === 1 ? '' : 's' }}</p></div>
      <div class="header-actions">
        <button class="button" type="button" :disabled="loading" @click="load"><PhArrowClockwise :size="15" :class="{ spinning: loading }"/> Refresh</button>
      </div>
    </header>

    <div v-if="loading" class="loading"><span v-for="i in 3" :key="i" class="skeleton" style="height:120px;border-radius:var(--radius-lg)"/></div>

    <div v-if="!loading && profiles.length" class="profile-grid">
      <article v-for="(profile, i) in profiles" :key="i" class="profile-card">
        <div class="profile-icon"><PhCode :size="22" weight="duotone"/></div>
        <div class="profile-info">
          <strong>PHP {{ profile.version ?? profile.id ?? '?' }}</strong>
          <div class="profile-meta">
            <span v-if="profile.memory_limit_bytes">Memory: {{ Math.round(Number(profile.memory_limit_bytes) / 1048576) }}MB</span>
            <span v-if="profile.max_connections">Workers: {{ profile.max_connections }}</span>
            <span class="status" :class="`status-${String(profile.state ?? 'active').toLowerCase()}`">{{ profile.state ?? 'active' }}</span>
          </div>
        </div>
      </article>
    </div>

    <div v-if="!loading && !profiles.length" class="empty-state">
      <PhPackage :size="48" weight="duotone"/>
      <h3>No PHP profiles</h3>
      <p>PHP versions appear here once installed. Each website can use a different PHP version.</p>
    </div>
  </main>
</template>

<style scoped>
.php-page{padding:32px clamp(18px,3vw,48px) 64px;max-width:1400px;margin:0 auto}
.page-header{display:flex;justify-content:space-between;align-items:center;gap:20px;margin-bottom:24px}
.page-header h2{margin:0 0 4px;font-size:clamp(24px,2.5vw,32px);letter-spacing:-.04em;font-weight:700}
.page-header p{margin:0;color:var(--muted);font-size:14px}
.loading{display:grid;gap:12px}
.profile-grid{display:grid;grid-template-columns:repeat(auto-fill,minmax(340px,1fr));gap:14px}
.profile-card{display:flex;align-items:center;gap:16px;padding:18px 20px;border:1px solid var(--border);border-radius:var(--radius-lg);background:var(--surface);box-shadow:var(--shadow-sm)}
.profile-icon{width:44px;height:44px;display:grid;place-items:center;border-radius:var(--radius);color:var(--accent);background:var(--accent-soft);flex:0 0 auto}
.profile-info{flex:1;min-width:0}
.profile-info strong{display:block;font-size:16px;letter-spacing:-.02em}
.profile-meta{display:flex;gap:14px;margin-top:6px;color:var(--subtle);font-size:12px;flex-wrap:wrap;align-items:center}
.empty-state{display:grid;place-items:center;gap:14px;padding:64px 24px;text-align:center;border:1px dashed var(--border-strong);border-radius:var(--radius-lg)}
.empty-state svg{color:var(--faint)}
.empty-state h3{margin:0;font-size:18px}
.empty-state p{margin:0;color:var(--muted);font-size:13px;max-width:44ch;line-height:1.5}
.spinning{animation:spin .8s linear infinite}
@keyframes spin{to{transform:rotate(1turn)}}
</style>
