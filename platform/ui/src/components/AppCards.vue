<script setup lang="ts">
// WordPress/Apps page — visual app cards with install status, update
// available badge, health pill, and quick actions.
import { computed, inject, onMounted, ref } from "vue";
import {
  PhArrowClockwise, PhArrowUp, PhGlobe, PhPackage,
  PhPlus, PhShieldCheck, PhWrench,
} from "@phosphor-icons/vue";
import type { APIClient } from "../api";
import { sessionStore } from "../store";

const api = inject<APIClient>("api")!;
const loading = ref(true);
const error = ref("");
const apps = ref<Record<string, unknown>[]>([]);
const showInstall = ref(false);

const tenantId = computed(() => sessionStore.state.tenantId || undefined);
onMounted(() => void load());

async function load(): Promise<void> {
  loading.value = true; error.value = "";
  try {
    if (api.available("apps.instance.list")) {
      const response = await api.invoke<unknown>("apps.instance.list", { tenantId: tenantId.value, payload: { limit: 100 } });
      const result = response.result;
      apps.value = Array.isArray(result) ? result as Record<string, unknown>[] : (result as { items?: Record<string, unknown>[] })?.items ?? [];
    }
  } catch (cause) { error.value = cause instanceof Error ? cause.message : "Failed to load applications."; }
  finally { loading.value = false; }
}

function appIcon(type: string): string {
  const t = type.toLowerCase();
  if (t.includes("wordpress")) return "WP";
  if (t.includes("joomla")) return "J";
  if (t.includes("prestashop")) return "P";
  if (t.includes("mautic")) return "M";
  if (t.includes("magento")) return "MG";
  return "A";
}
function hasUpdate(app: Record<string, unknown>): boolean {
  return Number(app.updates ?? app.updates_available ?? 0) > 0;
}
</script>

<template>
  <main class="apps-page">
    <header class="page-header">
      <div>
        <h2>Applications</h2>
        <p>{{ apps.length }} app{{ apps.length === 1 ? '' : 's' }} installed{{ apps.filter(hasUpdate).length ? ` · ${apps.filter(hasUpdate).length} update${apps.filter(hasUpdate).length > 1 ? 's' : ''} available` : '' }}</p>
      </div>
      <div class="header-actions">
        <button class="button" type="button" :disabled="loading" @click="load">
          <PhArrowClockwise :size="15" :class="{ spinning: loading }"/> Refresh
        </button>
        <button class="button button-primary" type="button" @click="showInstall = !showInstall">
          <PhPlus :size="16" weight="bold"/> Install Application
        </button>
      </div>
    </header>

    <p v-if="error" class="error-banner">{{ error }}</p>
    <div v-if="loading" class="loading-grid">
      <div v-for="i in 3" :key="i" class="skeleton" style="height:160px;border-radius:var(--radius-lg)"/>
    </div>

    <!-- Install panel -->
    <div v-if="showInstall" class="install-panel">
      <h3>Install an Application</h3>
      <div class="install-options">
        <button class="install-option" type="button">
          <span class="option-icon wp">WP</span>
          <div><strong>WordPress</strong><small>Blog / CMS</small></div>
        </button>
        <button class="install-option" type="button">
          <span class="option-icon">J</span>
          <div><strong>Joomla</strong><small>CMS</small></div>
        </button>
        <button class="install-option" type="button">
          <span class="option-icon">P</span>
          <div><strong>PrestaShop</strong><small>E-commerce</small></div>
        </button>
        <button class="install-option" type="button">
          <span class="option-icon">M</span>
          <div><strong>Mautic</strong><small>Marketing</small></div>
        </button>
      </div>
    </div>

    <!-- App cards grid -->
    <div v-if="!loading && apps.length" class="app-grid">
      <article v-for="(app, i) in apps" :key="i" class="app-card">
        <div class="app-badge" :class="{ 'has-update': hasUpdate(app) }">
          {{ appIcon(String(app.type ?? app.application ?? '')) }}
          <span v-if="hasUpdate(app)" class="update-dot"/>
        </div>
        <div class="app-info">
          <div class="app-title-row">
            <strong>{{ app.hostname ?? app.name ?? 'Application' }}</strong>
            <span v-if="hasUpdate(app)" class="update-badge">
              <PhArrowUp :size="10" weight="bold"/> {{ app.updates ?? app.updates_available }} update{{ Number(app.updates ?? app.updates_available) > 1 ? 's' : '' }}
            </span>
          </div>
          <div class="app-meta">
            <span class="app-type">{{ app.type ?? app.application ?? 'app' }}</span>
            <span class="app-version">v{{ app.version ?? '?' }}</span>
            <span class="status" :class="`status-${String(app.health ?? 'unknown').toLowerCase()}`">{{ app.health ?? 'unknown' }}</span>
          </div>
        </div>
        <div class="app-actions">
          <button class="button button-small" type="button" title="Open site"><PhGlobe :size="14"/></button>
          <button v-if="hasUpdate(app)" class="button button-small update-btn" type="button" title="Update"><PhArrowUp :size="14"/> Update</button>
          <button class="button button-small" type="button" title="Repair"><PhWrench :size="14"/></button>
        </div>
      </article>
    </div>

    <!-- Empty state -->
    <div v-if="!loading && !apps.length && !error" class="empty-state">
      <PhPackage :size="48" weight="duotone"/>
      <h3>No apps installed yet</h3>
      <p>Install WordPress, Joomla, and other popular apps in one click. We handle the database and updates for you.</p>
      <button class="button button-primary" type="button" @click="showInstall = true">
        <PhPlus :size="16"/> Install an App
      </button>
    </div>
  </main>
</template>

<style scoped>
.apps-page{padding:32px clamp(18px,3vw,48px) 64px;max-width:1400px;margin:0 auto}
.page-header{display:flex;justify-content:space-between;align-items:center;gap:20px;margin-bottom:24px}
.page-header h2{margin:0 0 4px;font-size:clamp(24px,2.5vw,32px);letter-spacing:-.04em;font-weight:700}
.page-header p{margin:0;color:var(--muted);font-size:14px}
.header-actions{display:flex;gap:8px}
.error-banner{padding:14px 16px;border-left:3px solid var(--critical);border-radius:var(--radius-xs);background:var(--critical-soft);color:var(--critical);margin:0 0 16px}
.loading-grid{display:grid;grid-template-columns:repeat(auto-fill,minmax(380px,1fr));gap:14px}

.install-panel{border:1px solid var(--border-strong);border-radius:var(--radius-lg);background:var(--surface);padding:20px;margin-bottom:20px;box-shadow:var(--shadow)}
.install-panel h3{margin:0 0 14px;font-size:15px;font-weight:650}
.install-options{display:grid;grid-template-columns:repeat(auto-fill,minmax(180px,1fr));gap:10px}
.install-option{display:flex;align-items:center;gap:12px;padding:14px 16px;border:1px solid var(--border);border-radius:var(--radius);background:var(--bg-raised);cursor:pointer;text-align:left;transition:border-color .12s ease,background .12s ease}
.install-option:hover{border-color:var(--accent);background:var(--accent-softer)}
.option-icon{width:36px;height:36px;display:grid;place-items:center;border-radius:var(--radius-sm);background:var(--surface-2);color:var(--muted);font:700 14px/1 var(--font-mono);border:1px solid var(--border)}
.option-icon.wp{color:var(--accent);background:var(--accent-soft);border-color:color-mix(in srgb,var(--accent),transparent 75%)}
.install-option strong{display:block;font-size:13px}
.install-option small{color:var(--subtle);font-size:11px}

.app-grid{display:grid;grid-template-columns:repeat(auto-fill,minmax(400px,1fr));gap:14px}
.app-card{display:flex;align-items:center;gap:14px;padding:18px 20px;border:1px solid var(--border);border-radius:var(--radius-lg);background:var(--surface);box-shadow:var(--shadow-sm);transition:transform .16s ease,box-shadow .16s ease}
.app-card:hover{transform:translateY(-1px);box-shadow:var(--shadow)}

.app-badge{width:48px;height:48px;display:grid;place-items:center;border-radius:var(--radius);background:var(--accent-soft);color:var(--accent);font:700 18px/1 var(--font-mono);flex:0 0 auto;position:relative;border:1px solid color-mix(in srgb,var(--accent),transparent 75%)}
.app-badge.has-update{background:var(--warning-soft);color:var(--warning);border-color:color-mix(in srgb,var(--warning),transparent 70%)}
.update-dot{position:absolute;top:-2px;right:-2px;width:10px;height:10px;border-radius:50%;background:var(--warning);border:2px solid var(--surface)}

.app-info{flex:1;min-width:0}
.app-title-row{display:flex;align-items:center;gap:10px;flex-wrap:wrap}
.app-title-row strong{font-size:14px;letter-spacing:-.01em;word-break:break-all}
.update-badge{display:inline-flex;align-items:center;gap:3px;padding:2px 8px;border-radius:99px;font:600 10px/1.4 var(--font-mono);color:var(--warning);background:var(--warning-soft);border:1px solid color-mix(in srgb,var(--warning),transparent 75%)}
.app-meta{display:flex;gap:10px;align-items:center;margin-top:6px;flex-wrap:wrap}
.app-type{color:var(--subtle);font-size:11px;text-transform:capitalize}
.app-version{color:var(--subtle);font:500 11px/1 var(--font-mono)}

.app-actions{display:flex;gap:6px;flex:0 0 auto;align-items:center}
.update-btn{color:var(--warning);border-color:color-mix(in srgb,var(--warning),transparent 50%)}
.update-btn:hover{background:var(--warning-soft)}

.empty-state{display:grid;place-items:center;gap:14px;padding:64px 24px;text-align:center;border:1px dashed var(--border-strong);border-radius:var(--radius-lg)}
.empty-state svg{color:var(--faint)}
.empty-state h3{margin:0;font-size:18px}
.empty-state p{margin:0;color:var(--muted);font-size:13px;max-width:44ch;line-height:1.5}
.spinning{animation:spin .8s linear infinite}
@keyframes spin{to{transform:rotate(1turn)}}
</style>
