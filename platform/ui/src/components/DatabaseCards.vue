<script setup lang="ts">
// Database cards — replaces the flat table with visual cards showing
// connection info, users, and quick actions per database.
import { computed, inject, onMounted, ref } from "vue";
import {
  PhArrowClockwise, PhDatabase, PhDownload, PhPlus,
  PhTerminalWindow, PhTrash, PhUser, PhUsersThree, PhUpload,
} from "@phosphor-icons/vue";
import type { APIClient } from "../api";
import { sessionStore } from "../store";

const api = inject<APIClient>("api")!;
const loading = ref(true);
const error = ref("");
const databases = ref<Record<string, unknown>[]>([]);
const showCreateForm = ref(false);

const tenantId = computed(() => sessionStore.state.tenantId || undefined);

onMounted(() => void load());

async function load(): Promise<void> {
  loading.value = true; error.value = "";
  try {
    if (api.available("database.database.list")) {
      const response = await api.invoke<unknown>("database.database.list", { tenantId: tenantId.value, payload: { limit: 100 } });
      const result = response.result;
      databases.value = Array.isArray(result) ? result as Record<string, unknown>[] : (result as { items?: Record<string, unknown>[] })?.items ?? [];
    }
  } catch (cause) { error.value = cause instanceof Error ? cause.message : "Failed to load databases."; }
  finally { loading.value = false; }
}

function fmtBytes(value: unknown): string {
  const num = Number(value); if (!Number.isFinite(num) || num < 0) return "—";
  const units = ["B", "KB", "MB", "GB", "TB"]; let amount = num, i = 0;
  while (amount >= 1024 && i < units.length - 1) { amount /= 1024; i++; }
  return `${amount >= 10 || i === 0 ? amount.toFixed(0) : amount.toFixed(1)} ${units[i]}`;
}
</script>

<template>
  <main class="db-page">
    <header class="page-header">
      <div>
        <h2>Databases</h2>
        <p>{{ databases.length }} database{{ databases.length === 1 ? '' : 's' }} on your account</p>
      </div>
      <div class="header-actions">
        <button class="button" type="button" :disabled="loading" @click="load">
          <PhArrowClockwise :size="15" :class="{ spinning: loading }"/> Refresh
        </button>
        <button class="button button-primary" type="button" @click="showCreateForm = !showCreateForm">
          <PhPlus :size="16" weight="bold"/> Create Database
        </button>
      </div>
    </header>

    <p v-if="error" class="error-banner">{{ error }}</p>

    <div v-if="loading" class="loading-grid">
      <div v-for="i in 3" :key="i" class="skeleton" style="height: 140px; border-radius: var(--radius-lg)"/>
    </div>

    <!-- Create form panel -->
    <div v-if="showCreateForm" class="create-panel">
      <h3>Create a Database</h3>
      <div class="create-fields">
        <label class="field">Database name<input class="input" placeholder="myapp_production"/></label>
        <label class="field">Site (optional)<select class="input"><option>Not linked to a website</option><option>example.com</option></select></label>
        <label class="field">Character set<select class="input"><option>utf8mb4</option><option>utf8</option></select></label>
      </div>
      <div class="create-actions">
        <button class="button" type="button" @click="showCreateForm = false">Cancel</button>
        <button class="button button-primary" type="button">Create Database</button>
      </div>
    </div>

    <!-- Database cards grid -->
    <div v-if="!loading && databases.length" class="db-grid">
      <article v-for="(db, i) in databases" :key="i" class="db-card">
        <header class="db-card-head">
          <div class="db-icon">
            <PhDatabase :size="22" weight="duotone"/>
          </div>
          <div class="db-title">
            <strong>{{ db.name ?? 'database' }}</strong>
            <small>{{ db.instance ?? 'mariadb-local' }}</small>
          </div>
          <span class="status" :class="`status-${String(db.status ?? 'active').toLowerCase()}`">
            {{ db.status ?? 'active' }}
          </span>
        </header>

        <div class="db-stats">
          <div class="db-stat">
            <PhDatabase :size="14"/>
            <span>{{ fmtBytes(db.size) }}</span>
          </div>
          <div class="db-stat">
            <PhUsersThree :size="14"/>
            <span>{{ db.principals ?? 0 }} users</span>
          </div>
        </div>

        <footer class="db-card-actions">
          <button class="button button-small" type="button" title="Open SQL console">
            <PhTerminalWindow :size="14"/> Console
          </button>
          <button class="button button-small" type="button" title="Export">
            <PhDownload :size="14"/> Export
          </button>
          <button class="button button-small" type="button" title="Import">
            <PhUpload :size="14"/> Import
          </button>
          <button class="button button-small button-danger" type="button" title="Delete">
            <PhTrash :size="14"/>
          </button>
        </footer>
      </article>
    </div>

    <!-- Empty state -->
    <div v-if="!loading && !databases.length && !error" class="empty-state">
      <PhDatabase :size="48" weight="duotone"/>
      <h3>No databases yet</h3>
      <p>Create a database to store your application's data. Each database gets its own username and password.</p>
      <button class="button button-primary" type="button" @click="showCreateForm = true">
        <PhPlus :size="16"/> Create a Database
      </button>
    </div>
  </main>
</template>

<style scoped>
.db-page{padding:32px clamp(18px,3vw,48px) 64px;max-width:1400px;margin:0 auto}

.page-header{display:flex;justify-content:space-between;align-items:center;gap:20px;margin-bottom:24px}
.page-header h2{margin:0 0 4px;font-size:clamp(24px,2.5vw,32px);letter-spacing:-.04em;font-weight:700}
.page-header p{margin:0;color:var(--muted);font-size:14px}
.header-actions{display:flex;gap:8px}

.error-banner{padding:14px 16px;border-left:3px solid var(--critical);border-radius:var(--radius-xs);background:var(--critical-soft);color:var(--critical);margin:0 0 16px}

.loading-grid{display:grid;grid-template-columns:repeat(auto-fill,minmax(320px,1fr));gap:14px}

/* Create panel */
.create-panel{border:1px solid var(--border-strong);border-radius:var(--radius-lg);background:var(--surface);padding:24px;margin-bottom:20px;box-shadow:var(--shadow)}
.create-panel h3{margin:0 0 16px;font-size:16px;font-weight:650}
.create-fields{display:grid;grid-template-columns:repeat(auto-fit,minmax(220px,1fr));gap:16px;margin-bottom:16px}
.create-actions{display:flex;justify-content:flex-end;gap:8px}

/* Database card grid */
.db-grid{display:grid;grid-template-columns:repeat(auto-fill,minmax(340px,1fr));gap:14px}

.db-card{border:1px solid var(--border);border-radius:var(--radius-lg);background:var(--surface);box-shadow:var(--shadow-sm);display:flex;flex-direction:column;transition:transform .16s ease,box-shadow .16s ease}
.db-card:hover{transform:translateY(-2px);box-shadow:var(--shadow)}

.db-card-head{display:flex;align-items:center;gap:14px;padding:18px 20px;border-bottom:1px solid var(--border)}
.db-icon{width:44px;height:44px;display:grid;place-items:center;border-radius:var(--radius);background:var(--info-soft);color:var(--info);flex:0 0 auto}
.db-title{flex:1;min-width:0}
.db-title strong{display:block;font-size:15px;letter-spacing:-.02em;word-break:break-all}
.db-title small{color:var(--subtle);font-size:11px}

.db-stats{display:flex;gap:16px;padding:14px 20px}
.db-stat{display:flex;align-items:center;gap:6px;color:var(--muted);font-size:12px;font-weight:550}
.db-stat svg{color:var(--subtle)}

.db-card-actions{display:flex;gap:6px;padding:12px 20px;border-top:1px solid var(--border);margin-top:auto}

/* Empty state */
.empty-state{display:grid;place-items:center;gap:14px;padding:64px 24px;text-align:center;border:1px dashed var(--border-strong);border-radius:var(--radius-lg);background:var(--surface)}
.empty-state svg{color:var(--faint)}
.empty-state h3{margin:0;font-size:18px;font-weight:650}
.empty-state p{margin:0;color:var(--muted);font-size:13px;max-width:44ch;line-height:1.5}

.spinning{animation:spin .8s linear infinite}
@keyframes spin{to{transform:rotate(1turn)}}
</style>
