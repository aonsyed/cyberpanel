<script setup lang="ts">
// GenericCardPage — a reusable visual card layout for admin resource pages.
// Renders cards with icon, title, subtitle, status pill, and optional stats.
// This replaces the flat table+JSON drawer for admin pages that list resources.
import { computed, inject, onMounted, ref } from "vue";
import {
  PhArrowClockwise, PhPlus, PhDatabase, PhPackage, PhEnvelopeSimple,
  PhHardDrives, PhShieldCheck, PhClock, PhUserPlus,
  PhBell, PhBug, PhLock, PhGlobe, PhStack, PhFileText, PhUsersThree,
} from "@phosphor-icons/vue";
import type { APIClient } from "../api";
import { sessionStore } from "../store";

export interface CardPageConfig {
  title: string;
  subtitle: string;
  listOperation: string;
  createLabel?: string;
  icon?: string;
  nameField?: string;
  subtitleField?: string;
  statusField?: string;
  metaFields?: Array<{ key: string; label: string }>;
  emptyTitle: string;
  emptyBody: string;
  scope?: "tenant" | "installation";
}

const props = defineProps<{ config: CardPageConfig }>();
const api = inject<APIClient>("api")!;
const loading = ref(true);
const items = ref<Record<string, unknown>[]>([]);

const tenantId = computed(() => props.config.scope === "installation" ? undefined : sessionStore.state.tenantId || undefined);
onMounted(() => void load());

async function load(): Promise<void> {
  loading.value = true;
  try {
    if (api.available(props.config.listOperation)) {
      const response = await api.invoke<unknown>(props.config.listOperation, { tenantId: tenantId.value, payload: { limit: 100 } });
      const result = response.result;
      items.value = Array.isArray(result) ? result as Record<string, unknown>[] : (result as { items?: Record<string, unknown>[] })?.items ?? [];
    }
  } catch { items.value = []; }
  finally { loading.value = false; }
}

const iconMap: Record<string, unknown> = {
  database: PhDatabase, package: PhPackage, mail: PhEnvelopeSimple,
  server: PhHardDrives, shield: PhShieldCheck, clock: PhClock,
  cloud: PhArrowClockwise, user: PhUserPlus, bell: PhBell, bug: PhBug,
  lock: PhLock, globe: PhGlobe, stack: PhStack, file: PhFileText, users: PhUsersThree,
};

function pageIcon(): unknown {
  return iconMap[props.config.icon ?? "package"] ?? PhPackage;
}

function fieldValue(item: Record<string, unknown>, key: string): string {
  const value = item[key];
  if (value === undefined || value === null || value === "") return "";
  return String(value);
}

function statusClass(status: string): string {
  const s = status.toLowerCase();
  if (s.includes("active") || s.includes("healthy") || s.includes("ok") || s.includes("running")) return "status-healthy";
  if (s.includes("fail") || s.includes("error") || s.includes("down")) return "status-critical";
  if (s.includes("pend") || s.includes("wait") || s.includes("paused")) return "status-warning";
  return "status-info";
}
</script>

<template>
  <main class="card-page">
    <header class="page-header">
      <div>
        <h2>{{ config.title }}</h2>
        <p>{{ config.subtitle }}</p>
      </div>
      <div class="header-actions">
        <button class="button" type="button" :disabled="loading" @click="load">
          <PhArrowClockwise :size="15" :class="{ spinning: loading }"/> Refresh
        </button>
        <button v-if="config.createLabel" class="button button-primary" type="button">
          <PhPlus :size="16" weight="bold"/> {{ config.createLabel }}
        </button>
      </div>
    </header>

    <div v-if="loading" class="loading">
      <div v-for="i in 3" :key="i" class="skeleton" style="height:100px;border-radius:var(--radius-lg)"/>
    </div>

    <div v-if="!loading && items.length" class="card-grid">
      <article v-for="(item, i) in items" :key="i" class="item-card">
        <div class="item-icon">
          <component :is="pageIcon()" :size="20" weight="duotone"/>
        </div>
        <div class="item-info">
          <strong>{{ fieldValue(item, config.nameField ?? 'name') || fieldValue(item, 'id') || 'Item' }}</strong>
          <div v-if="config.subtitleField && fieldValue(item, config.subtitleField)" class="item-subtitle">
            {{ fieldValue(item, config.subtitleField!) }}
          </div>
          <div class="item-meta">
            <span v-for="meta in config.metaFields ?? []" :key="meta.key" v-show="fieldValue(item, meta.key)" class="meta-item">
              {{ meta.label }}: {{ fieldValue(item, meta.key) }}
            </span>
            <span v-if="config.statusField && fieldValue(item, config.statusField)" class="status" :class="statusClass(fieldValue(item, config.statusField!))">
              {{ fieldValue(item, config.statusField!) }}
            </span>
          </div>
        </div>
      </article>
    </div>

    <div v-if="!loading && !items.length" class="empty-state">
      <component :is="pageIcon()" :size="48" weight="duotone"/>
      <h3>{{ config.emptyTitle }}</h3>
      <p>{{ config.emptyBody }}</p>
      <button v-if="config.createLabel" class="button button-primary" type="button">
        <PhPlus :size="16"/> {{ config.createLabel }}
      </button>
    </div>
  </main>
</template>

<style scoped>
.card-page{padding:32px clamp(18px,3vw,48px) 64px;max-width:1400px;margin:0 auto}
.page-header{display:flex;justify-content:space-between;align-items:center;gap:20px;margin-bottom:24px}
.page-header h2{margin:0 0 4px;font-size:clamp(24px,2.5vw,32px);letter-spacing:-.04em;font-weight:700}
.page-header p{margin:0;color:var(--muted);font-size:14px}
.header-actions{display:flex;gap:8px}
.loading{display:grid;gap:12px}
.card-grid{display:grid;grid-template-columns:repeat(auto-fill,minmax(380px,1fr));gap:14px}
.item-card{display:flex;align-items:flex-start;gap:16px;padding:20px;border:1px solid var(--border);border-radius:var(--radius-lg);background:var(--surface);box-shadow:var(--shadow-sm);transition:transform .16s ease,box-shadow .16s ease}
.item-card:hover{transform:translateY(-1px);box-shadow:var(--shadow)}
.item-icon{width:44px;height:44px;display:grid;place-items:center;border-radius:var(--radius);color:var(--accent);background:var(--accent-soft);flex:0 0 auto}
.item-info{flex:1;min-width:0}
.item-info strong{display:block;font-size:15px;letter-spacing:-.02em;word-break:break-word}
.item-subtitle{color:var(--subtle);font-size:12px;margin-top:4px}
.item-meta{display:flex;gap:10px;margin-top:8px;flex-wrap:wrap;align-items:center}
.meta-item{color:var(--subtle);font-size:12px;font-family:var(--font-mono)}
.empty-state{display:grid;place-items:center;gap:14px;padding:64px 24px;text-align:center;border:1px dashed var(--border-strong);border-radius:var(--radius-lg)}
.empty-state svg{color:var(--faint)}
.empty-state h3{margin:0;font-size:18px}
.empty-state p{margin:0;color:var(--muted);font-size:13px;max-width:44ch;line-height:1.5}
.spinning{animation:spin .8s linear infinite}
@keyframes spin{to{transform:rotate(1turn)}}
</style>
