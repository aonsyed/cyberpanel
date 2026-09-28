<script setup lang="ts">
import { computed, inject, onMounted, ref } from "vue";
import { PhArrowClockwise as ArrowClockwise, PhCaretDown as CaretDown, PhCopySimple as CopySimple } from "@phosphor-icons/vue";
import type { APIClient } from "../api";
import type { ActionDefinition } from "../domain";
import { sessionStore } from "../store";

const props = defineProps<{ operation: string; resource: Record<string, unknown>; title: string; actions?: ActionDefinition[] | undefined; tenantId?: string | undefined }>();
const emit = defineEmits<{ close: []; action: [ActionDefinition, Record<string, unknown>] }>();
const api = inject<APIClient>("api")!;
const loading = ref(false);
const error = ref("");
const detail = ref<Record<string, unknown> | null>(null);
const copied = ref("");

const projection = computed(() => {
  const merged: Record<string, unknown> = { ...props.resource, ...(detail.value ?? {}) };
  return Object.entries(merged).filter(([, value]) => !(value !== null && typeof value === "object" && !Array.isArray(value) && Object.keys(value).length === 0));
});
const nested = computed(() => projection.value.filter(([, value]) => value !== null && typeof value === "object"));
const flat = computed(() => projection.value.filter(([, value]) => value === null || typeof value !== "object"));
const heading = computed(() => String(props.resource.hostname ?? props.resource.name ?? props.resource.id ?? props.resource.resource_id ?? props.title));
const detailAvailable = computed(() => api.available(props.operation));
const generation = computed(() => Number(detail.value?.generation ?? props.resource.generation ?? 0) || undefined);

onMounted(() => void load());

async function load(): Promise<void> {
  if (!detailAvailable.value) { detail.value = null; return; }
  loading.value = true; error.value = "";
  try {
    const response = await api.invoke<unknown>(props.operation, {
      tenantId: props.tenantId ?? (sessionStore.state.tenantId || undefined),
      resourceId: resourceId(),
      expectedGeneration: generation.value
    });
    if (response.result && typeof response.result === "object" && !Array.isArray(response.result)) {
      detail.value = response.result as Record<string, unknown>;
    } else detail.value = null;
  } catch (cause) { error.value = cause instanceof Error ? cause.message : "The detail projection could not be loaded."; }
  finally { loading.value = false; }
}
function resourceId(): string | undefined {
  const value = props.resource.id ?? props.resource.resource_id ?? props.resource.instance_id;
  return value === undefined || value === "" ? undefined : String(value);
}
function text(value: unknown): string {
  if (value === null || value === undefined) return "—";
  if (Array.isArray(value)) return value.map((entry) => text(entry)).join(", ");
  if (typeof value === "object") return JSON.stringify(value);
  if (typeof value === "boolean") return value ? "yes" : "no";
  return String(value);
}
function isDate(key: string): boolean { return /(_at|_until|_since)$/i.test(key) || /timestamp/i.test(key); }
function render(value: unknown): string {
  if (isFiniteDate(value)) return new Intl.DateTimeFormat(undefined, { dateStyle: "medium", timeStyle: "short" }).format(new Date(String(value)));
  return text(value);
}
function isFiniteDate(value: unknown): boolean {
  if (typeof value !== "string" || !/^\d{4}-\d{2}-\d{2}T/.test(value)) return false;
  return !Number.isNaN(new Date(value).valueOf());
}
async function copyJSON(): Promise<void> {
  try { await navigator.clipboard.writeText(JSON.stringify({ ...props.resource, ...(detail.value ?? {}) }, null, 2)); copied.value = "Copied"; setTimeout(() => copied.value = "", 1600); } catch { copied.value = ""; }
}
</script>

<template>
  <div class="drawer-layer" role="presentation" @mousedown.self="emit('close')">
    <section class="drawer detail-drawer" role="dialog" aria-modal="true" :aria-label="`Detail: ${heading}`">
      <header>
        <div>
          <p class="detail-kind mono">{{ title }}</p>
          <h3>{{ heading }}</h3>
          <p v-if="generation" class="detail-generation mono">GENERATION {{ generation }}</p>
        </div>
        <div class="drawer-tools">
          <button class="icon-button" type="button" aria-label="Refresh detail" :disabled="!detailAvailable || loading" @click="load"><ArrowClockwise :size="17" :class="{ spinning: loading }"/></button>
          <button class="icon-button" type="button" aria-label="Copy projection JSON" @click="copyJSON"><CopySimple :size="17"/><span v-if="copied" class="copy-note">{{ copied }}</span></button>
          <button class="icon-button" type="button" aria-label="Close detail" @click="emit('close')">×</button>
        </div>
      </header>
      <div v-if="loading" class="drawer-loading"><span v-for="index in 6" :key="index" class="skeleton"></span></div>
      <p v-else-if="error" class="detail-error" role="alert">{{ error }}</p>
      <div v-else class="drawer-body">
        <dl class="detail-grid">
          <template v-for="[key, value] in flat" :key="key">
            <dt>{{ key.replaceAll("_", " ") }}</dt>
            <dd :class="{ mono: typeof value === 'number' || key.includes('_id') || key === 'id' }">{{ render(value) }}</dd>
          </template>
        </dl>
        <details v-for="[key, value] in nested" :key="key" class="detail-nested">
          <summary>{{ key.replaceAll("_", " ") }} <CaretDown :size="13" class="caret"/></summary>
          <pre class="detail-json mono">{{ JSON.stringify(value, null, 2) }}</pre>
        </details>
        <details class="detail-nested raw">
          <summary>Raw projection <CaretDown :size="13" class="caret"/></summary>
          <pre class="detail-json mono">{{ JSON.stringify({ ...resource, ...(detail ?? {}) }, null, 2) }}</pre>
        </details>
      </div>
      <footer v-if="actions?.length">
        <span>Actions</span>
        <div>
          <button v-for="action in actions" :key="action.id" class="button button-small" :class="{ 'button-danger': action.tone === 'critical' }" type="button" @click="emit('action', action, { ...(detail ?? {}), ...resource })">{{ action.label }}</button>
        </div>
      </footer>
    </section>
  </div>
</template>

<style scoped>
.drawer-layer{position:fixed;z-index:80;inset:0;background:rgba(0,5,8,.55);display:flex;justify-content:flex-end}
.detail-drawer{width:min(620px,100vw);height:100dvh;background:var(--bg-raised);border-left:1px solid var(--border-strong);box-shadow:var(--shadow);display:flex;flex-direction:column;animation:drawer-in .18s ease}
@keyframes drawer-in{from{transform:translateX(24px);opacity:.4}}
.detail-drawer>header{min-height:86px;padding:18px 22px;border-bottom:1px solid var(--border);display:flex;align-items:flex-start;justify-content:space-between;gap:12px}
.detail-kind{margin:0;color:var(--accent);font-size:10px;letter-spacing:.12em;text-transform:uppercase}
.detail-drawer h3{margin:6px 0 4px;font-size:21px;letter-spacing:-.03em;line-height:1.1;word-break:break-all}
.detail-generation{color:var(--subtle);font-size:10px;margin:0}
.drawer-tools{display:flex;gap:2px;position:relative}
.copy-note{position:absolute;top:40px;right:0;font-size:10px;color:var(--healthy)}
.drawer-loading{display:grid;gap:10px;padding:20px 22px}
.drawer-loading .skeleton{height:22px}
.detail-error{margin:16px 22px;padding:11px 13px;border-left:3px solid var(--critical);background:color-mix(in srgb,var(--critical),transparent 92%);color:var(--critical);font-size:12px}
.drawer-body{flex:1;overflow:auto;padding:8px 22px 26px}
.detail-grid{display:grid;grid-template-columns:minmax(130px,max-content) 1fr;gap:0 18px;margin:14px 0 6px}
.detail-grid dt{color:var(--subtle);font-size:11px;text-transform:capitalize;padding:8px 0;border-bottom:1px solid var(--border)}
.detail-grid dd{margin:0;padding:8px 0;border-bottom:1px solid var(--border);font-size:13px;word-break:break-word}
.detail-nested{border:1px solid var(--border);border-radius:var(--radius);background:var(--surface);margin-top:12px}
.detail-nested summary{list-style:none;cursor:pointer;padding:12px 14px;font-size:12px;font-weight:650;color:var(--muted);display:flex;align-items:center;justify-content:space-between;text-transform:capitalize}
.detail-nested summary::-webkit-details-marker{display:none}
.caret{transition:transform .14s ease}
.detail-nested[open] .caret{transform:rotate(180deg)}
.detail-json{margin:0;padding:0 14px 14px;overflow:auto;max-height:320px;font-size:11px;line-height:1.5;color:var(--muted)}
.detail-drawer>footer{border-top:1px solid var(--border);padding:13px 22px;display:flex;align-items:center;gap:14px}
.detail-drawer>footer>span{color:var(--subtle);font:9px/1 "Panel Mono",monospace;letter-spacing:.12em}
.detail-drawer>footer>div{display:flex;flex-wrap:wrap;gap:7px}
.spinning{animation:spin .8s linear infinite}@keyframes spin{to{transform:rotate(1turn)}}
</style>
