<script setup lang="ts">
import { computed, inject, onMounted, ref, watch } from "vue";
import { PhArrowClockwise as ArrowClockwise, PhArrowRight as ArrowRight, PhFunnelSimple as FunnelSimple, PhMagnifyingGlass as MagnifyingGlass, PhPlus as Plus, PhWarningCircle as WarningCircle } from "@phosphor-icons/vue";
import type { APIClient } from "../api";
import type { ActionDefinition, PageDefinition } from "../domain";
import { sessionStore } from "../store";
import ActionDrawer from "./ActionDrawer.vue";
import DatabaseConsole from "./DatabaseConsole.vue";
import DataTable from "./DataTable.vue";

const props = defineProps<{ definition: PageDefinition }>();
const api = inject<APIClient>("api")!;
const rows = ref<Record<string, unknown>[]>([]);
const loading = ref(true);
const error = ref("");
const search = ref("");
const sortKey = ref("");
const sortDirection = ref<"asc" | "desc">("asc");
const cursor = ref("");
const nextCursor = ref("");
const previousCursors = ref<string[]>([]);
const total = ref<number | null>(null);
const activeAction = ref<ActionDefinition | null>(null);
const activeResource = ref<Record<string, unknown> | null>(null);

const availableCreate = computed(() => props.definition.createAction && api.available(props.definition.createAction.operation) ? props.definition.createAction : undefined);
const availableGlobalActions = computed(() => (props.definition.globalActions || []).filter((action) => api.available(action.operation)));
const availableRowActions = computed(() => (props.definition.rowActions || []).filter((action) => api.available(action.operation)));
const listAvailable = computed(() => api.available(props.definition.listOperation));
const tenantID = computed(() => props.definition.scope === "installation" ? undefined : sessionStore.state.tenantId || undefined);
const activeTenantID = computed(() => activeAction.value?.scope === "installation" ? undefined : activeAction.value?.scope === "tenant" ? sessionStore.state.tenantId || undefined : tenantID.value);
const visibleRows = computed(() => {
  const term = search.value.trim().toLocaleLowerCase();
  const filtered = term ? rows.value.filter((row) => Object.values(row).some((value) => primitiveText(value).toLocaleLowerCase().includes(term))) : rows.value.slice();
  if (!sortKey.value) return filtered;
  const direction = sortDirection.value === "asc" ? 1 : -1;
  return filtered.sort((left, right) => compare(valueAt(left, sortKey.value), valueAt(right, sortKey.value)) * direction);
});

watch(() => props.definition.id, () => { search.value = ""; cursor.value = ""; previousCursors.value = []; activeAction.value = null; void load(); });
onMounted(() => void load());

async function load(): Promise<void> {
  loading.value = true;
  error.value = "";
  if (!listAvailable.value) {
    rows.value = [];
    total.value = null;
    error.value = "This capability is not installed or enabled on the current node.";
    loading.value = false;
    return;
  }
  try {
    const response = await api.invoke<unknown>(props.definition.listOperation, {
      tenantId: tenantID.value,
      payload: { cursor: cursor.value || undefined, limit: 100 }
    });
    const normalized = normalizeCollection(response.result);
    rows.value = normalized.items;
    total.value = normalized.total;
    nextCursor.value = normalized.nextCursor;
  } catch (cause) {
    rows.value = [];
    error.value = cause instanceof Error ? cause.message : "The resource projection could not be loaded.";
  } finally { loading.value = false; }
}

function openAction(action: ActionDefinition, resource: Record<string, unknown> | null = null): void {
  activeAction.value = action;
  activeResource.value = resource;
}
function complete(): void { void load(); }
function sort(key: string): void {
  if (sortKey.value === key) sortDirection.value = sortDirection.value === "asc" ? "desc" : "asc";
  else { sortKey.value = key; sortDirection.value = "asc"; }
}
function nextPage(): void {
  if (!nextCursor.value) return;
  previousCursors.value.push(cursor.value);
  cursor.value = nextCursor.value;
  void load();
}
function previousPage(): void {
  if (!previousCursors.value.length) return;
  cursor.value = previousCursors.value.pop() || "";
  void load();
}
function valueAt(row: Record<string, unknown>, key: string): unknown { return key.split(".").reduce<unknown>((value, part) => value && typeof value === "object" ? (value as Record<string, unknown>)[part] : undefined, row); }
function compare(left: unknown, right: unknown): number { if (typeof left === "number" && typeof right === "number") return left - right; return primitiveText(left).localeCompare(primitiveText(right), undefined, { numeric: true, sensitivity: "base" }); }
function primitiveText(value: unknown): string { if (value === null || value === undefined) return ""; if (typeof value === "object") return JSON.stringify(value); return String(value); }
function normalizeCollection(result: unknown): { items: Record<string, unknown>[]; total: number | null; nextCursor: string } {
  if (Array.isArray(result)) return { items: result.filter(isRecord), total: result.length, nextCursor: "" };
  if (!isRecord(result)) return { items: [], total: 0, nextCursor: "" };
  const raw = Array.isArray(result.items) ? result.items : Array.isArray(result.resources) ? result.resources : Array.isArray(result.results) ? result.results : [];
  return { items: raw.filter(isRecord), total: typeof result.total === "number" ? result.total : raw.length, nextCursor: typeof result.next_cursor === "string" ? result.next_cursor : "" };
}
function isRecord(value: unknown): value is Record<string, unknown> { return Boolean(value) && typeof value === "object" && !Array.isArray(value); }
</script>

<template>
  <main class="resource-page">
    <header class="page-head">
      <div><p class="eyebrow">{{ definition.resourceKind }}</p><h2>{{ definition.title }}</h2><p>{{ definition.description }}</p></div>
      <div class="head-actions">
        <button v-for="action in availableGlobalActions" :key="action.id" class="button" type="button" @click="openAction(action)">{{ action.label }}</button>
        <button v-if="availableCreate" class="button button-primary" type="button" @click="openAction(availableCreate)"><Plus :size="16" weight="bold"/>{{ availableCreate.label }}</button>
      </div>
    </header>

    <section class="resource-toolbar" aria-label="Resource controls">
      <label class="resource-search"><MagnifyingGlass :size="16"/><span class="sr-only">Filter resources</span><input v-model="search" type="search" placeholder="Filter the current projection"/></label>
      <span class="resource-count"><strong>{{ total ?? rows.length }}</strong> {{ total === 1 ? "resource" : "resources" }}</span>
      <button class="button button-small" type="button" :disabled="loading" @click="load"><ArrowClockwise :size="15" :class="{ spinning: loading }"/>Refresh</button>
    </section>

    <section v-if="loading" class="loading-table" aria-label="Loading resources" aria-busy="true"><div v-for="index in 8" :key="index" class="skeleton-row"><span class="skeleton"></span></div></section>
    <section v-else-if="error" class="resource-problem" role="alert"><WarningCircle :size="28"/><div><strong>Projection unavailable</strong><p>{{ error }}</p></div><button class="button button-small" type="button" @click="load">Retry</button></section>
    <section v-else-if="visibleRows.length === 0" class="empty-state">
      <div class="empty-symbol"><FunnelSimple v-if="search" :size="28"/><span v-else></span></div>
      <h3>{{ search ? "No matching resources" : definition.emptyTitle }}</h3><p>{{ search ? "Change or clear the current filter." : definition.emptyBody }}</p>
      <button v-if="search" class="button" type="button" @click="search=''">Clear filter</button>
      <button v-else-if="availableCreate" class="button button-primary" type="button" @click="openAction(availableCreate)">{{ availableCreate.label }}<ArrowRight :size="15"/></button>
    </section>
    <template v-else>
      <DataTable :columns="definition.columns" :rows="visibleRows" :actions="availableRowActions" @action="openAction" @sort="sort" @select="(row) => definition.detailOperation && api.available(definition.detailOperation) ? openAction({id:'details',label:'Details',operation:definition.detailOperation,mutating:false},row) : undefined"/>
      <footer v-if="nextCursor || previousCursors.length" class="pagination"><button class="button button-small" type="button" :disabled="!previousCursors.length" @click="previousPage">Previous</button><span class="mono">CURSOR PAGE {{ previousCursors.length + 1 }}</span><button class="button button-small" type="button" :disabled="!nextCursor" @click="nextPage">Next</button></footer>
    </template>

    <DatabaseConsole v-if="activeAction?.operation === 'database.console.issue' && activeResource" :tenant-id="activeTenantID" :resource="activeResource" @close="activeAction=null;activeResource=null"/>
    <ActionDrawer v-else-if="activeAction" :action="activeAction" :tenant-id="activeTenantID" :resource="activeResource" :expected-generation="Number(activeResource?.generation || 0)" @close="activeAction=null;activeResource=null" @complete="complete"/>
  </main>
</template>

<style scoped>
.resource-page{padding:34px clamp(18px,3.2vw,48px) 64px;max-width:1700px;margin:0 auto}.page-head{display:flex;justify-content:space-between;align-items:flex-end;gap:24px;margin:0 0 28px}.page-head h2{margin:5px 0 8px;font-size:clamp(27px,3vw,38px);line-height:1;letter-spacing:-.045em}.page-head>div>p:last-child{margin:0;color:var(--muted);max-width:72ch}.eyebrow{margin:0;color:var(--accent);font:10px/1 "Panel Mono",monospace;letter-spacing:.13em;text-transform:uppercase}.head-actions{display:flex;flex-wrap:wrap;justify-content:flex-end;gap:8px}.resource-toolbar{min-height:52px;margin-bottom:12px;display:flex;align-items:center;gap:12px}.resource-search{height:38px;min-width:min(420px,45vw);display:flex;align-items:center;gap:8px;padding:0 11px;border:1px solid var(--border);border-radius:var(--radius);background:var(--surface)}.resource-search svg{color:var(--subtle)}.resource-search input{width:100%;border:0;outline:0;background:transparent;color:var(--text)}.resource-count{margin-left:auto;color:var(--subtle);font-size:12px}.resource-count strong{color:var(--text);font-family:"Panel Mono",monospace}.loading-table{border:1px solid var(--border);border-radius:var(--radius);background:var(--surface)}.resource-problem{min-height:180px;border:1px solid color-mix(in srgb,var(--critical),transparent 55%);background:color-mix(in srgb,var(--critical),transparent 94%);display:flex;align-items:center;justify-content:center;gap:14px;padding:24px}.resource-problem>svg{color:var(--critical)}.resource-problem strong{font-size:15px}.resource-problem p{margin:5px 0 0;color:var(--muted)}.resource-problem .button{margin-left:24px}.empty-state{min-height:390px;border:1px dashed var(--border-strong);border-radius:var(--radius);display:grid;place-content:center;justify-items:center;text-align:center;padding:40px;background:var(--surface)}.empty-symbol{width:54px;height:54px;display:grid;place-items:center;border:1px solid var(--border);border-radius:50%;color:var(--subtle);margin-bottom:15px}.empty-symbol span{width:15px;height:15px;border:2px solid var(--accent);transform:rotate(45deg)}.empty-state h3{font-size:20px;margin:0}.empty-state p{color:var(--muted);max-width:48ch;margin:8px 0 21px}.pagination{display:flex;justify-content:flex-end;align-items:center;gap:12px;padding:15px 0}.pagination span{color:var(--subtle);font-size:10px}.spinning{animation:spin .8s linear infinite}@keyframes spin{to{transform:rotate(1turn)}}.sr-only{position:absolute;width:1px;height:1px;padding:0;margin:-1px;overflow:hidden;clip:rect(0,0,0,0);white-space:nowrap;border:0}
@media(max-width:760px){.resource-page{padding:23px 14px 50px}.page-head{align-items:flex-start;flex-direction:column}.head-actions{justify-content:flex-start}.resource-toolbar{flex-wrap:wrap}.resource-search{min-width:100%}.resource-count{margin-left:0;margin-right:auto}}
</style>
