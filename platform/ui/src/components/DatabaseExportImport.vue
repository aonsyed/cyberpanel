<script setup lang="ts">
import { computed, inject, onBeforeUnmount, ref } from "vue";
import type { APIClient } from "../api";

const props = defineProps<{ tenantId?: string | undefined; source: Record<string, unknown>; artifact: Record<string, unknown>; disabled?: boolean }>();
const emit = defineEmits<{ busy: [value: boolean] }>();
const api = inject<APIClient>("api")!;
type Destination = { id: string; site_id: string; name: string; generation: number; status: string };
type ImportJob = { id: string; database_generation: number; [key: string]: unknown };
const destinations = ref<Destination[]>([]);
const selected = ref("");
const confirmedName = ref("");
const pending = ref(false);
const loading = computed(() => pending.value || props.disabled);
const loaded = ref(false);
const failure = ref("");
const job = ref<ImportJob | null>(null);
const submitted = ref(false);
const status = ref("");
const target = computed(() => destinations.value.find(item => item.id === selected.value));
const controller = new AbortController();
const scope = () => ({ tenantId: props.tenantId, resourceId: String(props.source.site_id), signal: controller.signal });
function setBusy(value: boolean): void { pending.value = value; emit("busy", value); }
function report(error: unknown): void { failure.value = error instanceof Error ? error.message : "Import request failed."; }
async function loadDestinations(): Promise<void> {
  if (loading.value || job.value) return;
  setBusy(true); failure.value = ""; loaded.value = false; destinations.value = []; selected.value = "";
  try {
    let cursor = "";
    const seen = new Set<string>();
    do {
      const response = await api.invoke<{ items: Destination[]; next_cursor?: string }>("database.database.list", {
        tenantId: props.tenantId, payload: { limit: 100, cursor: cursor || undefined }, signal: controller.signal
      });
      destinations.value.push(...response.result.items.filter(item => item.site_id === props.source.site_id && item.id !== props.source.database_id && item.status === "ready"));
      cursor = response.result.next_cursor || "";
      if (cursor && seen.has(cursor)) throw new Error("Database listing repeated a page. Refresh destinations to try again.");
      seen.add(cursor);
    } while (cursor);
    loaded.value = true;
  } catch (error) { destinations.value = []; report(error); }
  finally { setBusy(false); }
}
async function prepare(): Promise<void> {
  if (loading.value || !target.value || job.value) return;
  setBusy(true); failure.value = ""; confirmedName.value = "";
  try {
    const response = await api.invoke<ImportJob>("database.import.prepare", {
      ...scope(), expectedGeneration: target.value.generation,
      payload: { database_id: target.value.id, source_export: props.source, artifact: props.artifact }
    });
    job.value = response.result;
  } catch (error) { report(error); }
  finally { setBusy(false); }
}
async function run(): Promise<void> {
  if (loading.value || submitted.value || !job.value || !target.value || confirmedName.value !== target.value.name) return;
  setBusy(true); failure.value = ""; submitted.value = true; status.value = "Import running…";
  try {
    const response = await api.invoke<{ status: string }>("database.import.run", {
      ...scope(), expectedGeneration: job.value.database_generation, payload: { job: job.value }, idempotencyKey: crypto.randomUUID()
    });
    status.value = response.result.status;
  } catch (error) { status.value = "Outcome not confirmed. Check status before taking further action."; report(error); }
  finally { setBusy(false); }
}
async function inspect(): Promise<void> {
  if (loading.value || !job.value || !submitted.value) return;
  setBusy(true); failure.value = "";
  try {
    const response = await api.invoke<{ status: string }>("database.import.inspect", { ...scope(), payload: { job_id: job.value.id } });
    status.value = response.result.status;
  } catch (error) { report(error); }
  finally { setBusy(false); }
}
onBeforeUnmount(() => { controller.abort(); emit("busy", false); });
</script>

<template>
  <section aria-label="Import verified export" class="export-import">
    <h3>Import this verified export</h3>
    <p>Copy the exported tables into an empty database on this site. Existing tables are never replaced. This uses the retained server export, not a file upload.</p>
    <template v-if="!job">
      <button type="button" class="button" :disabled="loading" @click="loadDestinations">{{ loaded ? 'Refresh destinations' : 'Choose destination' }}</button>
      <form v-if="loaded && destinations.length" @submit.prevent="prepare">
        <label for="import-destination">Destination database</label>
        <select id="import-destination" v-model="selected" class="select" required :disabled="loading">
          <option value="" disabled>Select an empty database</option>
          <option v-for="item in destinations" :key="item.id" :value="item.id">{{ item.name }}</option>
        </select>
        <button type="submit" class="button" :disabled="loading || !target">Check import destination</button>
      </form>
      <p v-if="loaded && !destinations.length">No other ready databases on this site. Create an empty database first.</p>
    </template>
    <template v-else>
      <p>Destination: {{ target?.name }} · generation {{ job.database_generation }}. The server checked that it is empty and will check again before importing.</p>
      <p class="job-id">Job: {{ job.id }}</p>
      <form v-if="!submitted" @submit.prevent="run">
        <label for="import-confirmation">Type {{ target?.name }} to confirm import</label>
        <input id="import-confirmation" v-model="confirmedName" class="input" autocomplete="off" required :disabled="loading">
        <button type="submit" class="button button-primary" :disabled="loading || confirmedName !== target?.name">Import into empty database</button>
        <button type="button" class="button" :disabled="loading" @click="job=null;confirmedName=''">Change destination</button>
      </form>
      <p v-if="status" role="status">{{ status === 'completed' ? 'Import completed and verified.' : status }}</p>
      <button v-if="submitted" type="button" class="button" :disabled="loading" @click="inspect">Check import status</button>
    </template>
    <p v-if="failure" role="alert" class="import-error">{{ failure }}</p>
  </section>
</template>

<style scoped>
.export-import{margin:24px 0;padding-top:16px;border-top:1px solid var(--border)}h3{font-size:16px}p,label{font-size:13px}p{color:var(--muted)}form{display:grid;gap:12px;margin:16px 0}form .button{justify-self:start}.job-id{overflow-wrap:anywhere}.import-error{color:var(--critical)}input,select{max-width:100%;box-sizing:border-box}
</style>
