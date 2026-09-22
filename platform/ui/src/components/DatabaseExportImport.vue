<script setup lang="ts">
import { computed, inject, onBeforeUnmount, ref } from "vue";
import type { APIClient } from "../api";
import DatabaseImportStatus from "./DatabaseImportStatus.vue";

const props = defineProps<{ tenantId?: string | undefined; source: Record<string, unknown>; artifact: Record<string, unknown>; disabled?: boolean }>();
const emit = defineEmits<{ busy: [value: boolean] }>();
const api = inject<APIClient>("api")!;
type Destination = { id: string; site_id: string; name: string; generation: number; status: string };
type ImportJob = { id: string; database_generation: number; [key: string]: unknown };
const destinations = ref<Destination[]>([]);
const selected = ref("");
const confirmedName = ref("");
const replacement = ref(false);
const replacementApproved = ref(false);
const retainedJob = ref<ImportJob | null>(null);
const retireConfirmed = ref(false);
const retired = ref(false);
const pending = ref(false);
const monitoring = ref(false);
const loading = computed(() => pending.value || props.disabled);
const loaded = ref(false);
const failure = ref("");
const job = ref<ImportJob | null>(null);
const submitted = ref(false);
const status = ref("");
const target = computed(() => destinations.value.find(item => item.id === selected.value));
const controller = new AbortController();
const scope = () => ({ tenantId: props.tenantId, resourceId: String(props.source.site_id), signal: controller.signal });
function setBusy(value: boolean): void { pending.value = value; emit("busy", value || monitoring.value); }
function setMonitoring(value: boolean): void { monitoring.value = value; emit("busy", value || pending.value); }
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
      destinations.value.push(...response.result.items.filter(item => item.site_id === props.source.site_id && item.status === "ready"));
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
  setBusy(true); failure.value = ""; confirmedName.value = ""; replacementApproved.value = false; retainedJob.value = null; retired.value = false; retireConfirmed.value = false;
  try {
    const response = await api.invoke<ImportJob>("database.import.prepare", {
      ...scope(), expectedGeneration: target.value.generation,
      payload: { database_id: target.value.id, source_export: props.source, artifact: props.artifact, replacement: replacement.value }
    });
    job.value = response.result;
  } catch (error) { report(error); }
  finally { setBusy(false); }
}
async function run(): Promise<void> {
  if (loading.value || submitted.value || !job.value || !target.value || confirmedName.value !== target.value.name || replacement.value && !replacementApproved.value) return;
  setBusy(true); failure.value = ""; submitted.value = true; status.value = "Import running…";
  try {
    const response = await api.invoke<{ status: string }>(replacement.value ? "database.import.replace.run" : "database.import.run", {
      ...scope(), expectedGeneration: job.value.database_generation, payload: { job: job.value, ...(replacement.value ? { approval: approval(job.value, "replace") } : {}) }, idempotencyKey: crypto.randomUUID()
    });
    status.value = response.result.status;
  } catch (error) { if (status.value !== "completed") { status.value = "Outcome not confirmed. Check status before taking further action."; report(error); } }
  finally { setBusy(false); }
}
function approval(value: ImportJob, action: string): Record<string, unknown> {
  return { database_id: value.database_id, database_name: target.value?.name, generation: value.database_generation, job_digest: value.digest, restore_point_ref: value.restore_point_ref || value.id, action };
}
async function abortReplacement(): Promise<void> {
  if (loading.value || !job.value || !replacement.value || confirmedName.value !== target.value?.name) return;
  setBusy(true); failure.value = "";
  try {
    await api.invoke("database.import.replace.abort", { ...scope(), expectedGeneration: job.value.database_generation, payload: { job: job.value, approval: approval(job.value, "abort") }, idempotencyKey: crypto.randomUUID() });
    job.value = null; submitted.value = false; replacementApproved.value = false; status.value = "Original access restored. Prepare a new preview before retrying.";
  } catch (error) { report(error); }
  finally { setBusy(false); }
}
async function loadRetainedPoint(): Promise<void> {
  if (loading.value || !job.value) return;
  setBusy(true); failure.value = "";
  try { const response = await api.invoke<{ job: ImportJob }>("database.import.inspect", { ...scope(), payload: { job_id: job.value.id } }); retainedJob.value = response.result.job; }
  catch (error) { report(error); }
  finally { setBusy(false); }
}
async function retirePoint(): Promise<void> {
  if (loading.value || !retainedJob.value || !retireConfirmed.value) return;
  setBusy(true); failure.value = "";
  try {
    await api.invoke("database.import.restore_point.retire", { ...scope(), expectedGeneration: retainedJob.value.database_generation + 1, payload: { job: retainedJob.value, approval: approval(retainedJob.value, "retire") }, idempotencyKey: crypto.randomUUID() }); retired.value = true;
  } catch (error) { report(error); }
  finally { setBusy(false); }
}
onBeforeUnmount(() => { controller.abort(); emit("busy", false); });
</script>

<template>
  <section aria-label="Import verified export" class="export-import">
    <h3>Import this verified export</h3>
    <p>Import a retained server export on this site. Empty-only import is the default. Explicit replacement preserves the original tables in a recovery point and briefly blocks application writes while executing. File-upload replacement is not exposed here.</p>
    <template v-if="!job">
      <button type="button" class="button" :disabled="loading" @click="loadDestinations">{{ loaded ? 'Refresh destinations' : 'Choose destination' }}</button>
      <form v-if="loaded && destinations.length" @submit.prevent="prepare">
        <label for="import-destination">Destination database</label>
        <select id="import-destination" v-model="selected" class="select" required :disabled="loading">
          <option value="" disabled>Select a database</option>
          <option v-for="item in destinations" :key="item.id" :value="item.id">{{ item.name }}</option>
        </select>
        <label v-if="api.available('database.import.replace.run')"><input v-model="replacement" type="checkbox" :disabled="loading"> Replace existing tables with a retained recovery point</label>
        <button type="submit" class="button" :disabled="loading || !target">Check import destination</button>
      </form>
      <p v-if="loaded && !destinations.length">No other ready databases on this site. Create an empty database first.</p>
    </template>
    <template v-else>
      <p>Destination: {{ target?.name }} · generation {{ job.database_generation }}. {{ replacement ? 'Preview does not block writers. Approval starts a scoped writer fence; unsupported or shared writers are refused.' : 'The server checked that it is empty and will check again before importing.' }}</p>
      <p class="job-id">Job: {{ job.id }}</p>
      <p v-if="replacement" class="job-id">Intended retained recovery point: {{ job.id }}</p>
      <form v-if="!submitted" @submit.prevent="run">
        <label for="import-confirmation">Type {{ target?.name }} to confirm import</label>
        <input id="import-confirmation" v-model="confirmedName" class="input" autocomplete="off" required :disabled="loading">
        <label v-if="replacement"><input v-model="replacementApproved" type="checkbox" :disabled="loading"> I approve replacing {{ target?.name }} at generation {{ job.database_generation }}, retaining original tables at recovery point {{ job.id }}.</label>
        <button type="submit" class="button button-primary" :disabled="loading || confirmedName !== target?.name || replacement && !replacementApproved">{{ replacement ? 'Approve and replace tables' : 'Import into empty database' }}</button>
        <button type="button" class="button" :disabled="loading" @click="job=null;confirmedName=''">Change destination</button>
      </form>
      <DatabaseImportStatus v-if="submitted" :tenant-id="tenantId" :site-id="String(source.site_id)" :job-id="job.id" :running="pending" :status="status" @busy="setMonitoring" @complete="failure='';status='completed'" />
      <template v-if="replacement && submitted && status !== 'completed'">
        <p>If preparation failed after closing application access, abort reconciles the original state. Active or ambiguous replacements must be recovered first and cannot be aborted here.</p>
        <button type="button" class="button" :disabled="loading" @click="abortReplacement">Abort safe unfinished replacement and restore access</button>
      </template>
      <template v-if="replacement && status === 'completed' && !retired">
        <button v-if="!retainedJob" type="button" class="button" :disabled="loading" @click="loadRetainedPoint">Inspect retained recovery point</button>
        <template v-else>
          <p class="job-id">Retained original: {{ retainedJob.restore_point_ref }}. Keep it until you have verified the replacement. Retiring permanently deletes only these retained original tables.</p>
          <label><input v-model="retireConfirmed" type="checkbox" :disabled="loading"> Permanently retire {{ retainedJob.restore_point_ref }} for {{ target?.name }}; current generation {{ retainedJob.database_generation + 1 }} remains.</label>
          <button type="button" class="button" :disabled="loading || !retireConfirmed" @click="retirePoint">Permanently retire retained original</button>
        </template>
      </template>
      <p v-if="retired">Retained original deleted by explicit retirement. Current replacement data is unchanged.</p>
    </template>
    <p v-if="failure" role="alert" class="import-error">{{ failure }}</p>
  </section>
</template>

<style scoped>
.export-import{margin:24px 0;padding-top:16px;border-top:1px solid var(--border)}h3{font-size:16px}p,label{font-size:13px;overflow-wrap:anywhere}p{color:var(--muted)}form{display:grid;gap:12px;margin:16px 0}form .button{justify-self:start}.job-id{overflow-wrap:anywhere}.import-error{color:var(--critical)}input,select{max-width:100%;box-sizing:border-box}
</style>
