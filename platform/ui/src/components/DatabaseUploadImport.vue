<script setup lang="ts">
import { inject, onBeforeUnmount, onMounted, ref } from "vue";
import type { APIClient } from "../api";
import DatabaseImportStatus from "./DatabaseImportStatus.vue";

const props = defineProps<{ tenantId?: string | undefined; resource: Record<string, unknown> }>();
const emit = defineEmits<{ close: []; complete: [] }>();
const api = inject<APIClient>("api")!;
type Intent = { id: string; digest: string; bytes: number; payload_digest: string; compression: "none" | "gzip"; database_id: string; database_generation: number; site_id: string; expires_at: string; [key: string]: unknown };
type Artifact = { bytes: number; digest: string; compression: "none" | "gzip"; [key: string]: unknown };
type UploadState = { next_offset: number; artifact?: Artifact };
type Job = { id: string; database_generation: number; [key: string]: unknown };
const file = ref<File | null>(null);
const input = ref<HTMLInputElement | null>(null);
const busy = ref(false);
const monitoring = ref(false);
const failure = ref("");
const progress = ref("");
const intent = ref<Intent | null>(null);
const artifact = ref<Artifact | null>(null);
const job = ref<Job | null>(null);
const confirmation = ref("");
const submitted = ref(false);
const status = ref("");
const controller = new AbortController();
let beginIdentity = requestIdentity();
function requestIdentity(): { idempotencyKey: string; requestId: string } { return { idempotencyKey: crypto.randomUUID(), requestId: `req_${crypto.randomUUID().replaceAll("-", "")}` }; }
const scope = () => ({ tenantId: props.tenantId, resourceId: String(props.resource.site_id), expectedGeneration: Number(props.resource.generation), signal: controller.signal });
function uploadIdentity(action: string, offset = 0): { idempotencyKey: string; requestId: string } {
  return { idempotencyKey: `upload-${intent.value!.digest}-${action}-${offset}`, requestId: `req_${intent.value!.digest}_${action}_${offset}` };
}
function choose(event: Event): void {
  if (busy.value || intent.value) return;
  file.value = (event.target as HTMLInputElement).files?.[0] || null;
  failure.value = ""; progress.value = ""; beginIdentity = requestIdentity();
  if (file.value && (file.value.size === 0 || file.value.size > 64 * 1024 * 1024)) { failure.value = "Choose a nonempty SQL or gzip file no larger than 64 MiB."; file.value = null; }
}
function report(error: unknown): void { failure.value = error instanceof Error ? error.message : "Upload request failed."; }
async function upload(): Promise<void> {
  if (busy.value || !file.value || job.value) return;
  busy.value = true; failure.value = "";
  try {
    progress.value = "Checking file…";
    const data = new Uint8Array(await file.value.arrayBuffer());
    const digest = [...new Uint8Array(await crypto.subtle.digest("SHA-256", data))].map(value => value.toString(16).padStart(2, "0")).join("");
    const compression = data[0] === 0x1f && data[1] === 0x8b ? "gzip" : "none";
    if (/\.gz$/i.test(file.value.name) && compression !== "gzip") throw new Error("This .gz file does not contain gzip data.");
    if (!intent.value) {
      const begun = await api.invoke<{ intent: Intent; state: UploadState }>("database.upload.begin", {
        ...scope(), ...beginIdentity, payload: { database_id: props.resource.id, compression, bytes: data.length, digest }
      });
      intent.value = begun.result.intent;
    }
    const ticket = intent.value;
    if (ticket.bytes !== data.length || ticket.payload_digest !== digest || ticket.compression !== compression || ticket.database_id !== props.resource.id || ticket.database_generation !== Number(props.resource.generation) || ticket.site_id !== props.resource.site_id) throw new Error("The upload no longer matches this file and destination. Start over.");
    const current = await api.invoke<UploadState>("database.upload.status", { ...scope(), payload: { intent: ticket } });
    let offset = current.result.next_offset;
    if (!Number.isSafeInteger(offset) || offset < 0 || offset > data.length) throw new Error("Invalid upload progress.");
    while (offset < data.length) {
      const end = Math.min(offset + 256 * 1024, data.length);
      let binary = "";
      // Small batches avoid a spread/call-stack overflow on large chunks.
      for (let start = offset; start < end; start += 8192) binary += String.fromCharCode(...data.subarray(start, Math.min(start + 8192, end)));
      const chunk = await api.invoke<UploadState>("database.upload.chunk", {
        ...scope(), ...uploadIdentity("chunk", offset), payload: { intent: ticket, offset, data: btoa(binary) }
      });
      if (!Number.isSafeInteger(chunk.result.next_offset) || chunk.result.next_offset < end || chunk.result.next_offset > data.length) throw new Error("Invalid upload acknowledgement.");
      offset = chunk.result.next_offset; progress.value = `Uploading… ${Math.round(offset / data.length * 100)}%`;
    }
    const finalized = await api.invoke<UploadState>("database.upload.finish", { ...scope(), ...uploadIdentity("finish"), payload: { intent: ticket } });
    artifact.value = finalized.result.artifact || null;
    if (!artifact.value || artifact.value.digest !== digest || artifact.value.bytes !== data.length || artifact.value.compression !== compression) throw new Error("Server upload integrity check failed.");
    progress.value = "Upload verified. Checking the destination…";
    const prepared = await api.invoke<Job>("database.import.prepare", {
      ...scope(), payload: { database_id: props.resource.id, upload_source: ticket, artifact: artifact.value }
    });
    job.value = prepared.result;
    progress.value = "Upload verified. Confirm the empty destination to import.";
  } catch (error) { progress.value = "Upload not ready. Keep this dialog open to retry or start over."; report(error); }
  finally { busy.value = false; }
}
async function startOver(): Promise<void> {
  if (busy.value || submitted.value) return;
  busy.value = true; failure.value = "";
  try {
    if (intent.value && new Date(intent.value.expires_at).getTime() > Date.now()) await api.invoke<UploadState>("database.upload.discard", { ...scope(), ...uploadIdentity("discard"), payload: { intent: intent.value } });
    intent.value = null; artifact.value = null; job.value = null; file.value = null; confirmation.value = "";
    if (input.value) input.value.value = "";
    beginIdentity = requestIdentity(); progress.value = "Selection cleared. Finalized server artifacts expire automatically.";
  } catch (error) { report(error); }
  finally { busy.value = false; }
}
async function run(): Promise<void> {
  if (busy.value || submitted.value || !job.value || confirmation.value !== String(props.resource.name)) return;
  busy.value = true; submitted.value = true; failure.value = ""; status.value = "Import running…";
  try {
    const response = await api.invoke<{ status: string }>("database.import.run", { ...scope(), payload: { job: job.value }, ...requestIdentity() });
    status.value = response.result.status;
    if (status.value === "completed") emit("complete");
  } catch (error) { if (status.value !== "completed") { status.value = "Outcome not confirmed. Check status before taking further action."; report(error); } }
  finally { busy.value = false; }
}
function close(): void { if (!busy.value && !monitoring.value) emit("close"); }
function keydown(event: KeyboardEvent): void { if (event.key === "Escape") close(); }
onMounted(() => window.addEventListener("keydown", keydown));
onBeforeUnmount(() => { controller.abort(); window.removeEventListener("keydown", keydown); });
</script>

<template>
  <div class="upload-layer" @mousedown.self="close">
    <aside class="upload-dialog" role="dialog" aria-modal="true" aria-label="Import SQL file">
      <header><h2>Import into {{ resource.name }}</h2><button type="button" class="button" :disabled="busy || monitoring" @click="close">Close</button></header>
      <p>SQL or gzip, up to 64 MiB. The destination must be empty. Existing tables are never replaced. Data is loaded into an isolated database and verified before promotion.</p>
      <p>Use a table-only dump; routines, triggers, events and views are not supported by this import path yet. Incomplete uploads expire after one hour.</p>
      <form v-if="!job" @submit.prevent="upload">
        <label for="upload-sql-file">SQL or gzip file</label>
        <input id="upload-sql-file" ref="input" type="file" accept=".sql,.gz,application/sql,application/gzip" :disabled="busy || !!intent" @change="choose">
        <button type="submit" class="button button-primary" :disabled="busy || !file">{{ intent ? 'Resume upload' : 'Upload and verify' }}</button>
      </form>
      <p v-if="progress" role="status">{{ progress }}</p>
      <p v-if="intent" class="identifier">Upload: {{ intent.id }} · expires {{ new Date(intent.expires_at).toLocaleTimeString() }}</p>
      <template v-if="job">
        <p class="identifier">Job: {{ job.id }}</p>
        <form v-if="!submitted" @submit.prevent="run">
          <label for="upload-import-confirmation">Type {{ resource.name }} to confirm import</label>
          <input id="upload-import-confirmation" v-model="confirmation" class="input" autocomplete="off" :disabled="busy" required>
          <button type="submit" class="button button-primary" :disabled="busy || confirmation !== String(resource.name)">Import uploaded SQL</button>
        </form>
        <DatabaseImportStatus v-if="submitted" :tenant-id="tenantId" :site-id="String(resource.site_id)" :job-id="job.id" :running="busy" :status="status" @busy="monitoring=$event" @complete="failure='';status='completed';emit('complete')" />
      </template>
      <button v-if="(file || intent) && !submitted" type="button" class="button" :disabled="busy" @click="startOver">Start over</button>
      <p v-if="failure" role="alert" class="upload-error">{{ failure }}</p>
    </aside>
  </div>
</template>

<style scoped>
.upload-layer{position:fixed;inset:0;z-index:80;background:rgba(0,5,8,.62);display:flex;justify-content:flex-end}.upload-dialog{width:min(760px,100vw);height:100%;overflow:auto;padding:24px;background:var(--surface);border-left:1px solid var(--border);box-sizing:border-box}.upload-dialog header{display:flex;justify-content:space-between;align-items:flex-start;gap:16px}.upload-dialog h2{margin:0;font-size:21px;overflow-wrap:anywhere}.upload-dialog p{font-size:13px;color:var(--muted)}.upload-dialog form{display:grid;gap:12px;margin:24px 0}.upload-dialog form .button{justify-self:start}.upload-dialog label{font-size:13px}.upload-dialog input{min-width:0;max-width:100%;box-sizing:border-box}.identifier{overflow-wrap:anywhere}.upload-error{color:var(--critical)!important}
</style>
