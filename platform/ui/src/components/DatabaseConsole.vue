<script setup lang="ts">
import { computed, inject, onBeforeUnmount, onMounted, ref, watch } from "vue";
import type { APIClient } from "../api";

const props = defineProps<{ tenantId?: string | undefined; resource: Record<string, unknown> }>();
const emit = defineEmits<{ close: [] }>();
const api = inject<APIClient>("api")!;
const principal = ref("");
const busy = ref(false);
const failure = ref("");
const exportCompression = ref<"none" | "gzip">("gzip");
const exportProgress = ref("");
type ExportArtifact = { bytes: number; digest: string; compression: "none" | "gzip" };
const statement = ref("SELECT DATABASE() AS current_database;");
const session = ref<{ id: string; site_id: string; generation: number; expires_at: string } | null>(null);
const metadata = ref<{ entries: Array<{ object_name: string; kind: string }> }>({ entries: [] });
const result = ref<{ columns: Array<{ name: string }>; rows: Array<{ values: Array<{ kind: string; text?: string }> }>; truncated: boolean } | null>(null);
const options = computed(() => Array.isArray(props.resource.console_principals) ? props.resource.console_principals.flatMap(value => {
  if (!value || typeof value !== "object" || !("label" in value) || !("value" in value) || typeof value.label !== "string" || typeof value.value !== "string") return [];
  return [{ label: value.label, value: value.value }];
}) : []);
const tables = computed(() => [...new Set(metadata.value.entries.filter(entry => entry.kind === "table" || entry.kind === "view").map(entry => entry.object_name))]);
let openingKey = crypto.randomUUID();
watch(principal, () => { openingKey = crypto.randomUUID(); });
const controller = new AbortController();
async function open(): Promise<void> {
  if (!principal.value || busy.value) return;
  busy.value = true; failure.value = "";
  try {
    const response = await api.invoke<NonNullable<typeof session.value>>("database.console.issue", {
      tenantId: props.tenantId, resourceId: String(props.resource.id), expectedGeneration: Number(props.resource.generation),
      payload: { principal_id: principal.value }, idempotencyKey: openingKey, signal: controller.signal
    });
    session.value = response.result;
    const schema = await api.invoke<typeof metadata.value>("database.workspace.metadata", {
      tenantId: props.tenantId, resourceId: session.value.site_id, expectedGeneration: session.value.generation,
      payload: { session_id: session.value.id }, signal: controller.signal
    });
    metadata.value = schema.result;
  } catch (error) { failure.value = error instanceof Error ? error.message : "Could not open database console."; }
  finally { busy.value = false; }
}
async function query(): Promise<void> {
  if (!session.value || busy.value) return;
  busy.value = true; failure.value = ""; result.value = null;
  try {
    const response = await api.invoke<NonNullable<typeof result.value>>("database.workspace.query", {
      tenantId: props.tenantId, resourceId: session.value.site_id, expectedGeneration: session.value.generation,
      payload: { session_id: session.value.id, statement: statement.value }, signal: controller.signal
    });
    result.value = response.result;
  } catch (error) { failure.value = error instanceof Error ? error.message : "Query failed."; }
  finally { busy.value = false; }
}
async function exportDatabase(): Promise<void> {
  if (!session.value || busy.value) return;
  busy.value = true; failure.value = ""; exportProgress.value = "Preparing export…";
  const scope = { tenantId: props.tenantId, resourceId: session.value.site_id, expectedGeneration: session.value.generation, signal: controller.signal };
  const sessionID = session.value.id;
  try {
    const prepared = await api.invoke<Record<string, unknown>>("database.workspace.export_prepare", {
      ...scope, payload: { session_id: sessionID, options: { compression: exportCompression.value, selection: { schema: true, data: true } } }
    });
    exportProgress.value = "Exporting database…";
    const exported = await api.invoke<{ artifact: ExportArtifact }>("database.workspace.export", {
      ...scope, payload: { session_id: sessionID, job: prepared.result }, idempotencyKey: crypto.randomUUID()
    });
    const artifact = exported.result.artifact;
    if (!artifact || !Number.isSafeInteger(artifact.bytes) || artifact.bytes < 1 || artifact.bytes > 64 * 1024 * 1024 || !/^[a-f0-9]{64}$/.test(artifact.digest)) throw new Error("Invalid export descriptor.");
    const bytes = new Uint8Array(artifact.bytes);
    let offset = 0;
    while (offset < bytes.length) {
      const response = await api.invoke<{ offset: number; data: string; eof: boolean; digest: string }>("database.workspace.export_download", {
        ...scope, payload: { session_id: sessionID, job: prepared.result, artifact, offset, length: 256 * 1024 }
      });
      const chunk = response.result;
      const data = Uint8Array.from(atob(chunk.data), value => value.charCodeAt(0));
      const expected = Math.min(256 * 1024, bytes.length - offset);
      if (chunk.offset !== offset || data.length !== expected || chunk.eof !== (offset + expected === bytes.length)) throw new Error("Export download was incomplete.");
      const digest = [...new Uint8Array(await crypto.subtle.digest("SHA-256", data))].map(value => value.toString(16).padStart(2, "0")).join("");
      if (digest !== chunk.digest) throw new Error("Export chunk integrity check failed.");
      bytes.set(data, offset); offset += data.length;
      exportProgress.value = `Downloading export… ${Math.round(offset / bytes.length * 100)}%`;
    }
    const digest = [...new Uint8Array(await crypto.subtle.digest("SHA-256", bytes))].map(value => value.toString(16).padStart(2, "0")).join("");
    if (digest !== artifact.digest) throw new Error("Export integrity check failed. No file was saved.");
    if (controller.signal.aborted) throw new DOMException("Export cancelled", "AbortError");
    const url = URL.createObjectURL(new Blob([bytes], { type: artifact.compression === "gzip" ? "application/gzip" : "application/sql" }));
    const link = document.createElement("a");
    link.href = url; link.download = `${String(props.resource.name).replace(/[^a-zA-Z0-9_-]/g, "_")}.sql${artifact.compression === "gzip" ? ".gz" : ""}`;
    document.body.append(link); link.click(); link.remove();
    setTimeout(() => URL.revokeObjectURL(url), 1000);
    exportProgress.value = "Export downloaded and verified.";
  } catch (error) { exportProgress.value = ""; failure.value = error instanceof Error ? error.message : "Export failed."; }
  finally { busy.value = false; }
}
function keydown(event: KeyboardEvent): void { if (event.key === "Escape") emit("close"); }
onMounted(() => { principal.value = options.value[0]?.value || ""; window.addEventListener("keydown", keydown); });
onBeforeUnmount(() => { controller.abort(); window.removeEventListener("keydown", keydown); });
</script>

<template>
  <div class="console-layer" @mousedown.self="emit('close')">
    <aside class="database-console" role="dialog" aria-modal="true" aria-label="Database console">
      <header><div><h2>{{ resource.name }} · SQL console</h2><p>Queries run with the selected principal’s grants, never the database administrator.</p></div><button class="button" type="button" @click="emit('close')">Close</button></header>
      <form v-if="!session" @submit.prevent="open">
        <label for="console-principal">Database principal</label>
        <select id="console-principal" v-model="principal" class="select" required :disabled="busy"><option value="" disabled>Select a principal</option><option v-for="option in options" :key="option.value" :value="option.value">{{ option.label }}</option></select>
        <p v-if="!options.length">Add a principal with database grants before opening a console.</p>
        <button class="button button-primary" type="submit" :disabled="busy || !principal">{{ busy ? 'Opening…' : 'Open console' }}</button>
      </form>
      <template v-else>
        <p class="session-note">Expires {{ new Date(session.expires_at).toLocaleTimeString() }} · SELECT, SHOW, DESCRIBE and EXPLAIN · up to 1,000 rows</p>
        <p>Tables and views: {{ tables.join(', ') || 'None' }}</p>
        <form @submit.prevent="exportDatabase"><label for="export-compression">Export tables and views</label><select id="export-compression" v-model="exportCompression" class="select" :disabled="busy"><option value="gzip">Compressed SQL (.sql.gz)</option><option value="none">SQL (.sql)</option></select><p>Uses this console session’s size and time limits. Routines, triggers and events are not included.</p><button class="button" type="submit" :disabled="busy">Export SQL</button><p v-if="exportProgress" role="status">{{ exportProgress }}</p></form>
        <form @submit.prevent="query"><label for="console-statement">SQL statement</label><textarea id="console-statement" v-model="statement" class="textarea mono" rows="6" required :disabled="busy" spellcheck="false"></textarea><button class="button button-primary" type="submit" :disabled="busy">{{ busy ? 'Running…' : 'Run query' }}</button></form>
        <section v-if="result" aria-label="Query results" class="query-results"><p>{{ result.rows.length }} rows{{ result.truncated ? ' · result truncated' : '' }}</p><div class="result-scroll"><table><thead><tr><th v-for="(column,index) in result.columns" :key="index">{{ column.name }}</th></tr></thead><tbody><tr v-for="(row,index) in result.rows" :key="index"><td v-for="(value,column) in row.values" :key="column">{{ value.kind === 'null' ? 'NULL' : value.text }}</td></tr></tbody></table></div></section>
      </template>
      <p v-if="failure" role="alert" class="console-error">{{ failure }}</p>
    </aside>
  </div>
</template>

<style scoped>
.console-layer{position:fixed;inset:0;z-index:80;background:rgba(0,5,8,.62);display:flex;justify-content:flex-end}.database-console{width:min(880px,100vw);height:100%;overflow:auto;padding:24px;background:var(--surface);border-left:1px solid var(--border);box-sizing:border-box}.database-console header{display:flex;justify-content:space-between;align-items:flex-start;gap:16px}.database-console h2{margin:0;font-size:21px}.database-console p{color:var(--muted);font-size:13px}.database-console form{display:grid;gap:12px;margin:24px 0}.database-console label{font-size:13px}.database-console form .button{justify-self:start}.session-note{border-bottom:1px solid var(--border);padding-bottom:12px}.console-error{color:var(--critical)!important}.result-scroll{overflow:auto}table{width:100%;border-collapse:collapse;font-size:13px}th,td{text-align:left;border:1px solid var(--border);padding:9px;white-space:pre-wrap;overflow-wrap:anywhere}th{background:var(--bg-raised)}
</style>
