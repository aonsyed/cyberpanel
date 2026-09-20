<script setup lang="ts">
import { computed, inject, onBeforeUnmount, ref, watch } from "vue";
import type { APIClient } from "../api";

const props = defineProps<{ tenantId?: string | undefined; siteId: string; jobId: string; running: boolean; status: string }>();
const emit = defineEmits<{ busy: [value: boolean]; complete: [] }>();
const api = inject<APIClient>("api")!;
type JobState = { status: string; generation: number; cancellation_requested: boolean };
const state = ref<JobState | null>(null);
const pending = ref(false);
const failure = ref("");
const controller = new AbortController();
const terminal = (value: string) => ["completed", "cancelled", "failed", "ambiguous"].includes(value);
const finished = computed(() => terminal(props.status) || terminal(state.value?.status || ""));
const message = computed(() => {
  const status = terminal(props.status) ? props.status : state.value?.status || props.status;
  if (status === "completed") return "Import completed and verified.";
  if (status === "cancelled") return "Import cancelled. The destination was preserved.";
  if (status === "ambiguous") return "Import outcome is uncertain. Do not retry the import; recovery is required.";
  if (status === "failed") return "Import failed. Check the job result before taking further action.";
  if (state.value?.cancellation_requested) return "Cancellation requested. Waiting for a safe stopping point; the import may still finish.";
  return status;
});
const scope = () => ({ tenantId: props.tenantId, resourceId: props.siteId, signal: controller.signal, payload: { job_id: props.jobId } });
function accept(next: JobState): void {
  if (!Number.isSafeInteger(next.generation) || next.generation < 1) throw new Error("Invalid job generation.");
  if (!state.value || next.generation >= state.value.generation) state.value = next;
  if (next.status === "completed") emit("complete");
}
async function refresh(): Promise<JobState> {
  const response = await api.invoke<JobState>("database.import.inspect", scope());
  accept(response.result);
  return response.result;
}
async function check(cancel = false): Promise<void> {
  if (pending.value) return;
  pending.value = true; emit("busy", true); failure.value = "";
  try {
    const current = await refresh();
    if (cancel && !terminal(current.status) && !current.cancellation_requested) {
      const response = await api.invoke<JobState>("database.import.cancel", {
        ...scope(), expectedGeneration: current.generation,
        idempotencyKey: crypto.randomUUID(), requestId: `req_${crypto.randomUUID().replaceAll("-", "")}`
      });
      accept(response.result);
    }
  } catch (error) {
    failure.value = `${error instanceof Error ? error.message : "Job request failed."} Check status before retrying.`;
  } finally { pending.value = false; emit("busy", false); }
}
watch(() => props.running, (running, before) => { if (before && !running) void check(); });
onBeforeUnmount(() => { controller.abort(); emit("busy", false); });
</script>

<template>
  <section aria-label="Import job status">
    <p v-if="message" role="status">{{ message }}</p>
    <div class="import-controls">
      <button type="button" class="button" :disabled="pending" @click="check()">Check import status</button>
      <button v-if="!finished && api.available('database.import.cancel')" type="button" class="button" :disabled="pending || !!state?.cancellation_requested" @click="check(true)">Request cancellation</button>
    </div>
    <p v-if="failure" role="alert" class="import-error">{{ failure }}</p>
  </section>
</template>

<style scoped>
.import-controls{display:flex;flex-wrap:wrap;gap:8px}p{font-size:13px;overflow-wrap:anywhere}.import-error{color:var(--critical)}
</style>
