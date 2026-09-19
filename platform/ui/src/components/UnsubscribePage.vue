<script setup lang="ts">
import { inject, onMounted, ref } from "vue";
import { PhCheckCircle as CheckCircle, PhWarningCircle as WarningCircle } from "@phosphor-icons/vue";
import { APIClient } from "../api";

const api = inject<APIClient>("api")!;
const state = ref<"working"|"complete"|"failed">("working");
const detail = ref("Recording your request…");

onMounted(async () => {
  const token = new URLSearchParams(window.location.search).get("token") || "";
  window.history.replaceState({}, "", "/unsubscribe");
  if (token.length < 32 || token.length > 4096) {
    state.value = "failed"; detail.value = "This unsubscribe link is invalid or incomplete."; return;
  }
  try {
    await api.invokePublic("marketing.unsubscribe", { token });
    state.value = "complete"; detail.value = "This address has been removed from future campaign delivery.";
  } catch (error) {
    state.value = "failed";
    detail.value = error instanceof Error ? error.message : "The unsubscribe request could not be recorded.";
  }
});
</script>

<template>
  <main class="unsubscribe-stage">
    <section class="unsubscribe-card" aria-live="polite">
      <div class="unsubscribe-mark" :class="state">
        <span v-if="state==='working'" class="unsubscribe-spinner"></span>
        <CheckCircle v-else-if="state==='complete'" :size="34" weight="fill" />
        <WarningCircle v-else :size="34" weight="fill" />
      </div>
      <p>CYBERPANEL MAIL PREFERENCES</p>
      <h1>{{ state === "complete" ? "You’re unsubscribed." : state === "failed" ? "We couldn’t verify that link." : "Honoring your request." }}</h1>
      <span>{{ detail }}</span>
      <small v-if="state==='complete'">The change is immediate. A later, evidenced opt-in is required before campaigns can resume.</small>
    </section>
  </main>
</template>
