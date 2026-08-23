<script setup lang="ts">
import { onBeforeUnmount, onMounted, provide, ref } from "vue";
import { APIClient } from "./api";
import { sessionStore, type ViewerProjection } from "./store";
import AppShell from "./components/AppShell.vue";
import LoginPage from "./components/LoginPage.vue";
import NoticeStack from "./components/NoticeStack.vue";
import UnsubscribePage from "./components/UnsubscribePage.vue";

const api = new APIClient();
provide("api", api);
const booting = ref(true);
const bootError = ref("");
const publicUnsubscribe = window.location.pathname === "/unsubscribe";

async function bootstrap(): Promise<void> {
  booting.value = true; bootError.value = "";
  try {
    const operations = await api.loadCatalog(); sessionStore.setOperations(operations);
    if (api.available("identity.session.current")) {
      try {
        const response = await api.invoke<ViewerProjection>("identity.session.current");
        sessionStore.setProjection(response.result);
      } catch { sessionStore.setViewer(null); }
    }
  } catch (error) { bootError.value = error instanceof Error ? error.message : "The local control API is unavailable."; }
  finally { booting.value = false; }
}

const online = () => sessionStore.setOnline(navigator.onLine);
onMounted(() => { document.documentElement.dataset.theme = sessionStore.state.theme; void bootstrap(); window.addEventListener("online", online); window.addEventListener("offline", online); });
onBeforeUnmount(() => { window.removeEventListener("online", online); window.removeEventListener("offline", online); });
</script>

<template>
  <div v-if="booting" class="boot-stage" role="status" aria-live="polite">
    <div class="boot-mark"><span></span><span></span><span></span></div>
    <p>Establishing local control session</p>
  </div>
  <main v-else-if="bootError" class="failure-stage">
    <div class="failure-code">LOCAL API / UNAVAILABLE</div>
    <h1>The node console cannot reach panel-core.</h1>
    <p>{{ bootError }}</p>
    <button class="button button-primary" type="button" @click="bootstrap">Retry connection</button>
  </main>
  <UnsubscribePage v-else-if="publicUnsubscribe" />
  <LoginPage v-else-if="!sessionStore.authenticated.value" />
  <AppShell v-else />
  <NoticeStack />
</template>
