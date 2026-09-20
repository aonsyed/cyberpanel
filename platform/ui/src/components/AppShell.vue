<script setup lang="ts">
import { computed, onBeforeUnmount, onMounted } from "vue";
import { router } from "../router";
import { pageForPath } from "../domain";
import { sessionStore } from "../store";
import Sidebar from "./Sidebar.vue";
import Topbar from "./Topbar.vue";
import ResourcePage from "./ResourcePage.vue";
import DashboardPage from "./DashboardPage.vue";
import CommandPalette from "./CommandPalette.vue";
import WebmailPage from "./WebmailPage.vue";
import FileManagerPage from "./FileManagerPage.vue";

const page = computed(() => pageForPath(router.currentPath.value));

function shortcuts(event: KeyboardEvent): void {
  if ((event.metaKey || event.ctrlKey) && event.key.toLowerCase() === "k") { event.preventDefault(); sessionStore.setCommandOpen(true); }
  if (event.key === "Escape") sessionStore.setCommandOpen(false);
}
onMounted(() => window.addEventListener("keydown", shortcuts));
onBeforeUnmount(() => window.removeEventListener("keydown", shortcuts));
</script>

<template>
  <div class="shell" :class="{ 'shell-collapsed': sessionStore.state.navigationCollapsed }">
    <Sidebar />
    <div class="shell-main">
      <Topbar :page-title="page.title" />
      <div v-if="!sessionStore.state.online" class="offline-banner" role="status">Browser connectivity is offline. Local node work already accepted will continue.</div>
      <DashboardPage v-if="page.id === 'dashboard'" />
      <WebmailPage v-else-if="page.id === 'webmail'" />
      <FileManagerPage v-else-if="page.id === 'files'" />
      <ResourcePage v-else :definition="page" />
    </div>
    <CommandPalette v-if="sessionStore.state.commandOpen" />
  </div>
</template>

<style scoped>
.shell { min-height:100dvh; display:grid; grid-template-columns:var(--nav) minmax(0,1fr); }.shell-main { grid-column:2; min-width:0; padding-top:var(--topbar); }.offline-banner { position:fixed; z-index:30; top:var(--topbar); left:var(--nav); right:0; padding:7px 18px; background:var(--warning); color:#171006; font-size:12px; font-weight:700; text-align:center; }.shell-collapsed { --nav:72px; }
@media(max-width:900px){.shell{display:block}.shell-main{padding-top:56px}.offline-banner{left:0;top:56px}}
</style>
