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
import SecurityPosture from "./SecurityPosture.vue";
import MailRouting from "./MailRouting.vue";
import SiteDetailPage from "./SiteDetailPage.vue";
import DatabaseCards from "./DatabaseCards.vue";
import MailDomains from "./MailDomains.vue";
import DNSZoneEditor from "./DNSZoneEditor.vue";
import BackupHistory from "./BackupHistory.vue";
import CertificateCards from "./CertificateCards.vue";
import ContainerCards from "./ContainerCards.vue";
import AppCards from "./AppCards.vue";
import UserCards from "./UserCards.vue";
import ServicesGrid from "./ServicesGrid.vue";
import FileBrowser from "./FileBrowser.vue";
import AccessCredentials from "./AccessCredentials.vue";
import DomainCards from "./DomainCards.vue";
import LogViewer from "./LogViewer.vue";
import MetricsDashboard from "./MetricsDashboard.vue";
import MigrationTimeline from "./MigrationTimeline.vue";
import AlertCards from "./AlertCards.vue";
import SecurityFindings from "./SecurityFindings.vue";
import PHPSettings from "./PHPSettings.vue";

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
      <SiteDetailPage v-if="router.currentPath.value.startsWith('/sites/') && router.currentPath.value.split('/').length > 2 && router.currentPath.value.split('/')[2]" :site-id="router.currentPath.value.split('/')[2]" />
      <DatabaseCards v-else-if="router.currentPath.value === '/databases'" />
      <MailDomains v-else-if="router.currentPath.value === '/mail'" />
      <DNSZoneEditor v-else-if="router.currentPath.value === '/dns'" />
      <BackupHistory v-else-if="router.currentPath.value === '/backups'" />
      <CertificateCards v-else-if="router.currentPath.value === '/certificates'" />
      <ContainerCards v-else-if="router.currentPath.value === '/containers'" />
      <AppCards v-else-if="router.currentPath.value === '/applications'" />
      <UserCards v-else-if="router.currentPath.value === '/users'" />
      <ServicesGrid v-else-if="router.currentPath.value === '/services'" />
      <FileBrowser v-else-if="router.currentPath.value === '/files'" />
      <AccessCredentials v-else-if="router.currentPath.value === '/access'" />
      <DomainCards v-else-if="router.currentPath.value === '/domains'" />
      <LogViewer v-else-if="router.currentPath.value === '/logs'" />
      <MetricsDashboard v-else-if="router.currentPath.value === '/observability'" />
      <MigrationTimeline v-else-if="router.currentPath.value === '/migrations'" />
      <AlertCards v-else-if="router.currentPath.value === '/alerts'" />
      <SecurityFindings v-else-if="router.currentPath.value === '/security'" />
      <PHPSettings v-else-if="router.currentPath.value === '/engines'" />
      <DashboardPage v-else-if="page.id === 'dashboard'" />
      <WebmailPage v-else-if="page.id === 'webmail'" />
      <SecurityPosture v-else-if="page.component === 'security-posture'" />
      <MailRouting v-else-if="page.component === 'mail-routing'" />
      <ResourcePage v-else :definition="page" />
    </div>
    <CommandPalette v-if="sessionStore.state.commandOpen" />
  </div>
</template>

<style scoped>
.shell { min-height:100dvh; display:grid; grid-template-columns:var(--nav) minmax(0,1fr); }
.shell-main {
  grid-column:2; min-width:0; padding-top:var(--topbar);
  background:
    radial-gradient(ellipse 50% 20% at 50% -60px, var(--accent-softer), transparent),
    var(--bg);
}
.offline-banner { position:fixed; z-index:30; top:var(--topbar); left:var(--nav); right:0; padding:7px 18px; background:var(--warning); color:#171006; font-size:12px; font-weight:700; text-align:center; }
.shell-collapsed { --nav:72px; }
@media(max-width:900px){.shell{display:block}.shell-main{padding-top:56px}.offline-banner{left:0;top:56px}}
</style>

