<script setup lang="ts">
import { computed, type Component } from "vue";
import {
  PhAddressBook, PhArchive, PhArrowCircleDown, PhArrowClockwise, PhArrowsLeftRight,
  PhArticle, PhBell, PhBellRinging, PhBug, PhCalendarCheck, PhCertificate,
  PhChartLineUp, PhCube, PhDatabase, PhEnvelopeSimple, PhFileMagnifyingGlass,
  PhFolderOpen, PhGauge, PhGavel, PhGlobeHemisphereWest, PhHardDrives, PhLifebuoy,
  PhListMagnifyingGlass, PhMegaphone, PhPackage, PhPaperPlaneTilt, PhPlugsConnected,
  PhPulse, PhShieldCheck, PhShieldWarning, PhSignpost, PhSlidersHorizontal, PhStack,
  PhStackSimple, PhTerminalWindow, PhTray, PhTreeStructure, PhUserPlus, PhUsersThree,
  PhCaretDoubleRight, PhCaretDoubleLeft,
} from "@phosphor-icons/vue";
import { navigation } from "../domain";
import { router } from "../router";
import { sessionStore } from "../store";

const collapsed = computed(() => sessionStore.state.navigationCollapsed);
const icons: Record<string, Component> = {
  PhAddressBook, PhArchive, PhArrowCircleDown, PhArrowClockwise, PhArrowsLeftRight,
  PhArticle, PhBell, PhBellRinging, PhBug, PhCalendarCheck, PhCertificate,
  PhChartLineUp, PhCube, PhDatabase, PhEnvelopeSimple, PhFileMagnifyingGlass,
  PhFolderOpen, PhGauge, PhGavel, PhGlobeHemisphereWest, PhHardDrives, PhLifebuoy,
  PhListMagnifyingGlass, PhMegaphone, PhPackage, PhPaperPlaneTilt, PhPlugsConnected,
  PhPulse, PhShieldCheck, PhShieldWarning, PhSignpost, PhSlidersHorizontal, PhStack,
  PhStackSimple, PhTerminalWindow, PhTray, PhTreeStructure, PhUserPlus, PhUsersThree,
};
function navigate(event: MouseEvent, route: string): void { event.preventDefault(); router.push(route); }
</script>

<template>
  <aside class="sidebar" aria-label="Primary navigation">
    <div class="brand">
      <div class="brand-mark" aria-hidden="true"><span></span><span></span></div>
      <div v-if="!collapsed" class="brand-type"><strong>CyberPanel</strong><small>CONTROL SURFACE</small></div>
    </div>
    <nav class="navigation">
      <section v-for="group in navigation" :key="group.id" class="nav-group">
        <h2 v-if="!collapsed">{{ group.label }}</h2>
        <a v-for="item in group.items" :key="item.id" :href="item.route" class="nav-link" :class="{ active: router.currentPath.value === item.route }" v-bind="collapsed ? {title:item.label} : {}" @click="navigate($event,item.route)">
          <span class="nav-icon"><component :is="icons[`Ph${item.icon}`]" :size="18" :weight="router.currentPath.value === item.route ? 'fill' : 'regular'" aria-hidden="true" /></span>
          <span v-if="!collapsed" class="nav-label">{{ item.label }}</span>
        </a>
      </section>
    </nav>
    <div class="sidebar-foot">
      <div class="node-light"><i></i><span v-if="!collapsed">Local node online</span></div>
      <button class="collapse" type="button" :aria-label="collapsed ? 'Expand navigation' : 'Collapse navigation'" @click="sessionStore.toggleNavigation()">
        <component :is="collapsed ? PhCaretDoubleRight : PhCaretDoubleLeft" :size="16" />
        <span v-if="!collapsed">Collapse</span>
      </button>
    </div>
  </aside>
</template>

<style scoped>
.sidebar {
  position: fixed; z-index: 40; inset: 0 auto 0 0;
  width: var(--nav);
  display: flex; flex-direction: column;
  background:
    linear-gradient(180deg, color-mix(in srgb, var(--accent) 2%, var(--bg-raised)), var(--bg-raised) 28%),
    var(--bg-raised);
  border-right: 1px solid var(--border);
  overflow: hidden;
}

.brand {
  height: var(--topbar);
  display: flex; align-items: center; gap: 12px;
  padding: 0 20px;
  border-bottom: 1px solid var(--border);
  flex: 0 0 auto;
}
.brand-mark {
  width: 36px; height: 36px;
  position: relative;
  border: 1px solid var(--border-strong);
  display: grid; place-items: center;
  background: linear-gradient(135deg, var(--surface-2), var(--surface));
  border-radius: var(--radius-sm);
  flex: 0 0 auto;
  box-shadow: inset 0 1px 0 rgba(255,255,255,.04), var(--shadow-sm);
}
.brand-mark span { position: absolute; width: 4px; height: 20px; background: var(--accent); transform: skew(-21deg); border-radius: 1px; }
.brand-mark span:first-child { margin-left: -9px; height: 13px; opacity: .7; }
.brand-mark span:last-child { margin-left: 8px; }
.brand-type { display: grid; line-height: 1.05; }
.brand-type strong { font-size: 16px; letter-spacing: -.02em; font-weight: 700; }
.brand-type small { margin-top: 5px; color: var(--subtle); font: 500 9px/1 var(--font-mono); letter-spacing: .14em; }

.navigation {
  flex: 1; overflow-y: auto;
  padding: 16px 12px 24px;
  scrollbar-width: thin;
  scrollbar-color: var(--surface-3) transparent;
}

.nav-group { margin-bottom: 20px; }
.nav-group h2 {
  margin: 0 8px 7px;
  color: var(--faint);
  font: 600 9.5px/1.3 var(--font-mono);
  text-transform: uppercase;
  letter-spacing: .14em;
}

.nav-link {
  position: relative;
  display: flex; align-items: center; gap: 11px;
  min-height: 36px;
  padding: 0 10px;
  border-radius: var(--radius-sm);
  color: var(--muted);
  white-space: nowrap;
  font-size: 13px;
  font-weight: 500;
  transition: color .12s ease, background .12s ease;
}
.nav-link:hover {
  color: var(--text);
  background: var(--surface);
}
.nav-link .nav-icon {
  display: grid; place-items: center;
  width: 26px; height: 26px;
  border-radius: var(--radius-xs);
  transition: background .12s ease, color .12s ease;
  flex: 0 0 auto;
}
.nav-link:hover .nav-icon { color: var(--text); }

.nav-link.active {
  color: var(--accent);
  background: var(--accent-soft);
  font-weight: 650;
}
.nav-link.active .nav-icon {
  color: var(--accent);
  background: color-mix(in srgb, var(--accent) 8%, transparent);
}
.nav-link.active::before {
  content: "";
  position: absolute; left: -12px; top: 8px; bottom: 8px;
  width: 3px;
  background: linear-gradient(180deg, var(--accent-strong), var(--accent));
  border-radius: 0 3px 3px 0;
  box-shadow: 0 0 8px var(--accent-glow);
}

.sidebar-foot {
  border-top: 1px solid var(--border);
  padding: 10px 12px;
  display: grid; gap: 4px;
  background: linear-gradient(0deg, color-mix(in srgb, var(--accent) 1.5%, transparent), transparent 40%);
}
.node-light, .collapse {
  min-height: 34px;
  display: flex; align-items: center; gap: 10px;
  padding: 0 10px;
  color: var(--subtle);
  font-size: 12px;
  border-radius: var(--radius-xs);
}
.node-light i {
  width: 7px; height: 7px;
  border-radius: 50%;
  background: var(--healthy);
  box-shadow: 0 0 0 3px var(--healthy-soft), 0 0 6px var(--healthy);
  flex: 0 0 auto;
  animation: pulse-dot 2.4s ease-in-out infinite;
}
@keyframes pulse-dot { 0%, 100% { box-shadow: 0 0 0 3px var(--healthy-soft), 0 0 6px var(--healthy); } 50% { box-shadow: 0 0 0 5px transparent, 0 0 10px var(--healthy); } }
.collapse { border: 0; background: transparent; cursor: pointer; }
.collapse:hover { background: var(--surface); color: var(--text); }

.shell-collapsed .brand { padding: 0; justify-content: center; }
.shell-collapsed .navigation { padding-inline: 10px; }
.shell-collapsed .nav-link { justify-content: center; padding: 0; }
.shell-collapsed .nav-link.active::before { left: -10px; }
.shell-collapsed .node-light, .shell-collapsed .collapse { justify-content: center; padding: 0; }

@media (max-width: 900px) { .sidebar { display: none; } }
</style>
