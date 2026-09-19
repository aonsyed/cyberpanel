<script setup lang="ts">
import { computed } from "vue";
import * as Phosphor from "@phosphor-icons/vue";
import { navigation } from "../domain";
import { router } from "../router";
import { sessionStore } from "../store";

const collapsed = computed(() => sessionStore.state.navigationCollapsed);
const icons = Phosphor as unknown as Record<string, object>;
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
          <component :is="icons[`Ph${item.icon}`]" :size="19" :weight="router.currentPath.value === item.route ? 'fill' : 'regular'" aria-hidden="true" />
          <span v-if="!collapsed">{{ item.label }}</span>
        </a>
      </section>
    </nav>
    <div class="sidebar-foot">
      <div class="node-light"><i></i><span v-if="!collapsed">Local node online</span></div>
      <button class="collapse" type="button" :aria-label="collapsed ? 'Expand navigation' : 'Collapse navigation'" @click="sessionStore.toggleNavigation()">
        <component :is="collapsed ? icons.CaretDoubleRight : icons.CaretDoubleLeft" :size="17" />
        <span v-if="!collapsed">Collapse</span>
      </button>
    </div>
  </aside>
</template>

<style scoped>
.sidebar{position:fixed;z-index:40;inset:0 auto 0 0;width:var(--nav);display:flex;flex-direction:column;background:var(--bg-raised);border-right:1px solid var(--border);overflow:hidden}.brand{height:var(--topbar);display:flex;align-items:center;gap:11px;padding:0 18px;border-bottom:1px solid var(--border);flex:0 0 auto}.brand-mark{width:35px;height:35px;position:relative;border:1px solid var(--border-strong);display:grid;place-items:center;background:var(--surface);border-radius:7px;flex:0 0 auto}.brand-mark span{position:absolute;width:4px;height:19px;background:var(--accent);transform:skew(-21deg)}.brand-mark span:first-child{margin-left:-9px;height:13px}.brand-mark span:last-child{margin-left:8px}.brand-type{display:grid;line-height:1.05}.brand-type strong{font-size:16px;letter-spacing:-.02em}.brand-type small{margin-top:5px;color:var(--subtle);font:9px/1 "Panel Mono",monospace;letter-spacing:.14em}.navigation{flex:1;overflow-y:auto;padding:15px 10px 24px;scrollbar-width:thin;scrollbar-color:var(--border) transparent}.nav-group{margin-bottom:17px}.nav-group h2{margin:0 9px 6px;color:var(--subtle);font:10px/1.3 "Panel Mono",monospace;text-transform:uppercase;letter-spacing:.12em}.nav-link{position:relative;display:flex;align-items:center;gap:11px;min-height:37px;padding:0 10px;border-radius:7px;color:var(--muted);white-space:nowrap}.nav-link:hover{color:var(--text);background:var(--surface)}.nav-link.active{color:var(--text);background:var(--accent-soft)}.nav-link.active::before{content:"";position:absolute;left:0;top:9px;bottom:9px;width:2px;background:var(--accent)}.sidebar-foot{border-top:1px solid var(--border);padding:10px;display:grid;gap:4px}.node-light,.collapse{min-height:34px;display:flex;align-items:center;gap:10px;padding:0 10px;color:var(--subtle);font-size:12px}.node-light i{width:7px;height:7px;border-radius:50%;background:var(--healthy);box-shadow:0 0 0 3px color-mix(in srgb,var(--healthy),transparent 82%);flex:0 0 auto}.collapse{border:0;background:transparent;cursor:pointer;border-radius:6px}.collapse:hover{background:var(--surface);color:var(--text)}
.shell-collapsed .brand{padding:0 18px}.shell-collapsed .navigation{padding-inline:10px}.shell-collapsed .nav-link{justify-content:center;padding:0}.shell-collapsed .node-light,.shell-collapsed .collapse{justify-content:center;padding:0}
@media(max-width:900px){.sidebar{display:none}}
</style>
