<script setup lang="ts">
import { computed, inject, ref } from "vue";
import { PhBell as Bell, PhCaretDown as CaretDown, PhCommand as Command, PhList as List, PhMagnifyingGlass as MagnifyingGlass, PhMoon as Moon, PhSun as Sun } from "@phosphor-icons/vue";
import type { APIClient } from "../api";
import { sessionStore } from "../store";

defineProps<{pageTitle:string}>();
const api = inject<APIClient>("api")!;
const menuOpen = ref(false);
const initials = computed(() => sessionStore.state.viewer?.displayName.split(/\s+/).map((part)=>part[0]).join("").slice(0,2).toUpperCase() || "CP");
async function logout(): Promise<void> { try { if(api.available("identity.session.logout")) await api.invoke("identity.session.logout"); } finally { api.clearSession();sessionStore.setViewer(null);menuOpen.value=false; } }
function cycleTheme():void{const order=["system","dark","light"] as const;const index=order.indexOf(sessionStore.state.theme);sessionStore.setTheme(order[(index+1)%order.length]!)}
</script>

<template>
  <header class="topbar">
    <div class="mobile-brand"><List :size="21"/><strong>CyberPanel</strong></div>
    <h1>{{ pageTitle }}</h1>
    <button class="search-trigger" type="button" @click="sessionStore.setCommandOpen(true)"><MagnifyingGlass :size="17"/><span>Search resources and actions</span><kbd><Command :size="12"/> K</kbd></button>
    <div class="top-actions">
      <button class="icon-button" type="button" :aria-label="`Theme: ${sessionStore.state.theme}`" @click="cycleTheme"><Sun v-if="sessionStore.state.theme==='light'" :size="18"/><Moon v-else :size="18"/></button>
      <button class="icon-button notification-button" type="button" aria-label="Notifications"><Bell :size="18"/><i></i></button>
      <div class="user-menu">
        <button class="user-trigger" type="button" :aria-expanded="menuOpen" @click="menuOpen=!menuOpen"><span class="avatar">{{ initials }}</span><span class="user-copy"><strong>{{ sessionStore.state.viewer?.displayName }}</strong><small>{{ sessionStore.state.viewer?.tenantName }}</small></span><CaretDown :size="13"/></button>
        <div v-if="menuOpen" class="user-popover">
          <div><small>ASSURANCE</small><strong>{{ sessionStore.state.viewer?.assurance || 'password' }}</strong></div>
          <button type="button" @click="logout">Sign out</button>
        </div>
      </div>
    </div>
  </header>
</template>

<style scoped>
.topbar{position:fixed;z-index:35;top:0;right:0;left:var(--nav);height:var(--topbar);display:grid;grid-template-columns:minmax(150px,1fr) minmax(280px,520px) minmax(220px,1fr);align-items:center;gap:18px;padding:0 22px;background:color-mix(in srgb,var(--bg-raised),transparent 4%);border-bottom:1px solid var(--border);backdrop-filter:blur(16px)}h1{font-size:14px;letter-spacing:-.01em;margin:0}.search-trigger{height:36px;border:1px solid var(--border);border-radius:7px;background:var(--surface);color:var(--subtle);display:flex;align-items:center;gap:9px;padding:0 10px;text-align:left;cursor:pointer}.search-trigger span{flex:1}.search-trigger kbd{font:11px/1 "Panel Mono",monospace;display:flex;align-items:center;gap:3px;border:1px solid var(--border);padding:4px 6px;border-radius:5px;background:var(--surface-2)}.top-actions{display:flex;align-items:center;justify-content:flex-end;gap:4px}.notification-button{position:relative}.notification-button i{position:absolute;right:8px;top:8px;width:5px;height:5px;border-radius:50%;background:var(--critical)}.user-menu{position:relative;margin-left:5px}.user-trigger{height:44px;border:0;background:transparent;color:var(--text);display:flex;align-items:center;gap:9px;cursor:pointer;border-radius:7px;padding:0 7px}.user-trigger:hover{background:var(--surface)}.avatar{width:31px;height:31px;border-radius:7px;display:grid;place-items:center;background:var(--accent-soft);color:var(--accent);font:11px/1 "Panel Mono",monospace;font-weight:700}.user-copy{display:grid;text-align:left;line-height:1.1}.user-copy strong{font-size:12px}.user-copy small{margin-top:4px;color:var(--subtle);font-size:10px}.user-popover{position:absolute;right:0;top:49px;width:210px;padding:8px;background:var(--surface);border:1px solid var(--border-strong);border-radius:var(--radius);box-shadow:var(--shadow)}.user-popover div{display:grid;gap:4px;padding:9px}.user-popover small{color:var(--subtle);font:9px/1 "Panel Mono",monospace;letter-spacing:.1em}.user-popover button{width:100%;border:0;border-top:1px solid var(--border);background:transparent;color:var(--critical);text-align:left;padding:11px 9px;cursor:pointer}.mobile-brand{display:none}
@media(max-width:1100px){.topbar{grid-template-columns:1fr minmax(240px,420px) auto}.user-copy{display:none}}
@media(max-width:900px){.topbar{left:0;height:56px;grid-template-columns:1fr auto;padding:0 14px}.mobile-brand{display:flex;align-items:center;gap:10px}.topbar>h1,.search-trigger{display:none}.user-trigger>svg{display:none}.user-menu{margin:0}}
</style>
