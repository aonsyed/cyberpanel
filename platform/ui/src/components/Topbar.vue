<script setup lang="ts">
import { computed, inject, onBeforeUnmount, onMounted, ref } from "vue";
import { PhBell as Bell, PhCaretDown as CaretDown, PhCommand as Command, PhList as List, PhMagnifyingGlass as MagnifyingGlass, PhMoon as Moon, PhSignOut as SignOut, PhSun as Sun } from "@phosphor-icons/vue";
import type { APIClient } from "../api";
import { sessionStore } from "../store";

defineProps<{pageTitle:string}>();
const api = inject<APIClient>("api")!;
const menuOpen = ref(false);
const initials = computed(() => sessionStore.state.viewer?.displayName.split(/\s+/).map((part)=>part[0]).join("").slice(0,2).toUpperCase() || "CP");
async function logout(): Promise<void> { try { if(api.available("identity.session.logout")) await api.invoke("identity.session.logout"); } finally { api.clearSession();sessionStore.setViewer(null);menuOpen.value=false; } }
function cycleTheme():void{const order=["system","dark","light"] as const;const index=order.indexOf(sessionStore.state.theme);sessionStore.setTheme(order[(index+1)%order.length]!)}
function dismiss():void{menuOpen.value=false}
onMounted(()=>window.addEventListener("click",dismiss));
onBeforeUnmount(()=>window.removeEventListener("click",dismiss));
</script>

<template>
  <header class="topbar">
    <div class="mobile-brand"><button class="icon-button" type="button" aria-label="Open navigation" :aria-expanded="sessionStore.state.commandOpen" @click.stop="sessionStore.setCommandOpen(true)"><List :size="21"/></button><strong>CyberPanel</strong></div>
    <div class="page-context"><h1>{{ pageTitle }}</h1></div>
    <button class="search-trigger" type="button" @click="sessionStore.setCommandOpen(true)"><MagnifyingGlass :size="16"/><span>Search resources and actions</span><kbd><Command :size="11"/> K</kbd></button>
    <div class="top-actions">
      <button class="icon-button" type="button" :aria-label="`Theme: ${sessionStore.state.theme}`" @click.stop="cycleTheme"><Sun v-if="sessionStore.state.theme==='light'" :size="17"/><Moon v-else :size="17"/></button>
      <button class="icon-button notification-button" type="button" aria-label="Notifications" @click.stop><Bell :size="17"/><i></i></button>
      <div class="user-menu">
        <button class="user-trigger" type="button" :aria-expanded="menuOpen" @click.stop="menuOpen=!menuOpen"><span class="avatar">{{ initials }}</span><span class="user-copy"><strong>{{ sessionStore.state.viewer?.displayName }}</strong><small>{{ sessionStore.state.viewer?.tenantName }}</small></span><CaretDown :size="12" class="caret" :class="{open:menuOpen}"/></button>
        <Transition name="menu">
          <div v-if="menuOpen" class="user-popover" @click.stop>
            <div class="menu-head"><small>SIGNED IN AS</small><strong>{{ sessionStore.state.viewer?.username }}</strong><span class="mono">{{ sessionStore.state.viewer?.email }}</span></div>
            <div class="menu-row"><span>Assurance</span><strong class="mono">{{ sessionStore.state.viewer?.assurance || 'password' }}</strong></div>
            <div class="menu-row"><span>Tenant</span><strong>{{ sessionStore.state.viewer?.tenantName }}</strong></div>
            <button type="button" class="menu-signout" @click="logout"><SignOut :size="14"/>Sign out</button>
          </div>
        </Transition>
      </div>
    </div>
  </header>
</template>

<style scoped>
.topbar{position:fixed;z-index:35;top:0;right:0;left:var(--nav);height:var(--topbar);display:grid;grid-template-columns:minmax(150px,1fr) minmax(280px,520px) minmax(220px,1fr);align-items:center;gap:18px;padding:0 22px;background:var(--surface-glass);backdrop-filter:blur(20px) saturate(1.3);border-bottom:1px solid var(--border)}
h1{font-size:14px;letter-spacing:-.01em;margin:0;font-weight:650;color:var(--muted)}
.page-context{display:flex;align-items:center;gap:8px;min-width:0}
.search-trigger{height:36px;border:1px solid var(--border);border-radius:var(--radius);background:var(--surface);color:var(--subtle);display:flex;align-items:center;gap:9px;padding:0 10px;text-align:left;cursor:pointer;transition:border-color .14s ease,box-shadow .14s ease}
.search-trigger:hover{border-color:var(--border-bright);box-shadow:var(--shadow-sm)}
.search-trigger span{flex:1}
.search-trigger kbd{font:11px/1 var(--font-mono);display:flex;align-items:center;gap:3px;border:1px solid var(--border);padding:4px 6px;border-radius:var(--radius-xs);background:var(--surface-2)}
.top-actions{display:flex;align-items:center;justify-content:flex-end;gap:4px}
.notification-button{position:relative}
.notification-button i{position:absolute;right:9px;top:9px;width:5px;height:5px;border-radius:50%;background:var(--critical);box-shadow:0 0 4px var(--critical)}
.user-menu{position:relative;margin-left:5px}
.user-trigger{height:44px;border:0;background:transparent;color:var(--text);display:flex;align-items:center;gap:9px;cursor:pointer;border-radius:var(--radius);padding:0 7px;transition:background .12s ease}
.user-trigger:hover{background:var(--surface)}
.avatar{width:32px;height:32px;border-radius:var(--radius-sm);display:grid;place-items:center;background:linear-gradient(135deg,var(--accent-soft),color-mix(in srgb,var(--accent) 14%,transparent));color:var(--accent);font:700 11px/1 var(--font-mono);border:1px solid color-mix(in srgb,var(--accent) 20%,transparent)}
.user-copy{display:grid;text-align:left;line-height:1.1}
.user-copy strong{font-size:12px}
.user-copy small{margin-top:4px;color:var(--subtle);font-size:10px}
.caret{transition:transform .16s ease;color:var(--subtle)}
.caret.open{transform:rotate(180deg)}
.user-popover{position:absolute;right:0;top:49px;width:230px;padding:6px;background:var(--surface-glass);backdrop-filter:blur(20px) saturate(1.3);border:1px solid var(--border-strong);border-radius:var(--radius-lg);box-shadow:var(--shadow-lg)}
.menu-head{display:grid;gap:4px;padding:11px 10px;border-bottom:1px solid var(--border);margin-bottom:4px}
.menu-head small{color:var(--subtle);font:600 9px/1 var(--font-mono);letter-spacing:.12em}
.menu-head strong{font-size:13px}
.menu-head .mono{color:var(--muted);font-size:11px}
.menu-row{display:flex;align-items:center;justify-content:space-between;padding:8px 10px;border-radius:var(--radius-xs)}
.menu-row span{color:var(--subtle);font-size:11px}
.menu-row strong{font-size:12px}
.menu-signout{width:100%;border:0;border-top:1px solid var(--border);margin-top:4px;background:transparent;color:var(--critical);display:flex;align-items:center;gap:8px;text-align:left;padding:11px 10px;cursor:pointer;border-radius:var(--radius-xs);font-size:12px;transition:background .1s ease}
.menu-signout:hover{background:var(--critical-soft)}
.menu-enter-active,.menu-leave-active{transition:opacity .14s ease,transform .14s ease}
.menu-enter-from,.menu-leave-to{opacity:0;transform:translateY(-4px) scale(.98)}
.mobile-brand{display:none}
@media(max-width:1100px){.topbar{grid-template-columns:1fr minmax(240px,420px) auto}.user-copy{display:none}}
@media(max-width:900px){.topbar{left:0;height:56px;grid-template-columns:1fr auto;padding:0 14px}.mobile-brand{display:flex;align-items:center;gap:10px}.topbar>h1,.search-trigger{display:none}.user-trigger>svg{display:none}.user-menu{margin:0}}
</style>
