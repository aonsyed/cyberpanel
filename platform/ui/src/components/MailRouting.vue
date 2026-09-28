<script setup lang="ts">
import { computed, inject, onMounted, ref } from "vue";
import { PhArrowClockwise as ArrowClockwise, PhCheck as Check, PhEnvelopeSimple as Envelope, PhWarningCircle as WarningCircle, PhX as X } from "@phosphor-icons/vue";
import type { APIClient } from "../api";
import { catchAllAliasPayload, plainAliasPayload } from "../consoleLogic";
import { sessionStore } from "../store";

interface RouteRow { id?: string; domain_id?: string; source?: string; targets?: string[]; kind?: string; state?: string; generation?: number; updated_at?: string }

const api = inject<APIClient>("api")!;
const loading = ref(true);
const error = ref("");
const routes = ref<RouteRow[]>([]);
const domains = ref<string[]>([]);
const search = ref("");
const creating = ref<"catchall" | "alias" | null>(null);
const form = ref({ domain: "", source: "", target: "", targets: "" });
const formError = ref("");
const working = ref(false);
const formNotice = ref("");

const tenantID = computed(() => sessionStore.state.tenantId || undefined);
const createAvailable = computed(() => api.available("mail.alias.create"));
const visibleRoutes = computed(() => {
  const term = search.value.trim().toLowerCase();
  return term ? routes.value.filter((route) => `${route.source ?? ""} ${route.targets?.join(" ") ?? ""} ${route.kind ?? ""}`.toLowerCase().includes(term)) : routes.value;
});
const catchAlls = computed(() => visibleRoutes.value.filter((route) => route.kind === "catch_all"));
const plainAliases = computed(() => visibleRoutes.value.filter((route) => route.kind !== "catch_all" && route.kind !== "pipe"));

onMounted(() => void load());

async function load(): Promise<void> {
  loading.value = true; error.value = "";
  try {
    if (api.available("mail.route.list")) {
      const response = await api.invoke<unknown>("mail.route.list", { tenantId: tenantID.value, payload: { limit: 200 } });
      const result = response.result;
      const items = Array.isArray(result) ? result : result && typeof result === "object" && Array.isArray((result as { items?: unknown[] }).items) ? (result as { items: unknown[] }).items : [];
      routes.value = items.filter(isRecord) as unknown as RouteRow[];
      domains.value = [...new Set(routes.value.map((route) => String(route.domain_id ?? "").split("@").pop() ?? "").filter(Boolean))].sort();
    } else if (api.available("mail.domain.list")) {
      const response = await api.invoke<unknown>("mail.domain.list", { tenantId: tenantID.value, payload: { limit: 200 } });
      const result = response.result;
      const items = Array.isArray(result) ? result : result && typeof result === "object" && Array.isArray((result as { items?: unknown[] }).items) ? (result as { items: unknown[] }).items : [];
      domains.value = items.filter(isRecord).map((item) => String((item as Record<string, unknown>).name ?? (item as Record<string, unknown>).domain ?? "")).filter(Boolean);
      routes.value = [];
    } else throw new Error("Mail routing projection is not enabled on this node.");
  } catch (cause) { routes.value = []; error.value = cause instanceof Error ? cause.message : "Mail routing could not be loaded."; }
  finally { loading.value = false; }
}
function isRecord(value: unknown): value is Record<string, unknown> { return Boolean(value) && typeof value === "object" && !Array.isArray(value); }

function openCreate(kind: "catchall" | "alias"): void {
  creating.value = kind; formError.value = ""; formNotice.value = "";
  form.value = { domain: domains.value[0] ?? "", source: "", target: "", targets: "" };
}
async function submit(): Promise<void> {
  if (!creating.value) return;
  formError.value = ""; formNotice.value = "";
  const built = creating.value === "catchall"
    ? catchAllAliasPayload({ domainId: form.value.domain, target: form.value.target })
    : plainAliasPayload({ domainId: form.value.domain, source: form.value.source, targets: form.value.targets.split(/[\n,]+/) });
  if ("error" in built) { formError.value = built.error; return; }
  working.value = true;
  try {
    await api.invoke("mail.alias.create", { tenantId: tenantID.value, payload: built });
    creating.value = null; formNotice.value = "Alias created and routing generation advanced.";
    await load();
  } catch (cause) { formError.value = cause instanceof Error ? cause.message : "The alias was not created."; }
  finally { working.value = false; }
}
async function removeRoute(route: RouteRow): Promise<void> {
  if (!route.id) return;
  working.value = true; formError.value = "";
  try {
    await api.invoke("mail.alias.delete", { tenantId: tenantID.value, resourceId: route.id, expectedGeneration: Number(route.generation) || undefined, payload: {} });
    await load();
  } catch (cause) { formError.value = cause instanceof Error ? cause.message : "The alias was not removed."; }
  finally { working.value = false; }
}
</script>

<template>
  <main class="routing">
    <header class="page-head">
      <div>
        <p class="eyebrow">MAIL / ROUTING</p>
        <h2>Aliases, catch-all &amp; forwarding</h2>
        <p>Every accepted message is decided by the routing generation: exact aliases, catch-all destinations for unmatched local addresses, and the native pattern rules behind them.</p>
      </div>
      <div class="head-actions">
        <button class="button button-small" type="button" :disabled="loading" @click="load"><ArrowClockwise :size="15" :class="{ spinning: loading }"/>Refresh</button>
        <button v-if="createAvailable" class="button" type="button" @click="openCreate('alias')">Add alias</button>
        <button v-if="createAvailable" class="button button-primary" type="button" @click="openCreate('catchall')">Add catch-all</button>
      </div>
    </header>

    <p v-if="error" class="routing-error" role="alert"><WarningCircle :size="17"/>{{ error }}</p>
    <p v-if="formNotice" class="routing-notice" role="status"><Check :size="15"/>{{ formNotice }}</p>

    <div v-if="creating" class="alias-form" role="dialog" :aria-label="creating === 'catchall' ? 'Add catch-all' : 'Add alias'">
      <header>
        <h3><Envelope :size="15"/>{{ creating === "catchall" ? "Catch-all for a domain" : "Forwarding alias" }}</h3>
        <button class="icon-button" type="button" aria-label="Cancel" @click="creating=null"><X :size="16"/></button>
      </header>
      <div class="alias-fields">
        <label class="field">Mail domain
          <input v-if="domains.length" v-model="form.domain" class="input" list="routing-domains" placeholder="example.invalid"/>
        <datalist id="routing-domains"><option v-for="domain in domains" :key="domain" :value="domain"/></datalist>
          <p v-if="!domains.length" class="field-help">No domain is loaded yet; type the full mail domain.</p>
        </label>
        <label v-if="creating === 'alias'" class="field">Local address <input v-model="form.source" class="input" placeholder="info"/></label>
        <label v-if="creating === 'catchall'" class="field">Deliver unmatched mail to <input v-model="form.target" class="input" placeholder="owner@example.invalid"/></label>
        <label v-else class="field">Target addresses (one per line) <textarea v-model="form.targets" class="textarea" rows="3" placeholder="owner@example.invalid&#10;team@example.invalid"/></label>
      </div>
      <p v-if="formError" class="field-error">{{ formError }}</p>
      <footer>
        <span class="mono">{{ creating === "catchall" ? "catch_all = true" : "exact source match" }}</span>
        <div><button class="button" type="button" @click="creating=null">Cancel</button><button class="button button-primary" type="button" :disabled="working" @click="submit">{{ working ? "Applying…" : "Create" }}</button></div>
      </footer>
    </div>

    <section v-if="loading" class="routing-loading" aria-busy="true"><span v-for="index in 5" :key="index" class="skeleton-row"><span class="skeleton"></span></span></section>
    <template v-else>
      <label class="routing-search"><input v-model="search" type="search" placeholder="Filter routes, sources, and targets"/></label>
      <section class="routing-panel">
        <header><div><p>UNMATCHED LOCAL ADDRESSES</p><h3>Catch-all destinations</h3></div><span class="mono">{{ catchAlls.length }}</span></header>
        <p v-if="!catchAlls.length" class="routing-empty">No catch-all is configured. Unmatched addresses are rejected by the routing policy.</p>
        <ul v-else class="route-list">
          <li v-for="(route, index) in catchAlls" :key="route.id ?? index">
            <div><strong class="mono">@{{ String(route.source ?? route.domain_id ?? "").replace(/^@?[^@]*@?/, "") || route.domain_id }}</strong><small>{{ route.targets?.join(", ") }}</small></div>
            <div><i :class="`status status-${route.state ?? 'active'}`">{{ route.state ?? "active" }}</i><button class="button button-small button-danger" type="button" :disabled="working" @click="removeRoute(route)">Remove</button></div>
          </li>
        </ul>
      </section>
      <section class="routing-panel">
        <header><div><p>EXACT FORWARDS</p><h3>Aliases</h3></div><span class="mono">{{ plainAliases.length }}</span></header>
        <p v-if="!plainAliases.length" class="routing-empty">No exact forwarding alias exists yet.</p>
        <ul v-else class="route-list">
          <li v-for="(route, index) in plainAliases" :key="route.id ?? index">
            <div><strong class="mono">{{ route.source }}</strong><small>{{ route.targets?.join(", ") }}</small></div>
            <div><i :class="`status status-${route.state ?? 'active'}`">{{ route.state ?? "active" }}</i><button class="button button-small button-danger" type="button" :disabled="working" @click="removeRoute(route)">Remove</button></div>
          </li>
        </ul>
      </section>
      <p class="routing-note">Pattern rules (prefix and suffix matching) and plus-addressing are enforced by the same routing generation through the API; this console covers aliases and catch-all, the everyday controls.</p>
    </template>
  </main>
</template>

<style scoped>
.routing{padding:36px clamp(18px,3.2vw,52px) 64px;max-width:1300px;margin:0 auto}
.page-head{display:flex;justify-content:space-between;align-items:flex-end;gap:24px;margin:0 0 26px}
.page-head h2{margin:6px 0 8px;font-size:clamp(28px,3vw,40px);line-height:1;letter-spacing:-.048em;font-weight:750}
.page-head>div>p:last-child{margin:0;color:var(--muted);max-width:72ch}
.head-actions{display:flex;gap:8px;flex-wrap:wrap;justify-content:flex-end}
.routing-error{display:flex;align-items:center;gap:8px;margin:0 0 15px;padding:12px 14px;border-left:3px solid var(--critical);border-radius:var(--radius-xs);background:var(--critical-soft);color:var(--critical)}
.routing-notice{display:flex;align-items:center;gap:8px;margin:0 0 15px;padding:11px 14px;border-left:3px solid var(--healthy);border-radius:var(--radius-xs);background:var(--healthy-soft);color:var(--healthy)}
.alias-form{border:1px solid var(--border-strong);border-radius:var(--radius-lg);background:var(--surface);margin-bottom:18px;box-shadow:var(--shadow)}
.alias-form>header{min-height:54px;padding:11px 17px;border-bottom:1px solid var(--border);display:flex;align-items:center;justify-content:space-between}
.alias-form h3{margin:0;font-size:14px;font-weight:650;display:flex;align-items:center;gap:8px;letter-spacing:-.02em}
.alias-fields{display:grid;grid-template-columns:repeat(auto-fit,minmax(230px,1fr));gap:14px;padding:17px}
.alias-form>footer{border-top:1px solid var(--border);padding:12px 17px;display:flex;align-items:center;justify-content:space-between}
.alias-form>footer span{color:var(--subtle);font-size:10px;font-family:var(--font-mono)}
.alias-form>footer div{display:flex;gap:8px}
.alias-form .field-error{margin:0 17px 14px}
.routing-search{display:flex;margin:0 0 14px}
.routing-search input{width:100%;max-width:420px;height:38px;border:1px solid var(--border);border-radius:var(--radius);background:var(--surface);color:var(--text);padding:0 12px;transition:border-color .14s ease,box-shadow .14s ease}
.routing-search input:focus{outline:none;border-color:var(--accent);box-shadow:0 0 0 3px var(--accent-soft)}
.routing-loading{border:1px solid var(--border);border-radius:var(--radius-lg);background:var(--surface);box-shadow:var(--shadow-sm);overflow:hidden}
.routing-panel{border:1px solid var(--border);border-radius:var(--radius-lg);background:var(--surface);margin-bottom:16px;box-shadow:var(--shadow-sm)}
.routing-panel>header{min-height:58px;padding:12px 18px;border-bottom:1px solid var(--border);display:flex;align-items:center;justify-content:space-between}
.routing-panel header p{margin:0 0 5px;color:var(--subtle);font:600 9px/1 var(--font-mono);letter-spacing:.13em}
.routing-panel h3{margin:0;font-size:14px;font-weight:650;letter-spacing:-.02em}
.routing-panel>header>span{color:var(--subtle);font:600 11px/1 var(--font-mono)}
.routing-empty{margin:0;padding:20px 18px;color:var(--subtle);font-size:12px;line-height:1.5}
.route-list{list-style:none;margin:0;padding:4px 0}
.route-list li{display:flex;align-items:center;justify-content:space-between;gap:14px;padding:11px 18px;border-bottom:1px solid var(--border);transition:background .1s ease}
.route-list li:hover{background:var(--surface-2)}
.route-list li:last-child{border-bottom:0}
.route-list li>div{display:grid;gap:5px;min-width:0}
.route-list strong{font-size:12px;word-break:break-all}
.route-list small{color:var(--subtle);font-size:10px;word-break:break-all}
.route-list li>div:last-child{display:flex;align-items:center;gap:10px}
.routing-note{margin:0;color:var(--subtle);font-size:11px;line-height:1.45}
.spinning{animation:spin .8s linear infinite}@keyframes spin{to{transform:rotate(1turn)}}
</style>

