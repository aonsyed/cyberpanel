<script setup lang="ts">
// Site detail page — replaces the JSON drawer with a real page showing
// a site's complete picture: overview stats, domains, SSL, apps, databases.
import { computed, inject, onMounted, ref } from "vue";
import {
  PhArrowClockwise, PhCertificate, PhDatabase, PhGlobe,
  PhHardDrives, PhLock, PhPackage, PhPulse, PhSpeedometer,
  PhTrash, PhWarningCircle, PhGlobeHemisphereWest, PhArrowLeft,
} from "@phosphor-icons/vue";
import type { APIClient } from "../api";
import { router } from "../router";
import { sessionStore } from "../store";

const props = defineProps<{ siteId: string }>();
const api = inject<APIClient>("api")!;
const loading = ref(true);
const error = ref("");
const site = ref<Record<string, unknown>>({});
const bindings = ref<Record<string, unknown>[]>([]);
const databases = ref<Record<string, unknown>[]>([]);
const apps = ref<Record<string, unknown>[]>([]);
const activeTab = ref<"overview" | "domains" | "ssl" | "apps" | "databases">("overview");

const tenantId = computed(() => sessionStore.state.tenantId || undefined);
const hostname = computed(() => String(site.value.primary_hostname ?? site.value.hostname ?? props.siteId));
const lifecycle = computed(() => String(site.value.lifecycle ?? "unknown"));
const phpProfile = computed(() => String(site.value.php_profile ?? "—"));
const diskUsage = computed(() => String(site.value.disk_usage ?? "—"));
const bandwidth = computed(() => String(site.value.bandwidth ?? "—"));
const generation = computed(() => String(site.value.generation ?? "0"));

const tabs = [
  { key: "overview", label: "Overview", icon: PhSpeedometer },
  { key: "domains", label: "Domains", icon: PhGlobe },
  { key: "ssl", label: "SSL/TLS", icon: PhLock },
  { key: "apps", label: "Applications", icon: PhPackage },
  { key: "databases", label: "Databases", icon: PhDatabase },
] as const;

onMounted(() => void load());

async function load(): Promise<void> {
  loading.value = true; error.value = "";
  try {
    if (api.available("hosting.site.get")) {
      const response = await api.invoke<unknown>("hosting.site.get", { tenantId: tenantId.value, resourceId: props.siteId });
      if (response.result && typeof response.result === "object") site.value = response.result as Record<string, unknown>;
    }
    // Load related resources in parallel
    const promises: Promise<void>[] = [];
    if (api.available("hosting.binding.list")) {
      promises.push(api.invoke<unknown>("hosting.binding.list", { tenantId: tenantId.value, payload: { limit: 50 } })
        .then(r => { const res = r.result; bindings.value = Array.isArray(res) ? res as Record<string, unknown>[] : (res as { items?: Record<string, unknown>[] })?.items ?? []; })
        .catch(() => { bindings.value = []; }));
    }
    if (api.available("database.database.list")) {
      promises.push(api.invoke<unknown>("database.database.list", { tenantId: tenantId.value, payload: { limit: 50 } })
        .then(r => { const res = r.result; databases.value = Array.isArray(res) ? res as Record<string, unknown>[] : (res as { items?: Record<string, unknown>[] })?.items ?? []; })
        .catch(() => { databases.value = []; }));
    }
    if (api.available("apps.instance.list")) {
      promises.push(api.invoke<unknown>("apps.instance.list", { tenantId: tenantId.value, payload: { limit: 50 } })
        .then(r => { const res = r.result; apps.value = Array.isArray(res) ? res as Record<string, unknown>[] : (res as { items?: Record<string, unknown>[] })?.items ?? []; })
        .catch(() => { apps.value = []; }));
    }
    await Promise.all(promises);
  } catch (cause) { error.value = cause instanceof Error ? cause.message : "Failed to load site."; }
  finally { loading.value = false; }
}

function fmtBytes(value: unknown): string {
  const num = Number(value); if (!Number.isFinite(num) || num < 0) return "—";
  const units = ["B", "KB", "MB", "GB", "TB"]; let amount = num, i = 0;
  while (amount >= 1024 && i < units.length - 1) { amount /= 1024; i++; }
  return `${amount >= 10 || i === 0 ? amount.toFixed(0) : amount.toFixed(1)} ${units[i]}`;
}

function fmtDate(value: unknown): string {
  if (!value) return "—"; const d = new Date(String(value));
  return isNaN(d.valueOf()) ? "—" : d.toLocaleDateString(undefined, { month: "short", day: "numeric", year: "numeric" });
}
</script>

<template>
  <main class="site-detail">
    <!-- Breadcrumb header -->
    <nav class="breadcrumb">
      <button class="back" type="button" @click="router.push('/sites')">
        <PhArrowLeft :size="16"/> All Sites
      </button>
      <span class="sep">/</span>
      <strong>{{ hostname }}</strong>
    </nav>

    <!-- Hero card: site identity + status + quick actions -->
    <header class="site-hero" v-if="!loading && !error">
      <div class="hero-info">
        <div class="hero-title">
          <h2>{{ hostname }}</h2>
          <span class="status" :class="`status-${lifecycle.toLowerCase()}`">{{ lifecycle }}</span>
        </div>
        <div class="hero-meta">
          <span><PhPackage :size="14"/> {{ phpProfile }}</span>
          <span><PhHardDrives :size="14"/> {{ fmtBytes(diskUsage) }} disk</span>
          <span><PhSpeedometer :size="14"/> {{ fmtBytes(bandwidth) }} transfer</span>
          <span class="mono">gen {{ generation }}</span>
        </div>
      </div>
      <div class="hero-actions">
        <button class="button" type="button" :disabled="loading" @click="load">
          <PhArrowClockwise :size="15" :class="{ spinning: loading }"/> Refresh
        </button>
      </div>
    </header>

    <!-- Stat cards row -->
    <section class="stat-row" v-if="!loading && !error">
      <article class="stat-card">
        <div class="stat-icon tone-info"><PhGlobe :size="20"/></div>
        <div><span class="stat-label">Domains</span><strong class="stat-value">{{ bindings.length + 1 }}</strong></div>
      </article>
      <article class="stat-card">
        <div class="stat-icon tone-healthy"><PhDatabase :size="20"/></div>
        <div><span class="stat-label">Databases</span><strong class="stat-value">{{ databases.length }}</strong></div>
      </article>
      <article class="stat-card">
        <div class="stat-icon tone-warning"><PhPackage :size="20"/></div>
        <div><span class="stat-label">Apps</span><strong class="stat-value">{{ apps.length }}</strong></div>
      </article>
      <article class="stat-card">
        <div class="stat-icon tone-info"><PhLock :size="20"/></div>
        <div><span class="stat-label">SSL</span><strong class="stat-value">{{ bindings.some(b => String(b.tls ?? "") !== "") ? 'Active' : 'None' }}</strong></div>
      </article>
    </section>

    <p v-if="error" class="error-banner" role="alert"><PhWarningCircle :size="18"/> {{ error }}</p>
    <div v-if="loading" class="loading-state"><span v-for="i in 4" :key="i" class="skeleton" style="height:80px;border-radius:var(--radius-lg)"/></div>

    <!-- Tabbed content -->
    <div v-if="!loading && !error" class="tab-area">
      <nav class="tabs" role="tablist">
        <button v-for="tab in tabs" :key="tab.key" :class="{ active: activeTab === tab.key }" type="button" role="tab" :aria-selected="activeTab === tab.key" @click="activeTab = tab.key">
          <component :is="tab.icon" :size="16"/> {{ tab.label }}
        </button>
      </nav>

      <!-- OVERVIEW -->
      <section v-if="activeTab === 'overview'" class="tab-panel">
        <div class="info-grid">
          <div class="info-card">
            <h4>Site Information</h4>
            <dl>
              <div><dt>Hostname</dt><dd>{{ hostname }}</dd></div>
              <div><dt>Lifecycle</dt><dd><span class="status" :class="`status-${lifecycle.toLowerCase()}`">{{ lifecycle }}</span></dd></div>
              <div><dt>PHP Runtime</dt><dd>{{ phpProfile }}</dd></div>
              <div><dt>Generation</dt><dd class="mono">{{ generation }}</dd></div>
              <div><dt>Created</dt><dd>{{ fmtDate(site.created_at) }}</dd></div>
              <div><dt>Last Updated</dt><dd>{{ fmtDate(site.updated_at) }}</dd></div>
            </dl>
          </div>
          <div class="info-card">
            <h4>Resource Usage</h4>
            <div class="usage-bars">
              <div class="usage-item">
                <span>Disk</span>
                <div class="bar"><div class="fill tone-info" :style="{ width: '35%' }"/></div>
                <small>{{ fmtBytes(diskUsage) }}</small>
              </div>
              <div class="usage-item">
                <span>Transfer</span>
                <div class="bar"><div class="fill tone-healthy" :style="{ width: '20%' }"/></div>
                <small>{{ fmtBytes(bandwidth) }}</small>
              </div>
            </div>
          </div>
        </div>
      </section>

      <!-- DOMAINS -->
      <section v-if="activeTab === 'domains'" class="tab-panel">
        <div class="domain-list">
          <article v-for="(binding, i) in [{ hostname, relationship: 'primary', tls: 'active' }, ...bindings]" :key="i" class="domain-card">
            <div class="domain-info">
              <PhGlobeHemisphereWest :size="18" class="domain-icon"/>
              <div>
                <strong>{{ binding.hostname ?? binding.name ?? '—' }}</strong>
                <small>{{ binding.relationship ?? binding.kind ?? 'alias' }}</small>
              </div>
            </div>
            <div class="domain-actions">
              <span v-if="binding.tls" class="status status-healthy"><PhCertificate :size="12"/> SSL</span>
              <span v-else class="status status-warning">No SSL</span>
            </div>
          </article>
          <div v-if="!bindings.length" class="empty-hint">
            <PhGlobe :size="24"/>
            <p>No additional domains. Only the primary hostname is bound.</p>
          </div>
        </div>
      </section>

      <!-- SSL -->
      <section v-if="activeTab === 'ssl'" class="tab-panel">
        <div class="ssl-card">
          <PhCertificate :size="32" class="ssl-icon"/>
          <div>
            <h4>TLS Certificate</h4>
            <p v-if="bindings.some(b => String(b.tls ?? '') !== '')" class="ssl-status healthy">
              A certificate is active for this site's domains.
            </p>
            <p v-else class="ssl-status warning">
              No certificate found. A Let's Encrypt certificate can be issued from the Certificates page.
            </p>
            <button class="button" type="button" @click="router.push('/certificates')">
              <PhCertificate :size="15"/> Manage Certificates
            </button>
          </div>
        </div>
      </section>

      <!-- APPS -->
      <section v-if="activeTab === 'apps'" class="tab-panel">
        <div v-if="apps.length" class="app-grid">
          <article v-for="(app, i) in apps" :key="i" class="app-card">
            <PhPackage :size="20" class="app-icon"/>
            <div>
              <strong>{{ app.hostname ?? app.name ?? 'Application' }}</strong>
              <small>{{ app.type ?? 'unknown' }} · v{{ app.version ?? '?' }}</small>
            </div>
            <span class="status" :class="`status-${String(app.health ?? 'unknown').toLowerCase()}`">{{ app.health ?? 'unknown' }}</span>
          </article>
        </div>
        <div v-else class="empty-hint">
          <PhPackage :size="24"/>
          <p>No managed applications installed on this site.</p>
          <button class="button button-primary" type="button" @click="router.push('/wordpress')">Browse Applications</button>
        </div>
      </section>

      <!-- DATABASES -->
      <section v-if="activeTab === 'databases'" class="tab-panel">
        <div v-if="databases.length" class="db-grid">
          <article v-for="(db, i) in databases" :key="i" class="db-card">
            <PhDatabase :size="20" class="db-icon"/>
            <div class="db-info">
              <strong>{{ db.name ?? 'database' }}</strong>
              <small>{{ fmtBytes(db.size) }} · {{ db.principals ?? 0 }} users</small>
            </div>
            <span class="status" :class="`status-${String(db.status ?? 'active').toLowerCase()}`">{{ db.status ?? 'active' }}</span>
          </article>
        </div>
        <div v-else class="empty-hint">
          <PhDatabase :size="24"/>
          <p>No databases associated with this site.</p>
          <button class="button button-primary" type="button" @click="router.push('/databases')">Create Database</button>
        </div>
      </section>
    </div>
  </main>
</template>

<style scoped>
.site-detail{padding:24px clamp(18px,3vw,48px) 64px;max-width:1400px;margin:0 auto}

.breadcrumb{display:flex;align-items:center;gap:10px;margin-bottom:20px;color:var(--subtle);font-size:13px}
.back{display:flex;align-items:center;gap:6px;border:0;background:transparent;color:var(--accent);cursor:pointer;font-size:13px;font-weight:550;padding:4px 8px;border-radius:var(--radius-xs);transition:background .1s ease}
.back:hover{background:var(--surface-2)}
.sep{color:var(--faint)}
.breadcrumb strong{color:var(--text);font-weight:600}

.site-hero{display:flex;justify-content:space-between;align-items:center;gap:20px;padding:24px 28px;border:1px solid var(--border);border-radius:var(--radius-lg);background:linear-gradient(135deg,var(--surface),var(--bg-raised));box-shadow:var(--shadow-sm);margin-bottom:16px}
.hero-title{display:flex;align-items:center;gap:14px;flex-wrap:wrap}
.hero-title h2{margin:0;font-size:clamp(22px,2.5vw,32px);letter-spacing:-.04em;font-weight:700;line-height:1}
.hero-meta{display:flex;gap:18px;flex-wrap:wrap;margin-top:10px;color:var(--muted);font-size:13px}
.hero-meta span{display:flex;align-items:center;gap:5px}
.hero-actions{display:flex;gap:8px}

.stat-row{display:grid;grid-template-columns:repeat(auto-fit,minmax(200px,1fr));gap:12px;margin-bottom:20px}
.stat-card{display:flex;align-items:center;gap:14px;padding:18px 20px;border:1px solid var(--border);border-radius:var(--radius-lg);background:var(--surface);box-shadow:var(--shadow-sm);transition:transform .16s ease,box-shadow .16s ease}
.stat-card:hover{transform:translateY(-1px);box-shadow:var(--shadow)}
.stat-icon{width:44px;height:44px;display:grid;place-items:center;border-radius:var(--radius);flex:0 0 auto}
.tone-info{color:var(--info);background:var(--info-soft)}
.tone-healthy{color:var(--healthy);background:var(--healthy-soft)}
.tone-warning{color:var(--warning);background:var(--warning-soft)}
.stat-label{display:block;font-size:12px;color:var(--subtle);font-weight:550}
.stat-value{font-size:24px;font-weight:700;letter-spacing:-.03em}

.error-banner{display:flex;align-items:center;gap:8px;padding:14px 16px;border-left:3px solid var(--critical);border-radius:var(--radius-xs);background:var(--critical-soft);color:var(--critical);margin:0 0 16px}
.loading-state{display:grid;gap:12px}

.tab-area{border:1px solid var(--border);border-radius:var(--radius-lg);background:var(--surface);box-shadow:var(--shadow-sm);overflow:hidden}
.tabs{display:flex;border-bottom:1px solid var(--border);background:var(--bg-raised);overflow-x:auto}
.tabs button{display:flex;align-items:center;gap:8px;padding:14px 20px;border:0;background:transparent;color:var(--muted);font-size:13px;font-weight:550;cursor:pointer;border-bottom:2px solid transparent;transition:color .12s ease,border-color .12s ease;white-space:nowrap}
.tabs button:hover{color:var(--text)}
.tabs button.active{color:var(--accent);border-bottom-color:var(--accent);font-weight:650}
.tab-panel{padding:24px}

.info-grid{display:grid;grid-template-columns:repeat(auto-fit,minmax(320px,1fr));gap:16px}
.info-card{border:1px solid var(--border);border-radius:var(--radius);background:var(--bg-raised);padding:20px}
.info-card h4{margin:0 0 14px;font-size:14px;font-weight:650;color:var(--text)}
.info-card dl{margin:0;display:flex;flex-direction:column}
.info-card dl>div{display:flex;justify-content:space-between;align-items:center;padding:9px 0;border-bottom:1px solid var(--border)}
.info-card dl>div:last-child{border-bottom:0}
.info-card dt{color:var(--subtle);font-size:12px;font-weight:550}
.info-card dd{margin:0;font-size:13px;font-weight:500}

.usage-bars{display:flex;flex-direction:column;gap:16px}
.usage-item{display:grid;gap:6px}
.usage-item>span{font-size:12px;color:var(--subtle);font-weight:550}
.bar{height:6px;background:var(--surface-2);border-radius:3px;overflow:hidden}
.fill{height:100%;border-radius:3px;transition:width .3s ease}
.fill.tone-info{background:var(--info)}
.fill.tone-healthy{background:var(--healthy)}
.usage-item small{color:var(--subtle);font-size:11px;font-family:var(--font-mono)}

.domain-list{display:flex;flex-direction:column;gap:8px}
.domain-card{display:flex;justify-content:space-between;align-items:center;padding:14px 18px;border:1px solid var(--border);border-radius:var(--radius);background:var(--bg-raised);transition:border-color .12s ease}
.domain-card:hover{border-color:var(--border-bright)}
.domain-info{display:flex;align-items:center;gap:12px}
.domain-icon{color:var(--accent)}
.domain-info strong{font-size:14px;display:block}
.domain-info small{color:var(--subtle);font-size:11px;text-transform:capitalize}

.ssl-card{display:flex;gap:18px;padding:24px;border:1px solid var(--border);border-radius:var(--radius);background:var(--bg-raised);align-items:flex-start}
.ssl-icon{color:var(--accent);flex:0 0 auto;margin-top:4px}
.ssl-card h4{margin:0 0 8px;font-size:15px}
.ssl-status{margin:0 0 14px;font-size:13px;line-height:1.5}
.ssl-status.healthy{color:var(--healthy)}
.ssl-status.warning{color:var(--warning)}

.app-grid,.db-grid{display:grid;grid-template-columns:repeat(auto-fill,minmax(280px,1fr));gap:12px}
.app-card,.db-card{display:flex;align-items:center;gap:14px;padding:16px 18px;border:1px solid var(--border);border-radius:var(--radius);background:var(--bg-raised);transition:border-color .12s ease}
.app-card:hover,.db-card:hover{border-color:var(--border-bright)}
.app-icon{color:var(--warning);flex:0 0 auto}
.db-icon{color:var(--info);flex:0 0 auto}
.app-card>div,.db-info{flex:1;min-width:0}
.app-card strong,.db-info strong{display:block;font-size:14px}
.app-card small,.db-info small{color:var(--subtle);font-size:11px}

.empty-hint{display:grid;place-items:center;gap:12px;padding:48px 24px;color:var(--subtle);text-align:center;border:1px dashed var(--border-strong);border-radius:var(--radius)}
.empty-hint svg{color:var(--faint)}
.empty-hint p{margin:0;font-size:13px;max-width:40ch;line-height:1.5}

.spinning{animation:spin .8s linear infinite}
@keyframes spin{to{transform:rotate(1turn)}}
</style>
