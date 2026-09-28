<script setup lang="ts">
// DNS zone editor — visual record cards replacing the flat record table.
// Each record gets a type badge, name, value, TTL, and inline actions.
import { computed, inject, onMounted, ref } from "vue";
import {
  PhArrowClockwise, PhGlobe, PhPlus, PhTrash, PhTreeStructure, PhX,
} from "@phosphor-icons/vue";
import type { APIClient } from "../api";
import { sessionStore } from "../store";

const api = inject<APIClient>("api")!;
const loading = ref(true);
const error = ref("");
const zones = ref<Record<string, unknown>[]>([]);
const activeZone = ref<string>("");
const records = ref<Record<string, unknown>[]>([]);
const showAddRecord = ref(false);
const newRecord = ref({ name: "", type: "A", value: "", ttl: "3600" });

const tenantId = computed(() => sessionStore.state.tenantId || undefined);

onMounted(() => void load());

async function load(): Promise<void> {
  loading.value = true; error.value = "";
  try {
    if (api.available("dns.zone.list")) {
      const response = await api.invoke<unknown>("dns.zone.list", { tenantId: tenantId.value, payload: { limit: 100 } });
      const result = response.result;
      zones.value = Array.isArray(result) ? result as Record<string, unknown>[] : (result as { items?: Record<string, unknown>[] })?.items ?? [];
      if (zones.value.length && !activeZone.value) {
        activeZone.value = String(zones.value[0]?.name ?? zones.value[0]?.id ?? "");
        await loadRecords();
      }
    }
  } catch (cause) { error.value = cause instanceof Error ? cause.message : "Failed to load DNS zones."; }
  finally { loading.value = false; }
}

async function loadRecords(): Promise<void> {
  if (!activeZone.value || !api.available("dns.recordset.list")) { records.value = []; return; }
  try {
    const response = await api.invoke<unknown>("dns.recordset.list", { tenantId: tenantId.value, resourceId: activeZone.value, payload: { limit: 200 } });
    const result = response.result;
    records.value = Array.isArray(result) ? result as Record<string, unknown>[] : (result as { items?: Record<string, unknown>[] })?.items ?? [];
  } catch { records.value = []; }
}

function selectZone(zone: Record<string, unknown>): void {
  activeZone.value = String(zone.name ?? zone.id ?? "");
  void loadRecords();
}

function recordTypeClass(type: string): string {
  const t = type.toUpperCase();
  if (t === "A" || t === "AAAA") return "type-address";
  if (t === "CNAME") return "type-cname";
  if (t === "MX") return "type-mx";
  if (t === "TXT") return "type-txt";
  if (t === "NS") return "type-ns";
  if (t === "SOA") return "type-soa";
  return "type-other";
}
</script>

<template>
  <main class="dns-page">
    <header class="page-header">
      <div>
        <h2>DNS Zones</h2>
        <p>{{ zones.length }} zone{{ zones.length === 1 ? '' : 's' }} · {{ records.length }} record{{ records.length === 1 ? '' : 's' }}</p>
      </div>
      <div class="header-actions">
        <button class="button" type="button" :disabled="loading" @click="load">
          <PhArrowClockwise :size="15" :class="{ spinning: loading }"/> Refresh
        </button>
        <button class="button button-primary" type="button">
          <PhPlus :size="16" weight="bold"/> Add Zone
        </button>
      </div>
    </header>

    <p v-if="error" class="error-banner">{{ error }}</p>
    <div v-if="loading" class="loading"><span v-for="i in 4" :key="i" class="skeleton" style="height:60px"/></div>

    <div v-if="!loading && zones.length" class="dns-layout">
      <!-- Zone selector sidebar -->
      <aside class="zone-list">
        <h3>Zones</h3>
        <button v-for="zone in zones" :key="String(zone.id)" :class="{ active: activeZone === String(zone.name ?? zone.id) }" type="button" class="zone-item" @click="selectZone(zone)">
          <PhGlobe :size="16"/>
          <span>{{ zone.name ?? zone.id }}</span>
        </button>
      </aside>

      <!-- Records for selected zone -->
      <section class="records-area">
        <header class="records-header">
          <h3>{{ activeZone }}</h3>
          <button class="button button-small button-primary" type="button" @click="showAddRecord = !showAddRecord">
            <PhPlus :size="14"/> Add Record
          </button>
        </header>

        <!-- Add record inline form -->
        <div v-if="showAddRecord" class="add-record-form">
          <div class="add-fields">
            <label class="field-sm">Name<input v-model="newRecord.name" class="input" placeholder="@"/></label>
            <label class="field-sm">Type<select v-model="newRecord.type" class="input"><option>A</option><option>AAAA</option><option>CNAME</option><option>MX</option><option>TXT</option><option>NS</option><option>SRV</option></select></label>
            <label class="field-sm">Value<input v-model="newRecord.value" class="input" placeholder="192.168.1.1"/></label>
            <label class="field-sm">TTL<input v-model="newRecord.ttl" class="input" type="number"/></label>
          </div>
          <div class="add-actions">
            <button class="button button-small" type="button" @click="showAddRecord = false">Cancel</button>
            <button class="button button-small button-primary" type="button">Add Record</button>
          </div>
        </div>

        <!-- Record cards -->
        <div v-if="records.length" class="record-list">
          <article v-for="(record, i) in records" :key="i" class="record-card">
            <span class="record-type" :class="recordTypeClass(String(record.type ?? ''))">{{ record.type ?? '?' }}</span>
            <div class="record-body">
              <strong>{{ record.name ?? record.owner ?? '@' }}</strong>
              <span class="record-value">{{ record.value ?? record.content ?? record.records ?? '—' }}</span>
            </div>
            <span class="record-ttl">{{ record.ttl ?? '3600' }}</span>
            <button class="record-delete" type="button" aria-label="Delete record">
              <PhTrash :size="14"/>
            </button>
          </article>
        </div>
        <div v-else class="empty-hint">
          <PhTreeStructure :size="24"/>
          <p>No records in this zone yet. Add your first record to start resolving.</p>
        </div>
      </section>
    </div>

    <!-- Empty state -->
    <div v-if="!loading && !zones.length && !error" class="empty-state">
      <PhGlobe :size="48" weight="duotone"/>
      <h3>No DNS zones</h3>
      <p>Create a DNS zone to manage records for your domains — A, AAAA, CNAME, MX, TXT and more.</p>
      <button class="button button-primary" type="button"><PhPlus :size="16"/> Create Your First Zone</button>
    </div>
  </main>
</template>

<style scoped>
.dns-page{padding:32px clamp(18px,3vw,48px) 64px;max-width:1400px;margin:0 auto}
.page-header{display:flex;justify-content:space-between;align-items:center;gap:20px;margin-bottom:24px}
.page-header h2{margin:0 0 4px;font-size:clamp(24px,2.5vw,32px);letter-spacing:-.04em;font-weight:700}
.page-header p{margin:0;color:var(--muted);font-size:14px}
.header-actions{display:flex;gap:8px}
.error-banner{padding:14px 16px;border-left:3px solid var(--critical);border-radius:var(--radius-xs);background:var(--critical-soft);color:var(--critical);margin:0 0 16px}
.loading{display:grid;gap:10px}

.dns-layout{display:grid;grid-template-columns:240px minmax(0,1fr);gap:16px}

.zone-list{border:1px solid var(--border);border-radius:var(--radius-lg);background:var(--surface);padding:12px;box-shadow:var(--shadow-sm)}
.zone-list h3{margin:0 0 10px;padding:0 8px;font:600 10px/1 var(--font-mono);text-transform:uppercase;letter-spacing:.12em;color:var(--subtle)}
.zone-item{display:flex;align-items:center;gap:10px;width:100%;padding:10px 12px;border:0;border-radius:var(--radius-sm);background:transparent;color:var(--muted);font-size:13px;font-weight:500;cursor:pointer;text-align:left;transition:background .1s ease,color .1s ease}
.zone-item:hover{background:var(--surface-2);color:var(--text)}
.zone-item.active{background:var(--accent-soft);color:var(--accent);font-weight:650}
.zone-item svg{flex:0 0 auto}

.records-area{border:1px solid var(--border);border-radius:var(--radius-lg);background:var(--surface);box-shadow:var(--shadow-sm);overflow:hidden}
.records-header{display:flex;justify-content:space-between;align-items:center;padding:16px 20px;border-bottom:1px solid var(--border)}
.records-header h3{margin:0;font-size:16px;font-weight:650;letter-spacing:-.02em;word-break:break-all}

.add-record-form{padding:16px 20px;border-bottom:1px solid var(--border);background:var(--bg-raised)}
.add-fields{display:grid;grid-template-columns:1fr 100px 2fr 80px;gap:10px;margin-bottom:12px}
.field-sm{display:grid;gap:4px;font-size:11px;font-weight:600;color:var(--subtle)}
.field-sm .input{min-height:36px;padding:6px 10px;font-size:13px}
.add-actions{display:flex;justify-content:flex-end;gap:8px}

.record-list{display:flex;flex-direction:column}
.record-card{display:flex;align-items:center;gap:14px;padding:12px 20px;border-bottom:1px solid var(--border);transition:background .1s ease}
.record-card:last-child{border-bottom:0}
.record-card:hover{background:var(--surface-2)}

.record-type{min-width:52px;text-align:center;padding:4px 0;border-radius:var(--radius-xs);font:700 11px/1.4 var(--font-mono);letter-spacing:.06em}
.type-address{color:var(--info);background:var(--info-soft)}
.type-cname{color:var(--accent);background:var(--accent-soft)}
.type-mx{color:var(--warning);background:var(--warning-soft)}
.type-txt{color:var(--muted);background:var(--surface-2)}
.type-ns{color:var(--healthy);background:var(--healthy-soft)}
.type-soa{color:var(--subtle);background:var(--surface-3)}
.type-other{color:var(--muted);background:var(--surface-2)}

.record-body{flex:1;min-width:0;display:grid;gap:2px}
.record-body strong{font-size:13px;font-weight:600}
.record-value{color:var(--subtle);font-size:12px;font-family:var(--font-mono);word-break:break-all;overflow:hidden;text-overflow:ellipsis;white-space:nowrap}
.record-ttl{color:var(--subtle);font:500 11px/1 var(--font-mono);flex:0 0 auto}
.record-delete{width:28px;height:28px;border:0;border-radius:var(--radius-xs);background:transparent;color:var(--faint);display:grid;place-items:center;cursor:pointer;opacity:0;transition:opacity .1s ease,background .1s ease,color .1s ease}
.record-card:hover .record-delete{opacity:1}
.record-delete:hover{background:var(--critical-soft);color:var(--critical)}

.empty-hint{display:grid;place-items:center;gap:10px;padding:40px 24px;color:var(--subtle);text-align:center}
.empty-hint p{margin:0;font-size:13px;max-width:40ch;line-height:1.5}
.empty-state{display:grid;place-items:center;gap:14px;padding:64px 24px;text-align:center;border:1px dashed var(--border-strong);border-radius:var(--radius-lg)}
.empty-state svg{color:var(--faint)}
.empty-state h3{margin:0;font-size:18px}
.empty-state p{margin:0;color:var(--muted);font-size:13px;max-width:44ch;line-height:1.5}

.spinning{animation:spin .8s linear infinite}
@keyframes spin{to{transform:rotate(1turn)}}
@media(max-width:900px){.dns-layout{grid-template-columns:1fr}.add-fields{grid-template-columns:1fr 1fr}}
</style>
