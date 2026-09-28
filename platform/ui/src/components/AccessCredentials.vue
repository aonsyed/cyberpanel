<script setup lang="ts">
import { computed, inject, onMounted, ref } from "vue";
import { PhArrowClockwise, PhKey, PhPlus, PhTerminalWindow, PhTrash, PhUser } from "@phosphor-icons/vue";
import type { APIClient } from "../api";
import { sessionStore } from "../store";

const api = inject<APIClient>("api")!;
const loading = ref(true);
const error = ref("");
const credentials = ref<Record<string, unknown>[]>([]);

const tenantId = computed(() => sessionStore.state.tenantId || undefined);
onMounted(() => void load());

async function load(): Promise<void> {
  loading.value = true; error.value = "";
  try {
    if (api.available("access.credential.list")) {
      const response = await api.invoke<unknown>("access.credential.list", { tenantId: tenantId.value, payload: { limit: 100 } });
      const result = response.result;
      credentials.value = Array.isArray(result) ? result as Record<string, unknown>[] : (result as { items?: Record<string, unknown>[] })?.items ?? [];
    }
  } catch { credentials.value = []; }
  finally { loading.value = false; }
}

function credType(cred: Record<string, unknown>): string {
  const kind = String(cred.kind ?? cred.type ?? "");
  if (kind.includes("ssh")) return "SSH Key";
  if (kind.includes("ftp")) return "FTP";
  return kind || "Credential";
}
function typeIcon(kind: string): unknown {
  if (kind.includes("SSH")) return PhKey;
  return PhUser;
}
function fmtDate(value: unknown): string {
  if (!value) return ""; const d = new Date(String(value));
  return isNaN(d.valueOf()) ? "" : d.toLocaleDateString(undefined, { month: "short", day: "numeric", year: "numeric" });
}
</script>

<template>
  <main class="access-page">
    <header class="page-header">
      <div><h2>FTP & SSH</h2><p>{{ credentials.length }} credential{{ credentials.length === 1 ? '' : 's' }}</p></div>
      <div class="header-actions">
        <button class="button" type="button" :disabled="loading" @click="load"><PhArrowClockwise :size="15" :class="{ spinning: loading }"/> Refresh</button>
        <button class="button button-primary" type="button"><PhPlus :size="16" weight="bold"/> Add Credential</button>
      </div>
    </header>

    <div v-if="loading" class="loading"><span v-for="i in 3" :key="i" class="skeleton" style="height:80px;border-radius:var(--radius-lg)"/></div>

    <div v-if="!loading && credentials.length" class="cred-list">
      <article v-for="(cred, i) in credentials" :key="i" class="cred-card">
        <div class="cred-icon" :class="credType(cred).toLowerCase().replace(' ', '-')">
          <component :is="typeIcon(credType(cred))" :size="20" weight="duotone"/>
        </div>
        <div class="cred-info">
          <strong>{{ cred.label ?? cred.name ?? cred.id ?? 'Credential' }}</strong>
          <div class="cred-meta">
            <span class="cred-type-badge">{{ credType(cred) }}</span>
            <span v-if="cred.expires_at" class="cred-expiry">Expires {{ fmtDate(cred.expires_at) }}</span>
            <span class="status" :class="`status-${String(cred.state ?? 'active').toLowerCase()}`">{{ cred.state ?? 'active' }}</span>
          </div>
        </div>
        <div class="cred-actions">
          <button class="button button-small" type="button"><PhTerminalWindow :size="14"/> Use</button>
          <button class="button button-small button-danger" type="button"><PhTrash :size="14"/></button>
        </div>
      </article>
    </div>

    <div v-if="!loading && !credentials.length" class="empty-state">
      <PhKey :size="48" weight="duotone"/>
      <h3>No FTP or SSH credentials</h3>
      <p>Create an FTP account for file uploads, or add an SSH key for secure terminal access to your websites.</p>
      <button class="button button-primary" type="button"><PhPlus :size="16"/> Add Your First Credential</button>
    </div>
  </main>
</template>

<style scoped>
.access-page{padding:32px clamp(18px,3vw,48px) 64px;max-width:1400px;margin:0 auto}
.page-header{display:flex;justify-content:space-between;align-items:center;gap:20px;margin-bottom:24px}
.page-header h2{margin:0 0 4px;font-size:clamp(24px,2.5vw,32px);letter-spacing:-.04em;font-weight:700}
.page-header p{margin:0;color:var(--muted);font-size:14px}
.header-actions{display:flex;gap:8px}
.loading{display:grid;gap:12px}
.cred-list{display:flex;flex-direction:column;gap:10px}
.cred-card{display:flex;align-items:center;gap:16px;padding:16px 20px;border:1px solid var(--border);border-radius:var(--radius-lg);background:var(--surface);box-shadow:var(--shadow-sm);transition:border-color .12s ease}
.cred-card:hover{border-color:var(--border-bright)}
.cred-icon{width:44px;height:44px;display:grid;place-items:center;border-radius:var(--radius);flex:0 0 auto}
.cred-icon.ssh-key{color:var(--accent);background:var(--accent-soft)}
.cred-icon.ftp{color:var(--info);background:var(--info-soft)}
.cred-icon.credential{color:var(--muted);background:var(--surface-2)}
.cred-info{flex:1;min-width:0}
.cred-info strong{font-size:14px;display:block;letter-spacing:-.01em}
.cred-meta{display:flex;gap:10px;align-items:center;margin-top:6px;flex-wrap:wrap}
.cred-type-badge{padding:2px 8px;border-radius:var(--radius-xs);font:600 10px/1.4 var(--font-mono);background:var(--surface-2);color:var(--muted);text-transform:uppercase;letter-spacing:.06em}
.cred-expiry{color:var(--subtle);font-size:11px}
.cred-actions{display:flex;gap:6px;flex:0 0 auto}
.empty-state{display:grid;place-items:center;gap:14px;padding:64px 24px;text-align:center;border:1px dashed var(--border-strong);border-radius:var(--radius-lg)}
.empty-state svg{color:var(--faint)}
.empty-state h3{margin:0;font-size:18px}
.empty-state p{margin:0;color:var(--muted);font-size:13px;max-width:44ch;line-height:1.5}
.spinning{animation:spin .8s linear infinite}
@keyframes spin{to{transform:rotate(1turn)}}
</style>
