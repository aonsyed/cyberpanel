<script setup lang="ts">
// Mail domain cards — visual grid replacing the flat mail table.
// Each card shows the domain, mailbox count, DKIM status, and quick actions.
import { computed, inject, onMounted, ref } from "vue";
import {
  PhArrowClockwise, PhAt, PhEnvelopeSimple, PhLock, PhPlus,
  PhShieldCheck, PhUsersThree, PhWarning,
} from "@phosphor-icons/vue";
import type { APIClient } from "../api";
import { sessionStore } from "../store";

const api = inject<APIClient>("api")!;
const loading = ref(true);
const error = ref("");
const domains = ref<Record<string, unknown>[]>([]);
const mailboxes = ref<Record<string, unknown>[]>([]);

const tenantId = computed(() => sessionStore.state.tenantId || undefined);

onMounted(() => void load());

async function load(): Promise<void> {
  loading.value = true; error.value = "";
  try {
    if (api.available("mail.domain.list")) {
      const response = await api.invoke<unknown>("mail.domain.list", { tenantId: tenantId.value, payload: { limit: 100 } });
      const result = response.result;
      domains.value = Array.isArray(result) ? result as Record<string, unknown>[] : (result as { items?: Record<string, unknown>[] })?.items ?? [];
    }
    if (api.available("mail.mailbox.list")) {
      const response = await api.invoke<unknown>("mail.mailbox.list", { tenantId: tenantId.value, payload: { limit: 200 } });
      const result = response.result;
      mailboxes.value = Array.isArray(result) ? result as Record<string, unknown>[] : (result as { items?: Record<string, unknown>[] })?.items ?? [];
    }
  } catch (cause) { error.value = cause instanceof Error ? cause.message : "Failed to load mail domains."; }
  finally { loading.value = false; }
}

function mailboxCount(domainName: string): number {
  return mailboxes.value.filter(m => String(m.domain ?? m.domain_id ?? "").includes(domainName)).length;
}

function dkimStatus(domain: Record<string, unknown>): string {
  return String(domain.dkim_status ?? domain.dkim ?? "unknown");
}
</script>

<template>
  <main class="mail-page">
    <header class="page-header">
      <div>
        <h2>Mail</h2>
        <p>{{ domains.length }} domain{{ domains.length === 1 ? '' : 's' }} · {{ mailboxes.length }} mailbox{{ mailboxes.length === 1 ? '' : 'es' }}</p>
      </div>
      <div class="header-actions">
        <button class="button" type="button" :disabled="loading" @click="load">
          <PhArrowClockwise :size="15" :class="{ spinning: loading }"/> Refresh
        </button>
        <button class="button button-primary" type="button">
          <PhPlus :size="16" weight="bold"/> Add Domain
        </button>
      </div>
    </header>

    <p v-if="error" class="error-banner">{{ error }}</p>

    <div v-if="loading" class="loading-grid">
      <div v-for="i in 2" :key="i" class="skeleton" style="height: 160px; border-radius: var(--radius-lg)"/>
    </div>

    <!-- Domain cards -->
    <div v-if="!loading && domains.length" class="domain-grid">
      <article v-for="(domain, i) in domains" :key="i" class="domain-card">
        <header class="domain-head">
          <div class="domain-icon">
            <PhAt :size="22" weight="duotone"/>
          </div>
          <div class="domain-title">
            <strong>{{ domain.name ?? domain.domain ?? 'domain' }}</strong>
            <small>{{ mailboxCount(String(domain.name ?? domain.domain ?? '')) }} mailboxes</small>
          </div>
        </header>

        <div class="domain-status">
          <div class="status-item">
            <PhEnvelopeSimple :size="14"/>
            <span>{{ mailboxCount(String(domain.name ?? domain.domain ?? '')) }} accounts</span>
          </div>
          <div class="status-item" :class="{ healthy: dkimStatus(domain) === 'active' }">
            <PhShieldCheck v-if="dkimStatus(domain) === 'active'" :size="14"/>
            <PhWarning v-else :size="14"/>
            <span>DKIM {{ dkimStatus(domain) }}</span>
          </div>
          <div class="status-item">
            <PhLock :size="14"/>
            <span>TLS {{ domain.tls_status ?? 'auto' }}</span>
          </div>
        </div>

        <footer class="domain-actions">
          <button class="button button-small" type="button">Manage Mailboxes</button>
          <button class="button button-small" type="button">Aliases</button>
          <button class="button button-small" type="button">DKIM</button>
        </footer>
      </article>
    </div>

    <!-- Empty state -->
    <div v-if="!loading && !domains.length && !error" class="empty-state">
      <PhEnvelopeSimple :size="48" weight="duotone"/>
      <h3>No mail domains</h3>
      <p>Add a mail domain to create email addresses, aliases, and catch-all routing for your sites.</p>
      <button class="button button-primary" type="button">
        <PhPlus :size="16"/> Add Your First Domain
      </button>
    </div>
  </main>
</template>

<style scoped>
.mail-page{padding:32px clamp(18px,3vw,48px) 64px;max-width:1400px;margin:0 auto}

.page-header{display:flex;justify-content:space-between;align-items:center;gap:20px;margin-bottom:24px}
.page-header h2{margin:0 0 4px;font-size:clamp(24px,2.5vw,32px);letter-spacing:-.04em;font-weight:700}
.page-header p{margin:0;color:var(--muted);font-size:14px}
.header-actions{display:flex;gap:8px}

.error-banner{padding:14px 16px;border-left:3px solid var(--critical);border-radius:var(--radius-xs);background:var(--critical-soft);color:var(--critical);margin:0 0 16px}

.loading-grid{display:grid;grid-template-columns:repeat(auto-fill,minmax(380px,1fr));gap:14px}

.domain-grid{display:grid;grid-template-columns:repeat(auto-fill,minmax(380px,1fr));gap:14px}

.domain-card{border:1px solid var(--border);border-radius:var(--radius-lg);background:var(--surface);box-shadow:var(--shadow-sm);display:flex;flex-direction:column;transition:transform .16s ease,box-shadow .16s ease}
.domain-card:hover{transform:translateY(-2px);box-shadow:var(--shadow)}

.domain-head{display:flex;align-items:center;gap:14px;padding:18px 20px;border-bottom:1px solid var(--border)}
.domain-icon{width:44px;height:44px;display:grid;place-items:center;border-radius:var(--radius);background:var(--accent-soft);color:var(--accent);flex:0 0 auto}
.domain-title{flex:1;min-width:0}
.domain-title strong{display:block;font-size:16px;letter-spacing:-.02em;word-break:break-all}
.domain-title small{color:var(--subtle);font-size:12px}

.domain-status{display:flex;flex-direction:column;gap:8px;padding:14px 20px}
.status-item{display:flex;align-items:center;gap:8px;color:var(--muted);font-size:13px;font-weight:500}
.status-item svg{color:var(--subtle);flex:0 0 auto}
.status-item.healthy{color:var(--healthy)}
.status-item.healthy svg{color:var(--healthy)}

.domain-actions{display:flex;gap:6px;padding:12px 20px;border-top:1px solid var(--border);margin-top:auto}

.empty-state{display:grid;place-items:center;gap:14px;padding:64px 24px;text-align:center;border:1px dashed var(--border-strong);border-radius:var(--radius-lg);background:var(--surface)}
.empty-state svg{color:var(--faint)}
.empty-state h3{margin:0;font-size:18px;font-weight:650}
.empty-state p{margin:0;color:var(--muted);font-size:13px;max-width:44ch;line-height:1.5}

.spinning{animation:spin .8s linear infinite}
@keyframes spin{to{transform:rotate(1turn)}}
</style>
