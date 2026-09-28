<script setup lang="ts">
// Certificate status cards — visual grid with expiry countdown and issuer.
import { computed, inject, onMounted, ref } from "vue";
import {
  PhArrowClockwise, PhCertificate, PhPlus, PhLock, PhShieldCheck, PhWarning,
} from "@phosphor-icons/vue";
import type { APIClient } from "../api";
import { sessionStore } from "../store";

const api = inject<APIClient>("api")!;
const loading = ref(true);
const error = ref("");
const certs = ref<Record<string, unknown>[]>([]);

const tenantId = computed(() => sessionStore.state.tenantId || undefined);
onMounted(() => void load());

async function load(): Promise<void> {
  loading.value = true; error.value = "";
  try {
    if (api.available("certificate.list") || api.available("certificate.issuance.list")) {
      const op = api.available("certificate.list") ? "certificate.list" : "certificate.issuance.list";
      const response = await api.invoke<unknown>(op, { tenantId: tenantId.value, payload: { limit: 100 } });
      const result = response.result;
      certs.value = Array.isArray(result) ? result as Record<string, unknown>[] : (result as { items?: Record<string, unknown>[] })?.items ?? [];
    }
  } catch (cause) { error.value = cause instanceof Error ? cause.message : "Failed to load certificates."; }
  finally { loading.value = false; }
}

function daysUntil(dateStr: unknown): number {
  if (!dateStr) return Infinity;
  const d = new Date(String(dateStr));
  if (isNaN(d.valueOf())) return Infinity;
  return Math.ceil((d.getTime() - Date.now()) / 86400000);
}
function expiryClass(dateStr: unknown): string {
  const days = daysUntil(dateStr);
  if (days === Infinity) return "neutral";
  if (days < 0) return "critical";
  if (days < 14) return "warning";
  return "healthy";
}
function expiryText(dateStr: unknown): string {
  const days = daysUntil(dateStr);
  if (days === Infinity) return "No expiry";
  if (days < 0) return `Expired ${Math.abs(days)}d ago`;
  if (days === 0) return "Expires today";
  if (days === 1) return "Expires tomorrow";
  return `${days} days left`;
}
</script>

<template>
  <main class="cert-page">
    <header class="page-header">
      <div>
        <h2>Certificates</h2>
        <p>{{ certs.length }} certificate{{ certs.length === 1 ? '' : 's' }} managed</p>
      </div>
      <div class="header-actions">
        <button class="button" type="button" :disabled="loading" @click="load">
          <PhArrowClockwise :size="15" :class="{ spinning: loading }"/> Refresh
        </button>
        <button class="button button-primary" type="button">
          <PhPlus :size="16" weight="bold"/> Issue Certificate
        </button>
      </div>
    </header>

    <p v-if="error" class="error-banner">{{ error }}</p>
    <div v-if="loading" class="loading"><span v-for="i in 3" :key="i" class="skeleton" style="height:140px;border-radius:var(--radius-lg)"/></div>

    <div v-if="!loading && certs.length" class="cert-grid">
      <article v-for="(cert, i) in certs" :key="i" class="cert-card">
        <div class="cert-icon" :class="expiryClass(cert.not_after ?? cert.expires_at)">
          <PhCertificate :size="22" weight="duotone"/>
        </div>
        <div class="cert-body">
          <strong>{{ cert.names?.[0] ?? cert.domains?.[0] ?? cert.name ?? cert.id ?? 'Certificate' }}</strong>
          <div class="cert-meta">
            <span class="expiry" :class="expiryClass(cert.not_after ?? cert.expires_at)">
              <PhShieldCheck v-if="expiryClass(cert.not_after ?? cert.expires_at) === 'healthy'" :size="13"/>
              <PhWarning v-else :size="13"/>
              {{ expiryText(cert.not_after ?? cert.expires_at) }}
            </span>
            <span v-if="cert.issuer" class="issuer">{{ cert.issuer }}</span>
            <span v-if="cert.names?.length > 1" class="sans">{{ cert.names.length }} domains</span>
          </div>
        </div>
        <div class="cert-actions">
          <button class="button button-small" type="button">Renew</button>
          <button class="button button-small button-danger" type="button">Revoke</button>
        </div>
      </article>
    </div>

    <div v-if="!loading && !certs.length && !error" class="empty-state">
      <PhLock :size="48" weight="duotone"/>
      <h3>No certificates</h3>
      <p>Issue a free Let's Encrypt certificate to enable HTTPS for your sites. Certificates auto-renew before expiry.</p>
      <button class="button button-primary" type="button"><PhPlus :size="16"/> Issue Certificate</button>
    </div>
  </main>
</template>

<style scoped>
.cert-page{padding:32px clamp(18px,3vw,48px) 64px;max-width:1400px;margin:0 auto}
.page-header{display:flex;justify-content:space-between;align-items:center;gap:20px;margin-bottom:24px}
.page-header h2{margin:0 0 4px;font-size:clamp(24px,2.5vw,32px);letter-spacing:-.04em;font-weight:700}
.page-header p{margin:0;color:var(--muted);font-size:14px}
.header-actions{display:flex;gap:8px}
.error-banner{padding:14px 16px;border-left:3px solid var(--critical);border-radius:var(--radius-xs);background:var(--critical-soft);color:var(--critical);margin:0 0 16px}
.loading{display:grid;gap:12px}

.cert-grid{display:grid;grid-template-columns:repeat(auto-fill,minmax(400px,1fr));gap:14px}
.cert-card{display:flex;align-items:center;gap:16px;padding:18px 20px;border:1px solid var(--border);border-radius:var(--radius-lg);background:var(--surface);box-shadow:var(--shadow-sm);transition:transform .16s ease,box-shadow .16s ease}
.cert-card:hover{transform:translateY(-1px);box-shadow:var(--shadow)}

.cert-icon{width:48px;height:48px;display:grid;place-items:center;border-radius:var(--radius);flex:0 0 auto}
.cert-icon.healthy{color:var(--healthy);background:var(--healthy-soft)}
.cert-icon.warning{color:var(--warning);background:var(--warning-soft)}
.cert-icon.critical{color:var(--critical);background:var(--critical-soft)}
.cert-icon.neutral{color:var(--subtle);background:var(--surface-2)}

.cert-body{flex:1;min-width:0}
.cert-body strong{display:block;font-size:15px;letter-spacing:-.02em;margin-bottom:6px;word-break:break-all}
.cert-meta{display:flex;gap:10px;flex-wrap:wrap;align-items:center}
.expiry{display:flex;align-items:center;gap:4px;font-size:12px;font-weight:600}
.expiry.healthy{color:var(--healthy)}
.expiry.warning{color:var(--warning)}
.expiry.critical{color:var(--critical)}
.issuer{color:var(--subtle);font-size:11px;font-family:var(--font-mono)}
.sans{color:var(--subtle);font-size:11px;background:var(--surface-2);padding:2px 8px;border-radius:var(--radius-xs)}

.cert-actions{display:flex;gap:6px;flex:0 0 auto}
.empty-state{display:grid;place-items:center;gap:14px;padding:64px 24px;text-align:center;border:1px dashed var(--border-strong);border-radius:var(--radius-lg)}
.empty-state svg{color:var(--faint)}
.empty-state h3{margin:0;font-size:18px}
.empty-state p{margin:0;color:var(--muted);font-size:13px;max-width:44ch;line-height:1.5}
.spinning{animation:spin .8s linear infinite}
@keyframes spin{to{transform:rotate(1turn)}}
</style>
