<script setup lang="ts">
// Users/tenants page — visual user cards with avatar initials, role
// badges, session status, and quota usage bars.
import { computed, inject, onMounted, ref } from "vue";
import {
  PhArrowClockwise, PhPlus, PhShieldCheck, PhUserCircle, PhUsersThree,
} from "@phosphor-icons/vue";
import type { APIClient } from "../api";
import { sessionStore } from "../store";

const api = inject<APIClient>("api")!;
const loading = ref(true);
const error = ref("");
const users = ref<Record<string, unknown>[]>([]);
const tenants = ref<Record<string, unknown>[]>([]);

const tenantId = computed(() => sessionStore.state.tenantId || undefined);
onMounted(() => void load());

async function load(): Promise<void> {
  loading.value = true; error.value = "";
  try {
    if (api.available("identity.tenant.list")) {
      const response = await api.invoke<unknown>("identity.tenant.list", { payload: { limit: 100 } });
      const result = response.result;
      tenants.value = Array.isArray(result) ? result as Record<string, unknown>[] : (result as { items?: Record<string, unknown>[] })?.items ?? [];
    }
  } catch (cause) { error.value = cause instanceof Error ? cause.message : "Failed to load users."; }
  finally { loading.value = false; }
}

function initials(name: string): string {
  return name.split(/[\s@._-]+/).filter(Boolean).map(p => p[0]).join("").slice(0, 2).toUpperCase();
}
function roleColor(role: string): string {
  const r = role.toLowerCase();
  if (r.includes("owner") || r.includes("admin")) return "owner";
  if (r.includes("manager") || r.includes("editor")) return "manager";
  return "member";
}
</script>

<template>
  <main class="users-page">
    <header class="page-header">
      <div>
        <h2>Users & Teams</h2>
        <p>{{ tenants.length }} tenant{{ tenants.length === 1 ? '' : 's' }} · {{ users.length }} user{{ users.length === 1 ? '' : 's' }}</p>
      </div>
      <div class="header-actions">
        <button class="button" type="button" :disabled="loading" @click="load">
          <PhArrowClockwise :size="15" :class="{ spinning: loading }"/> Refresh
        </button>
        <button class="button button-primary" type="button">
          <PhPlus :size="16" weight="bold"/> Add User
        </button>
      </div>
    </header>

    <p v-if="error" class="error-banner">{{ error }}</p>
    <div v-if="loading" class="loading-grid">
      <div v-for="i in 3" :key="i" class="skeleton" style="height:120px;border-radius:var(--radius-lg)"/>
    </div>

    <!-- Tenant/user cards grid -->
    <div v-if="!loading && tenants.length" class="user-grid">
      <article v-for="(tenant, i) in tenants" :key="i" class="user-card">
        <div class="user-avatar" :class="roleColor(String(tenant.kind ?? tenant.role ?? 'member'))">
          {{ initials(String(tenant.name ?? tenant.display_name ?? tenant.id ?? 'U')) }}
        </div>
        <div class="user-info">
          <div class="user-title-row">
            <strong>{{ tenant.name ?? tenant.display_name ?? tenant.id ?? 'User' }}</strong>
            <span v-if="tenant.kind || tenant.role" class="role-badge" :class="roleColor(String(tenant.kind ?? tenant.role))">
              <PhShieldCheck :size="10"/> {{ tenant.kind ?? tenant.role }}
            </span>
          </div>
          <div class="user-meta">
            <span v-if="tenant.email" class="user-email">{{ tenant.email }}</span>
            <span class="status" :class="`status-${String(tenant.state ?? tenant.membership_state ?? 'active').toLowerCase()}`">
              {{ tenant.state ?? tenant.membership_state ?? 'active' }}
            </span>
          </div>
          <div v-if="tenant.quota_used !== undefined || tenant.disk_used !== undefined" class="quota-bar">
            <div class="quota-fill" :style="{ width: '30%' }"/>
            <small>{{ tenant.quota_used ?? tenant.disk_used ?? '0' }} / {{ tenant.quota_limit ?? tenant.disk_limit ?? '∞' }}</small>
          </div>
        </div>
        <div class="user-actions">
          <button class="button button-small" type="button">Manage</button>
          <button class="button button-small button-danger" type="button">Suspend</button>
        </div>
      </article>
    </div>

    <!-- Empty state -->
    <div v-if="!loading && !tenants.length && !error" class="empty-state">
      <PhUsersThree :size="48" weight="duotone"/>
      <h3>No other users yet</h3>
      <p>Add team members to help manage your websites, databases, and email. Each person gets their own permissions.</p>
      <button class="button button-primary" type="button"><PhPlus :size="16"/> Add a User</button>
    </div>
  </main>
</template>

<style scoped>
.users-page{padding:32px clamp(18px,3vw,48px) 64px;max-width:1400px;margin:0 auto}
.page-header{display:flex;justify-content:space-between;align-items:center;gap:20px;margin-bottom:24px}
.page-header h2{margin:0 0 4px;font-size:clamp(24px,2.5vw,32px);letter-spacing:-.04em;font-weight:700}
.page-header p{margin:0;color:var(--muted);font-size:14px}
.header-actions{display:flex;gap:8px}
.error-banner{padding:14px 16px;border-left:3px solid var(--critical);border-radius:var(--radius-xs);background:var(--critical-soft);color:var(--critical);margin:0 0 16px}
.loading-grid{display:grid;grid-template-columns:repeat(auto-fill,minmax(400px,1fr));gap:14px}

.user-grid{display:grid;grid-template-columns:repeat(auto-fill,minmax(420px,1fr));gap:14px}
.user-card{display:flex;align-items:flex-start;gap:14px;padding:20px;border:1px solid var(--border);border-radius:var(--radius-lg);background:var(--surface);box-shadow:var(--shadow-sm);transition:transform .16s ease,box-shadow .16s ease}
.user-card:hover{transform:translateY(-1px);box-shadow:var(--shadow)}

.user-avatar{width:48px;height:48px;display:grid;place-items:center;border-radius:var(--radius);font:700 16px/1 var(--font-mono);flex:0 0 auto}
.user-avatar.owner{background:var(--accent-soft);color:var(--accent);border:1px solid color-mix(in srgb,var(--accent),transparent 75%)}
.user-avatar.manager{background:var(--info-soft);color:var(--info);border:1px solid color-mix(in srgb,var(--info),transparent 75%)}
.user-avatar.member{background:var(--surface-2);color:var(--muted);border:1px solid var(--border)}

.user-info{flex:1;min-width:0}
.user-title-row{display:flex;align-items:center;gap:8px;flex-wrap:wrap}
.user-title-row strong{font-size:14px;letter-spacing:-.01em}
.role-badge{display:inline-flex;align-items:center;gap:3px;padding:2px 8px;border-radius:99px;font:600 10px/1.4 var(--font-mono)}
.role-badge.owner{color:var(--accent);background:var(--accent-soft)}
.role-badge.manager{color:var(--info);background:var(--info-soft)}
.role-badge.member{color:var(--muted);background:var(--surface-2)}

.user-meta{display:flex;gap:10px;align-items:center;margin-top:6px;flex-wrap:wrap}
.user-email{color:var(--subtle);font-size:12px;font-family:var(--font-mono)}

.quota-bar{margin-top:10px;display:grid;gap:4px}
.quota-fill{height:4px;background:var(--accent);border-radius:2px;transition:width .3s ease}
.quota-bar small{color:var(--subtle);font-size:10px;font-family:var(--font-mono)}

.user-actions{display:flex;gap:6px;flex:0 0 auto;align-items:center}

.empty-state{display:grid;place-items:center;gap:14px;padding:64px 24px;text-align:center;border:1px dashed var(--border-strong);border-radius:var(--radius-lg)}
.empty-state svg{color:var(--faint)}
.empty-state h3{margin:0;font-size:18px}
.empty-state p{margin:0;color:var(--muted);font-size:13px;max-width:44ch;line-height:1.5}
.spinning{animation:spin .8s linear infinite}
@keyframes spin{to{transform:rotate(1turn)}}
</style>
