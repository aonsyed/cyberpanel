<script setup lang="ts">
import { computed, inject, onMounted, ref } from "vue";
import { PhArrowClockwise as ArrowClockwise, PhFire as Fire, PhShieldCheck as ShieldCheck, PhWarningCircle as WarningCircle } from "@phosphor-icons/vue";
import type { APIClient } from "../api";
import { firewallRuleRows, type FirewallRuleShape } from "../consoleLogic";
import { sessionStore } from "../store";

interface FirewallPolicyShape { id?: string; generation?: number; backend?: string; default_inbound?: string; default_outbound?: string; default_forward?: string; rules?: FirewallRuleShape[]; status?: { lifecycle?: string } }
interface WAFPolicyShape { id?: string; generation?: number; mode?: string; site_id?: string; ruleset?: string; status?: { lifecycle?: string } }
interface SSHPolicyShape { id?: string; generation?: number; password_authentication?: boolean; root_login?: string; port?: number; status?: { lifecycle?: string } }
interface SnapshotShape { firewall_policies?: FirewallPolicyShape[]; waf_policies?: WAFPolicyShape[]; ssh_policies?: SSHPolicyShape[]; observed_at?: string }

const api = inject<APIClient>("api")!;
const loading = ref(true);
const error = ref("");
const snapshot = ref<SnapshotShape>({});
const replaceAvailable = computed(() => api.available("operations.firewall.replace"));
const wafReplaceAvailable = computed(() => api.available("operations.waf.replace"));

const firewall = computed(() => { const first = snapshot.value.firewall_policies?.[0]; return first !== undefined && isRecord(first) ? first as unknown as FirewallPolicyShape & Record<string, unknown> : null; });
const rules = computed(() => firewallRuleRows((firewall.value?.rules ?? []) as FirewallRuleShape[]));
const wafPolicies = computed(() => (snapshot.value.waf_policies ?? []).filter(isRecord));
const sshPolicies = computed(() => (snapshot.value.ssh_policies ?? []).filter(isRecord));
const tenantID = computed(() => sessionStore.state.tenantId || undefined);

onMounted(() => void load());

async function load(): Promise<void> {
  loading.value = true; error.value = "";
  try {
    if (!api.available("operations.security.snapshot")) throw new Error("The security posture snapshot is not enabled on this node.");
    const response = await api.invoke<unknown>("operations.security.snapshot", { tenantId: tenantID.value, payload: {} });
    snapshot.value = isRecord(response.result) ? response.result as SnapshotShape : {};
  } catch (cause) { snapshot.value = {}; error.value = cause instanceof Error ? cause.message : "The security snapshot could not be loaded."; }
  finally { loading.value = false; }
}
function isRecord(value: unknown): value is Record<string, unknown> { return Boolean(value) && typeof value === "object" && !Array.isArray(value); }
function text(value: unknown, fallback = "—"): string { return value === undefined || value === null || value === "" ? fallback : String(value); }
function lifecycleOf(policy: (Record<string, unknown> & { status?: { lifecycle?: string } }) | null | undefined): string { return policy?.status?.lifecycle ?? "unknown"; }
</script>

<template>
  <main class="posture">
    <header class="page-head">
      <div>
        <p class="eyebrow">SECURITY / PERSISTED POSTURE</p>
        <h2>Firewall, WAF &amp; SSH</h2>
        <p>The durable desired state this node enforces. Every change below still flows through the guarded replace operations with their own approvals.</p>
      </div>
      <div class="head-actions">
        <button class="button button-small" type="button" :disabled="loading" @click="load"><ArrowClockwise :size="15" :class="{ spinning: loading }"/>Refresh</button>
      </div>
    </header>

    <p v-if="error" class="posture-error" role="alert"><WarningCircle :size="17"/>{{ error }}</p>
    <section v-if="loading" class="posture-loading" aria-busy="true"><span v-for="index in 6" :key="index" class="skeleton-row"><span class="skeleton"></span></span></section>

    <template v-else>
      <section class="posture-panel">
        <header>
          <div><p>NETWORK EDGE</p><h3><Fire :size="16"/> Firewall policy</h3></div>
          <div class="posture-meta mono">
            <span v-if="firewall">{{ text(firewall.backend) }} · GEN {{ text(firewall.generation) }} · <i :class="`status status-${lifecycleOf(firewall)}`">{{ lifecycleOf(firewall) }}</i></span>
            <span v-else>NO PERSISTED POLICY</span>
          </div>
        </header>
        <template v-if="firewall">
          <div class="posture-defaults">
            <article><small>Default inbound</small><strong :class="`tone-${firewall.default_inbound === 'allow' ? 'critical' : 'healthy'}`">{{ text(firewall.default_inbound) }}</strong></article>
            <article><small>Default outbound</small><strong>{{ text(firewall.default_outbound) }}</strong></article>
            <article><small>Default forward</small><strong>{{ text(firewall.default_forward) }}</strong></article>
          </div>
          <p v-if="!rules.length" class="posture-empty">No explicit rule is persisted; the default actions above decide all traffic.</p>
          <ul v-else class="rule-list">
            <li v-for="row in rules" :key="row.key">
              <span class="rule-action" :class="`rule-${String(row.rule.action ?? 'deny')}`">{{ text(row.rule.action, "deny") }}</span>
              <span class="rule-summary mono">{{ row.summary }}</span>
              <span v-if="row.rule.description" class="rule-note">{{ row.rule.description }}</span>
            </li>
          </ul>
        </template>
        <p v-else class="posture-empty">No firewall policy has been applied on this node yet. Apply one through the guarded replace operation to make the posture durable and observable here.</p>
      </section>

      <div class="posture-grid">
        <section class="posture-panel">
          <header><div><p>APPLICATION LAYER</p><h3><ShieldCheck :size="16"/> WAF policies</h3></div></header>
          <p v-if="!wafPolicies.length" class="posture-empty">No WAF policy is persisted{{ wafReplaceAvailable ? "" : " and the WAF capability is not installed" }}.</p>
          <ul v-else class="flat-list">
            <li v-for="(policy, index) in wafPolicies" :key="text(policy.id, String(index))">
              <strong>{{ text(policy.site_id, "node-wide") }}</strong>
              <span class="mono">GEN {{ text(String(policy.generation ?? "")) }} · {{ text(policy.mode ?? policy.ruleset, "configured") }} · <i :class="`status status-${lifecycleOf(policy as Record<string, unknown> & { status?: { lifecycle?: string } })}`">{{ lifecycleOf(policy as Record<string, unknown> & { status?: { lifecycle?: string } }) }}</i></span>
            </li>
          </ul>
        </section>
        <section class="posture-panel">
          <header><div><p>ACCESS</p><h3>SSH policy</h3></div></header>
          <p v-if="!sshPolicies.length" class="posture-empty">No SSH policy has been persisted on this node.</p>
          <ul v-else class="flat-list">
            <li v-for="(policy, index) in sshPolicies" :key="text(policy.id, String(index))">
              <strong :class="{ critical: policy.password_authentication }">{{ policy.password_authentication ? "Password authentication enabled" : "Key-only authentication" }}</strong>
              <span class="mono">PORT {{ text(policy.port === undefined || policy.port === null ? "" : String(policy.port), "22") }} · ROOT {{ text(policy.root_login, "prohibited") }} · <i :class="`status status-${lifecycleOf(policy as Record<string, unknown> & { status?: { lifecycle?: string } })}`">{{ lifecycleOf(policy as Record<string, unknown> & { status?: { lifecycle?: string } }) }}</i></span>
            </li>
          </ul>
        </section>
      </div>
      <p class="posture-note">Changes are applied through <span class="mono">operations.firewall.replace</span>, <span class="mono">operations.waf.replace</span> and <span class="mono">operations.ssh_policy.replace</span> with generation fencing and protected approvals. This view never mutates state.</p>
    </template>
  </main>
</template>

<style scoped>
.posture{padding:36px clamp(18px,3.2vw,52px) 64px;max-width:1700px;margin:0 auto}
.page-head{display:flex;justify-content:space-between;align-items:flex-end;gap:24px;margin:0 0 30px}
.page-head h2{margin:6px 0 8px;font-size:clamp(28px,3vw,40px);line-height:1;letter-spacing:-.048em;font-weight:750}
.page-head>div>p:last-child{margin:0;color:var(--muted);max-width:72ch}
.posture-error{display:flex;align-items:center;gap:8px;margin:0 0 15px;padding:12px 14px;border-left:3px solid var(--critical);border-radius:var(--radius-xs);background:var(--critical-soft);color:var(--critical)}
.posture-loading{border:1px solid var(--border);border-radius:var(--radius-lg);background:var(--surface);box-shadow:var(--shadow-sm);overflow:hidden}
.posture-panel{border:1px solid var(--border);border-radius:var(--radius-lg);background:var(--surface);margin-bottom:16px;min-width:0;box-shadow:var(--shadow-sm)}
.posture-panel>header{min-height:60px;padding:13px 18px;border-bottom:1px solid var(--border);display:flex;align-items:center;justify-content:space-between;gap:14px}
.posture-panel header p{margin:0 0 5px;color:var(--subtle);font:600 9px/1 var(--font-mono);letter-spacing:.13em}
.posture-panel h3{margin:0;font-size:15px;font-weight:650;letter-spacing:-.02em;display:flex;align-items:center;gap:7px}
.posture-meta{font-size:10px;color:var(--subtle);text-align:right}
.posture-defaults{display:grid;grid-template-columns:repeat(3,1fr);border-bottom:1px solid var(--border)}
.posture-defaults article{padding:14px 18px;border-right:1px solid var(--border);display:grid;gap:6px}
.posture-defaults article:last-child{border-right:0}
.posture-defaults small{color:var(--subtle);font-size:9px;text-transform:uppercase;letter-spacing:.1em;font-weight:600}
.posture-defaults strong{font:600 13px/1 var(--font-mono);text-transform:uppercase}
.tone-healthy{color:var(--healthy)}.tone-critical{color:var(--critical)}
.rule-list{list-style:none;margin:0;padding:6px 0}
.rule-list li{display:flex;align-items:center;gap:12px;padding:10px 18px;border-bottom:1px solid var(--border);transition:background .1s ease}
.rule-list li:hover{background:var(--surface-2)}
.rule-list li:last-child{border-bottom:0}
.rule-action{min-width:54px;text-align:center;font:700 10px/1 var(--font-mono);letter-spacing:.08em;padding:5px 0;border-radius:var(--radius-xs)}
.rule-allow{color:var(--healthy);background:var(--healthy-soft);border:1px solid color-mix(in srgb,var(--healthy),transparent 78%)}
.rule-deny,.rule-reject,.rule-drop{color:var(--critical);background:var(--critical-soft);border:1px solid color-mix(in srgb,var(--critical),transparent 78%)}
.rule-summary{font-size:11px;color:var(--text)}
.rule-note{margin-left:auto;color:var(--subtle);font-size:10px;max-width:40%;overflow:hidden;text-overflow:ellipsis;white-space:nowrap}
.posture-grid{display:grid;grid-template-columns:1fr 1fr;gap:16px}
.flat-list{list-style:none;margin:0;padding:4px 0}
.flat-list li{display:grid;gap:6px;padding:12px 18px;border-bottom:1px solid var(--border);transition:background .1s ease}
.flat-list li:hover{background:var(--surface-2)}
.flat-list li:last-child{border-bottom:0}
.flat-list strong{font-size:12px}
.flat-list span{font-size:10px;color:var(--subtle)}
.posture-empty{margin:0;padding:22px 18px;color:var(--subtle);font-size:12px;line-height:1.5}
.posture-note{margin:6px 0 0;color:var(--subtle);font-size:11px}
.posture-note .mono{color:var(--muted)}
.spinning{animation:spin .8s linear infinite}@keyframes spin{to{transform:rotate(1turn)}}
@media(max-width:900px){.posture-grid{grid-template-columns:1fr}.posture-defaults{grid-template-columns:1fr}.posture-defaults article{border-right:0;border-bottom:1px solid var(--border)}}
</style>

