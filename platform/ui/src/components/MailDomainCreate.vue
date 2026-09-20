<script setup lang="ts">
import {inject, ref} from "vue";
import type {APIClient} from "../api";

const props=defineProps<{tenantId?:string|undefined}>();
const emit=defineEmits<{close:[];complete:[unknown]}>();
const api=inject<APIClient>("api")!;
const name=ref("");
const quota=ref(1024);
const busy=ref(false);
const failure=ref("");
const invalidSaved=ref(false);
type Attempt={tenant:string;name:string;quota:number;domainID:string;policyID:string;policyDone:boolean};
const storageKey=`panel.mail-domain-create.${props.tenantId||""}`;
const attempt=ref<Attempt|null>(null);
try {
  const saved=sessionStorage.getItem(storageKey);
  if(saved){const value=JSON.parse(saved) as Attempt;if(value.tenant===props.tenantId&&typeof value.name==="string"&&Number.isSafeInteger(value.quota)&&value.quota>0&&value.quota<=1048576&&typeof value.policyDone==="boolean"&&/^maildomain_[a-f0-9]{32}$/.test(value.domainID)&&/^mailpolicy_[a-f0-9]{32}$/.test(value.policyID)){attempt.value=value;name.value=value.name;quota.value=value.quota}else{throw new Error("invalid saved operation")}}
} catch {invalidSaved.value=true;failure.value="The saved operation could not be read. Do not resubmit until its state is checked."}
function save():void{sessionStorage.setItem(storageKey,JSON.stringify(attempt.value))}
async function submit():Promise<void>{
  if(busy.value||invalidSaved.value)return;
  failure.value="";
  if(!props.tenantId){failure.value="Select a tenant first.";return}
  const hostname=name.value.trim().toLowerCase().replace(/\.$/,"");
  if(!/^(?=.{1,253}$)(?:[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?\.)+[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?$/.test(hostname)||!Number.isSafeInteger(quota.value)||quota.value<1||quota.value>1048576){failure.value="Enter a valid domain and mailbox limit from 1 to 1048576 MiB.";return}
  busy.value=true;
  try{
    if(!attempt.value){const suffix=crypto.randomUUID().replaceAll("-","");attempt.value={tenant:props.tenantId,name:hostname,quota:quota.value,domainID:`maildomain_${suffix}`,policyID:`mailpolicy_${suffix}`,policyDone:false};save()}
    const current=attempt.value;
    if(!current.policyDone){
      await api.invoke("mail.policy.create",{tenantId:current.tenant,resourceId:current.policyID,idempotencyKey:`create_${current.policyID}`,payload:{policy:{id:current.policyID,max_mailbox_bytes:current.quota*1048576,max_recipients:100,spam_threshold:6,retain_days:30,log:{retain_days:30,redact_bodies:true,audit_deliveries:true}}}});
      current.policyDone=true;save();
    }
    const response=await api.invoke("mail.domain.create",{tenantId:current.tenant,resourceId:current.domainID,idempotencyKey:`create_${current.domainID}`,payload:{domain:{id:current.domainID,name:current.name,tenant:current.tenant,policy:current.policyID,dkim:{enabled:false},relay:{}}}});
    sessionStorage.removeItem(storageKey);
    emit("complete",response.result);
    emit("close");
  }catch(error){failure.value=error instanceof Error?error.message:"Mail domain creation failed."}finally{busy.value=false}
}
</script>

<template>
  <div class="mail-layer"><aside role="dialog" aria-modal="true" aria-label="Add mail domain">
    <header><h2>Add mail domain</h2><button type="button" :disabled="busy" aria-label="Close" @click="emit('close')">Close</button></header>
    <form @submit.prevent="submit">
      <p>Create a mail domain and its mailbox policy for the selected tenant. DNS records and DKIM activation are separate steps.</p>
      <label for="mail-domain-name">Domain</label><input id="mail-domain-name" v-model="name" required :disabled="busy||!!attempt" autocomplete="off" placeholder="example.com"/>
      <label for="mail-domain-quota">Maximum mailbox size (MiB)</label><input id="mail-domain-quota" v-model.number="quota" type="number" min="1" max="1048576" required :disabled="busy||!!attempt"/>
      <p v-if="attempt">An operation is recorded for {{attempt.name}}. Retry continues the same domain and policy; it does not create replacements.</p>
      <p v-if="failure" role="alert">{{failure}}</p>
      <button class="button button-primary" type="submit" :disabled="busy||invalidSaved">{{busy?'Creating…':attempt?'Retry creation':'Add mail domain'}}</button>
    </form>
  </aside></div>
</template>

<style scoped>
.mail-layer{position:fixed;inset:0;z-index:60;background:#0008;display:flex;justify-content:flex-end}.mail-layer aside{width:min(100%,520px);height:100%;overflow:auto;background:var(--surface);padding:24px;border-left:1px solid var(--border)}header{display:flex;align-items:center;justify-content:space-between;gap:12px}h2{font-size:22px}form{display:grid;gap:16px}p{color:var(--muted);line-height:1.5}input{padding:12px;background:var(--surface);color:var(--text);border:1px solid var(--border);width:100%;box-sizing:border-box}label{font-weight:600}p[role=alert]{color:var(--critical)}
</style>
