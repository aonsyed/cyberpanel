<script setup lang="ts">
import {inject, ref} from "vue";
import type {APIClient} from "../api";

const props=defineProps<{tenantId?:string|undefined;resource:Record<string,unknown>}>();
const emit=defineEmits<{close:[];complete:[unknown]}>();
const api=inject<APIClient>("api")!;
const local=ref("");const siteID=ref("");const quota=ref(1024);const password=ref("");
const busy=ref(false);const failure=ref("");const invalidSaved=ref(false);
type Attempt={tenant:string;domain:string;id:string;local:string;site:string;quota:number;created:boolean;credential:string};
const domain=String(props.resource.id||"");const storageKey=`panel.mailbox-create.${props.tenantId||""}.${domain}`;
const attempt=ref<Attempt|null>(null);
try{
 const saved=sessionStorage.getItem(storageKey);
 if(saved){const value=JSON.parse(saved) as Attempt;if(value.tenant!==props.tenantId||value.domain!==domain||!/^mailbox_[a-f0-9]{32}$/.test(value.id)||typeof value.local!=="string"||typeof value.site!=="string"||!Number.isSafeInteger(value.quota)||value.quota<1||value.quota>1048576||typeof value.created!=="boolean"||typeof value.credential!=="string")throw Error("invalid saved operation");attempt.value=value;local.value=value.local;siteID.value=value.site;quota.value=value.quota}
}catch{invalidSaved.value=true;failure.value="The saved mailbox operation cannot be read. Check its state before resubmitting."}
function save():void{sessionStorage.setItem(storageKey,JSON.stringify(attempt.value))}
async function submit():Promise<void>{
 if(busy.value||invalidSaved.value)return;failure.value="";
 if(!props.tenantId||!domain){failure.value="Select a tenant-owned mail domain.";return}
 if(!api.available("mail.mailbox.password.enroll")){failure.value="Mailbox password enrollment is not available on this node.";return}
 if(!/^[a-z0-9.!#$%&'*+\-=?^_`{|}~]{1,64}$/i.test(local.value)||local.value.startsWith(".")||local.value.endsWith(".")||local.value.includes("..")||!siteID.value.trim()||!Number.isSafeInteger(quota.value)||quota.value<1||quota.value>1048576){failure.value="Enter a valid mailbox name, owning site and mailbox limit.";return}
 if(!attempt.value?.credential&&(new TextEncoder().encode(password.value).length<12||new TextEncoder().encode(password.value).length>1024||password.value.includes("\0"))){failure.value="Use a password of 12 to 1024 bytes without NUL.";return}
 busy.value=true;
 try{
  if(!attempt.value){attempt.value={tenant:props.tenantId,domain,id:`mailbox_${crypto.randomUUID().replaceAll("-","")}`,local:local.value.toLowerCase(),site:siteID.value.trim(),quota:quota.value,created:false,credential:""};save()}
  const current=attempt.value;
  const mailbox={id:current.id,domain:current.domain,site_id:current.site,local:current.local,quota_bytes:current.quota*1048576,enabled:false};
  if(!current.created){
   const response=await api.invoke<{status:string}>("mail.mailbox.create",{tenantId:current.tenant,resourceId:current.id,idempotencyKey:`create_${current.id}`,payload:{mailbox}});
   if(response.result.status!=="applied")throw Error("Mailbox creation is not confirmed. Retry the recorded operation.");current.created=true;save();
  }
  if(!current.credential){
   const enrolled=await api.invoke<{id:string}>("mail.mailbox.password.enroll",{tenantId:current.tenant,resourceId:current.id,expectedGeneration:1,idempotencyKey:`password_${current.id}`,payload:{password:password.value}});
   if(!enrolled.result.id)throw Error("No mailbox credential reference returned.");current.credential=enrolled.result.id;save();
  }
  const response=await api.invoke<{status:string}>("mail.mailbox.update",{tenantId:current.tenant,resourceId:current.id,expectedGeneration:1,idempotencyKey:`activate_${current.id}`,payload:{mailbox:{...mailbox,enabled:true,credential_ref:current.credential}}});
  if(response.result.status!=="applied")throw Error("Mailbox activation is not confirmed. Retry the recorded operation.");
  sessionStorage.removeItem(storageKey);emit("complete",response.result);emit("close");
 }catch(error){failure.value=error instanceof Error?error.message:"Mailbox provisioning failed."}finally{password.value="";busy.value=false}
}
</script>

<template>
 <div class="mailbox-layer"><aside role="dialog" aria-modal="true" aria-label="Add mailbox">
  <header><h2>Add mailbox</h2><button type="button" :disabled="busy" aria-label="Close" @click="password='';emit('close')">Close</button></header>
  <form @submit.prevent="submit">
   <p>The mailbox uses the selected site's Unix owner. Its password is enrolled write-only; activation follows confirmed credential enrollment.</p>
   <label for="mailbox-local">Mailbox name</label><input id="mailbox-local" v-model="local" required :disabled="busy||!!attempt" autocomplete="off"/>
   <label for="mailbox-site">Owning site</label><input id="mailbox-site" v-model="siteID" required :disabled="busy||!!attempt"/>
   <label for="mailbox-quota">Mailbox size (MiB)</label><input id="mailbox-quota" v-model.number="quota" type="number" min="1" max="1048576" required :disabled="busy||!!attempt"/>
   <template v-if="!attempt?.credential"><label for="mailbox-password">Mailbox password</label><input id="mailbox-password" v-model="password" type="password" autocomplete="new-password" required :disabled="busy"/></template>
   <p v-if="attempt">Retry continues mailbox {{attempt.local}} with the same operation IDs. If prompted, enter the same password.</p>
   <p v-if="failure" role="alert">{{failure}}</p>
   <button type="submit" class="button button-primary" :disabled="busy||invalidSaved">{{busy?'Provisioning…':attempt?'Retry provisioning':'Add mailbox'}}</button>
  </form>
 </aside></div>
</template>

<style scoped>
.mailbox-layer{position:fixed;inset:0;z-index:60;background:#0008;display:flex;justify-content:flex-end}.mailbox-layer aside{width:min(100%,520px);height:100%;overflow:auto;background:var(--surface);padding:24px;border-left:1px solid var(--border)}header{display:flex;align-items:center;justify-content:space-between;gap:12px}h2{font-size:22px}form{display:grid;gap:14px}p{color:var(--muted);line-height:1.5}input{padding:12px;background:var(--surface);color:var(--text);border:1px solid var(--border);width:100%;box-sizing:border-box}label{font-weight:600}p[role=alert]{color:var(--critical)}
</style>
