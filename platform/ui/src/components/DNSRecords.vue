<script setup lang="ts">
import {inject, onMounted, ref} from "vue";
import type {APIClient} from "../api";

const props=defineProps<{tenantId?:string|undefined;resource:Record<string,unknown>}>();
const emit=defineEmits<{close:[];complete:[unknown]}>();
const api=inject<APIClient>("api")!;
type RecordSet={owner:string;kind:string;ttl:number;records:string[]};
type Editable={key:number;name:string;type:string;ttl:number;values:string};
const rows=ref<Editable[]>([]);
const busy=ref(false);
const loaded=ref(false);
const failure=ref("");
const confirmed=ref(false);
const generation=ref(Number(props.resource.generation));
const attempt=ref<{key:string;payload:string}|null>(null);
let nextKey=0;
const kinds=["A","AAAA","CNAME","TXT","MX","NS","SRV","PTR","CAA","NAPTR","TLSA","SSHFP"];
onMounted(()=>void load());

async function load():Promise<void>{
  busy.value=true;loaded.value=false;failure.value="";
  try{
    const all:Editable[]=[];let cursor="";
    do{
      const response=await api.invoke<{items:RecordSet[];next_cursor?:string}>("dns.recordset.list",{tenantId:props.tenantId,resourceId:String(props.resource.id),payload:{limit:1000,cursor:cursor||undefined}});
      for(const set of response.result.items||[]){
        if(set.kind!=="SOA"&&!kinds.includes(set.kind))throw new Error(`This zone contains ${set.kind} records that this editor cannot replace. No changes were made.`);
        if(set.kind!=="SOA")all.push({key:nextKey++,name:set.owner,type:set.kind,ttl:set.ttl,values:set.records.join("\n")});
      }
      cursor=response.result.next_cursor||"";
      if(all.length>10000)throw new Error("This zone is too large for the record editor.");
    }while(cursor);
    rows.value=all;loaded.value=true;
  }catch(error){failure.value=error instanceof Error?error.message:"Records could not be loaded."}
  finally{busy.value=false}
}

function add():void{rows.value.push({key:nextKey++,name:"@",type:"A",ttl:300,values:""});confirmed.value=false}
async function save():Promise<void>{
  if(busy.value||!loaded.value||!confirmed.value)return;
  failure.value="";
  const record_sets=rows.value.map(row=>({name:row.name.trim(),type:row.type,ttl:row.ttl,values:row.values.split("\n").map(value=>value.trim()).filter(Boolean)}));
  if(record_sets.some(set=>!set.name||!Number.isInteger(set.ttl)||set.ttl<30||set.ttl>604800||!set.values.length)){
    failure.value="Every record set needs an owner, a TTL from 30 to 604800 seconds, and at least one value.";return;
  }
  const payload={record_sets,replace:true};
  const serialized=JSON.stringify(payload);
  if(attempt.value&&attempt.value.payload!==serialized){failure.value="A previous save has an uncertain outcome. Close and reopen the editor before changing it.";return}
  if(!attempt.value)attempt.value={key:`dns_${crypto.randomUUID().replaceAll("-","")}`,payload:serialized};
  busy.value=true;
  try{
    const response=await api.invoke("dns.zone.import",{tenantId:props.tenantId,resourceId:String(props.resource.id),expectedGeneration:generation.value,idempotencyKey:attempt.value.key,payload});
    emit("complete",response.result);emit("close");
  }catch(error){failure.value=error instanceof Error?error.message:"Records could not be saved."}
  finally{busy.value=false}
}
</script>

<template>
  <div class="dns-layer"><aside role="dialog" aria-modal="true" aria-label="DNS records">
    <header><h2>Records · {{resource.name}}</h2><button class="button" type="button" :disabled="busy" aria-label="Close" @click="emit('close')">Close</button></header>
    <p>Edit the complete set of records in this zone. Use @ for its apex or a fully qualified owner name. The managed SOA, transfer settings, and DNSSEC keys are preserved.</p>
    <p v-if="resource.mode==='secondary'">Secondary records are maintained by zone transfers and cannot be edited here.</p>
    <form v-else @submit.prevent="save">
      <fieldset v-for="(row,index) in rows" :key="row.key" :disabled="busy||!!attempt">
        <legend>Record set {{index+1}}</legend>
        <label :for="`dns-name-${row.key}`">Owner</label><input :id="`dns-name-${row.key}`" v-model="row.name" required @input="confirmed=false"/>
        <label :for="`dns-type-${row.key}`">Type</label><select :id="`dns-type-${row.key}`" v-model="row.type" @change="confirmed=false"><option v-for="kind in kinds" :key="kind">{{kind}}</option></select>
        <label :for="`dns-ttl-${row.key}`">TTL (seconds)</label><input :id="`dns-ttl-${row.key}`" v-model.number="row.ttl" type="number" min="30" max="604800" required @input="confirmed=false"/>
        <label :for="`dns-values-${row.key}`">Values (one per line)</label><textarea :id="`dns-values-${row.key}`" v-model="row.values" required @input="confirmed=false"></textarea>
        <button class="button" type="button" @click="rows.splice(index,1);confirmed=false">Remove record set {{index+1}}</button>
      </fieldset>
      <p v-if="loaded&&!rows.length">No editable records. Saving this empty list removes all non-SOA records.</p>
      <button class="button" type="button" :disabled="busy||!loaded||!!attempt" @click="add">Add record set</button>
      <label class="confirmation"><input v-model="confirmed" type="checkbox" :disabled="busy"/>Replace this zone’s editable records with the list above.</label>
      <p v-if="failure" role="alert">{{failure}}</p>
      <button class="button button-primary" type="submit" :disabled="busy||!loaded||!confirmed||!api.available('dns.zone.import')">{{busy?'Working…':attempt?'Retry save':'Save records'}}</button>
    </form>
    <p v-if="failure&&resource.mode==='secondary'" role="alert">{{failure}}</p>
  </aside></div>
</template>

<style scoped>
.dns-layer{position:fixed;inset:0;z-index:80;background:#0008;display:flex;justify-content:flex-end}.dns-layer aside{width:min(100%,620px);height:100%;overflow:auto;background:var(--surface);padding:24px;box-sizing:border-box;border-left:1px solid var(--border)}header{display:flex;align-items:center;justify-content:space-between;gap:12px}h2{font-size:20px;overflow-wrap:anywhere}form,fieldset{display:grid;gap:12px}fieldset{min-width:0;padding:16px;border:1px solid var(--border)}p{color:var(--muted);line-height:1.5}input,select,textarea{padding:10px;background:var(--surface);color:var(--text);border:1px solid var(--border);width:100%;box-sizing:border-box}textarea{min-height:80px}label{font-weight:600}.confirmation{display:flex;gap:10px;align-items:flex-start;margin:14px 0}.confirmation input{width:auto}p[role=alert]{color:var(--critical)}
</style>
