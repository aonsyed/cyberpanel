<script setup lang="ts">
import { computed, inject, onBeforeUnmount, onMounted, reactive, ref, watch } from "vue";
import { ArrowClockwise, ArrowRight, CheckCircle, ShieldWarning, X } from "@phosphor-icons/vue";
import { oneTimeToken, type APIClient } from "../api";
import type { ActionDefinition } from "../domain";
import { sessionStore } from "../store";

const props=defineProps<{action:ActionDefinition;tenantId?:string;resource?:Record<string,unknown>|null;expectedGeneration?:number}>();
const emit=defineEmits<{close:[];complete:[unknown]}>();
const api=inject<APIClient>("api")!;
const values=reactive<Record<string,unknown>>({});
const errors=reactive<Record<string,string>>({});
const confirmation=ref(false);
const submitting=ref(false);
const failure=ref("");
const result=ref<unknown>(null);
const completed=ref(false);
const title=computed(()=>props.resource?`${props.action.label} · ${String(props.resource.name||props.resource.primary_hostname||props.resource.domain||props.resource.id||"")}`:props.action.label);
const resultText=computed(()=>result.value===null?"":JSON.stringify(redact(result.value),null,2));

watch([()=>props.action,()=>props.resource],()=>{initialize();if(!props.action.mutating)queueMicrotask(()=>void submit())},{immediate:true});
function initialize():void{Object.keys(values).forEach((key)=>delete values[key]);props.action.fields?.forEach((field)=>values[field.key]=field.defaultValue??(field.type==="boolean"?false:""));confirmation.value=!props.action.confirmation;failure.value="";result.value=null;completed.value=false}
function validate():boolean{
  Object.keys(errors).forEach((key)=>delete errors[key]);
  for(const field of props.action.fields||[]){
    const value=values[field.key];
    if(field.required&&(value===undefined||value===null||String(value).trim()==="")){errors[field.key]="This value is required.";continue}
    if(value&&field.type==="email"&&!/^[^\s@]+@[^\s@]+\.[^\s@]+$/.test(String(value)))errors[field.key]="Enter a valid email address.";
    if(value&&field.type==="hostname"&&!/^(?=.{1,253}$)(?:[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?\.)+[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?$/i.test(String(value)))errors[field.key]="Enter a valid DNS hostname.";
    if(value&&field.type==="cidr"&&!/^([0-9a-f:.]+)\/(?:[0-9]|[1-9][0-9]|1[01][0-9]|12[0-8])$/i.test(String(value)))errors[field.key]="Enter a canonical IPv4 or IPv6 prefix.";
    if(String(value??"").trim()&&field.type==="json")try{JSON.parse(String(value))}catch{errors[field.key]="Enter valid JSON."}
  }
  return Object.keys(errors).length===0;
}
function actionPayload():Record<string,unknown>{
  const payload:Record<string,unknown>={};
  for(const field of props.action.fields||[]){
    const value=values[field.key];
    if(field.type==="json"){
      if(String(value??"").trim()!=="")payload[field.key]=JSON.parse(String(value));
    }else payload[field.key]=value;
  }
  return payload;
}
async function submit():Promise<void>{
  if(!validate()||(props.action.mutating&&!confirmation.value))return;
  submitting.value=true;failure.value="";
  try{
    const resourceID=props.resource?String(props.resource.id||props.resource.resource_id||props.resource.site_id||""):undefined;
    const explicitGeneration=Number(props.expectedGeneration||0);
    const resourceGeneration=Number(props.action.generationField==="revision"?(props.resource?.revision||0):(props.resource?.generation||0));
    const generation=props.action.mutating?(explicitGeneration||resourceGeneration||undefined):undefined;
    if(props.action.operation==="container.exec.issue"){
      const token=oneTimeToken();
      const argumentsValue=String(values.arguments||"").split("\n").map((value)=>value.trim()).filter(Boolean);
      const issued=await api.invoke<Record<string,unknown>>(props.action.operation,{tenantId:props.tenantId,resourceId:resourceID,expectedGeneration:generation,payload:{command_id:values.command_id,arguments:argumentsValue,ttl_seconds:Number(values.ttl_seconds)||60,token}});
      const grantID=String(issued.result.id||"");
      if(!grantID)throw new Error("The node did not return a valid one-time exec grant.");
      const exchanged=await api.exchangeContainerExec<unknown>(grantID,token);result.value=exchanged.result;
    }else{
      const response=await api.invoke<unknown>(props.action.operation,{tenantId:props.tenantId,resourceId:resourceID,expectedGeneration:generation,payload:actionPayload()});result.value=response.result;
    }
    completed.value=true;
    if(props.action.mutating){sessionStore.notify({tone:"healthy",title:`${props.action.label} accepted`,body:"The durable operation was admitted and will continue if this browser disconnects."});emit("complete",result.value)}
  }catch(error){failure.value=error instanceof Error?error.message:"The operation could not be admitted."}finally{submitting.value=false}
}
function redact(value:unknown,key=""):unknown{if(/password|secret|token|credential|private[_-]?key|authorization/i.test(key))return"[REDACTED]";if(Array.isArray(value))return value.map((item)=>redact(item));if(value&&typeof value==="object")return Object.fromEntries(Object.entries(value as Record<string,unknown>).map(([entryKey,entryValue])=>[entryKey,redact(entryValue,entryKey)]));return value}
function keydown(event:KeyboardEvent):void{if(event.key==="Escape")emit("close")}
onMounted(()=>window.addEventListener("keydown",keydown));onBeforeUnmount(()=>window.removeEventListener("keydown",keydown));
</script>

<template>
  <div class="drawer-layer" role="presentation" @mousedown.self="emit('close')">
    <aside class="drawer" role="dialog" aria-modal="true" :aria-label="title">
      <header><div><p>{{action.mutating?'DURABLE OPERATION':'RESOURCE PROJECTION'}}</p><h2>{{title}}</h2></div><button class="icon-button" type="button" aria-label="Close" @click="emit('close')"><X :size="18"/></button></header>
      <form @submit.prevent="submit">
        <div class="drawer-body">
          <div v-for="field in action.fields||[]" :key="field.key" class="field">
            <label :for="`field-${field.key}`">{{field.label}}</label>
            <select v-if="field.type==='select'" :id="`field-${field.key}`" v-model="values[field.key]" class="select" :required="field.required"><option value="" disabled>Select…</option><option v-for="option in field.options" :key="option.value" :value="option.value">{{option.label}}</option></select>
            <textarea v-else-if="field.type==='textarea'||field.type==='json'" :id="`field-${field.key}`" v-model="values[field.key]" class="textarea" :class="{mono:field.type==='json'}" :required="field.required"></textarea>
            <label v-else-if="field.type==='boolean'" class="checkbox"><input :id="`field-${field.key}`" v-model="values[field.key]" type="checkbox"/><span>Enabled</span></label>
            <input v-else :id="`field-${field.key}`" v-model="values[field.key]" class="input" :class="{mono:field.type==='cidr'||field.type==='cron'}" :type="field.type==='password'?'password':field.type==='number'?'number':field.type==='email'?'email':'text'" :required="field.required"/>
            <p v-if="field.helper" class="field-help">{{field.helper}}</p><p v-if="errors[field.key]" class="field-error">{{errors[field.key]}}</p>
          </div>
          <div v-if="action.confirmation&&!completed" class="confirmation" :class="`confirmation-${action.tone||'warning'}`"><ShieldWarning :size="22" weight="fill"/><div><strong>Confirm impact</strong><p>{{action.confirmation}}</p><label class="checkbox"><input v-model="confirmation" type="checkbox"/><span>I understand this change and its rollback boundary.</span></label></div></div>
          <div v-if="submitting&&!action.mutating" class="loading-result"><ArrowClockwise :size="20"/><span>Loading the current projection…</span></div>
          <div v-if="failure" class="operation-error" role="alert">{{failure}}</div>
          <section v-if="completed" class="result-panel" aria-live="polite"><header><CheckCircle :size="18" weight="fill"/><strong>{{action.mutating?'Operation admitted':'Current projection'}}</strong></header><pre v-if="resultText">{{resultText}}</pre><p v-else>The operation returned no response body.</p></section>
        </div>
        <footer>
          <button class="button" type="button" @click="emit('close')">{{completed?'Close':'Cancel'}}</button>
          <button v-if="!completed||!action.mutating" class="button" :class="action.tone==='critical'?'button-danger':'button-primary'" type="submit" :disabled="submitting||(action.mutating&&!confirmation)"><span>{{submitting?'Working…':action.mutating?action.label:completed?'Refresh':'Load details'}}</span><ArrowClockwise v-if="completed&&!action.mutating" :size="15"/><ArrowRight v-else-if="!submitting" :size="16"/></button>
        </footer>
      </form>
    </aside>
  </div>
</template>

<style scoped>
.drawer-layer{position:fixed;z-index:80;inset:0;background:rgba(0,5,8,.62);backdrop-filter:blur(3px);display:flex;justify-content:flex-end}.drawer{width:min(560px,100vw);height:100%;background:var(--surface);border-left:1px solid var(--border-strong);box-shadow:var(--shadow);display:flex;flex-direction:column}.drawer>header{min-height:76px;padding:17px 20px;border-bottom:1px solid var(--border);display:flex;justify-content:space-between;align-items:center}.drawer>header p{margin:0 0 7px;color:var(--accent);font:9px/1 "Panel Mono",monospace;letter-spacing:.13em}.drawer h2{margin:0;font-size:19px;letter-spacing:-.025em}.drawer form{display:flex;flex-direction:column;min-height:0;flex:1}.drawer-body{padding:22px;display:grid;gap:20px;overflow:auto;flex:1}.confirmation{display:grid;grid-template-columns:auto 1fr;gap:12px;border:1px solid color-mix(in srgb,var(--warning),transparent 55%);background:color-mix(in srgb,var(--warning),transparent 91%);padding:14px;border-radius:var(--radius)}.confirmation>svg{color:var(--warning)}.confirmation-critical{border-color:color-mix(in srgb,var(--critical),transparent 55%);background:color-mix(in srgb,var(--critical),transparent 91%)}.confirmation-critical>svg{color:var(--critical)}.confirmation strong{font-size:13px}.confirmation p{margin:5px 0 10px;color:var(--muted);font-size:12px}.confirmation .checkbox{min-height:24px;font-size:12px}.operation-error{padding:12px;border-left:3px solid var(--critical);background:color-mix(in srgb,var(--critical),transparent 91%);color:var(--critical);font-size:12px}.loading-result{min-height:120px;display:flex;justify-content:center;align-items:center;gap:10px;color:var(--muted)}.loading-result svg{animation:spin .8s linear infinite}.result-panel{border:1px solid var(--border);border-radius:var(--radius);overflow:hidden}.result-panel>header{height:43px;padding:0 12px;display:flex;align-items:center;gap:8px;background:var(--bg-raised);border-bottom:1px solid var(--border);color:var(--healthy)}.result-panel>header strong{font-size:12px;color:var(--text)}.result-panel pre{max-height:54vh;overflow:auto;margin:0;padding:15px;background:var(--bg);color:var(--muted);font:11px/1.65 "Panel Mono",monospace;white-space:pre-wrap;word-break:break-word}.result-panel>p{margin:0;padding:18px;color:var(--muted)}footer{min-height:67px;padding:13px 20px;border-top:1px solid var(--border);display:flex;justify-content:flex-end;align-items:center;gap:9px;background:var(--bg-raised)}footer .button:last-child{min-width:130px}@keyframes spin{to{transform:rotate(1turn)}}
</style>
