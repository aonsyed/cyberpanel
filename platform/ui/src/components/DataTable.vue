<script setup lang="ts">
import { computed } from "vue";
import { PhDotsThree as DotsThree, PhSortAscending as SortAscending } from "@phosphor-icons/vue";
import type { ActionDefinition, ColumnDefinition } from "../domain";

const props=defineProps<{columns:ColumnDefinition[];rows:Record<string,unknown>[];actions?:ActionDefinition[];selected?:string}>();
const emit=defineEmits<{action:[ActionDefinition,Record<string,unknown>];select:[Record<string,unknown>];sort:[string]}>();
const dateFormatter=new Intl.DateTimeFormat(undefined,{dateStyle:"medium",timeStyle:"short"});const numberFormatter=new Intl.NumberFormat();
function value(row:Record<string,unknown>,key:string):unknown{return key.split(".").reduce<unknown>((current,part)=>current&&typeof current==="object"?(current as Record<string,unknown>)[part]:undefined,row)}
function format(raw:unknown,column:ColumnDefinition):string{if(raw===undefined||raw===null||raw==="")return "—";switch(column.format){case"bytes":return bytes(Number(raw));case"number":return numberFormatter.format(Number(raw));case"date":{const date=new Date(String(raw));return Number.isNaN(date.valueOf())?"—":dateFormatter.format(date)}case"duration":return duration(Number(raw));case"hostname":return String(raw).toLowerCase();default:return Array.isArray(raw)?raw.join(", "):String(raw)}}
function bytes(value:number):string{if(!Number.isFinite(value))return"—";const units=["B","KiB","MiB","GiB","TiB","PiB"];let index=0;while(Math.abs(value)>=1024&&index<units.length-1){value/=1024;index++}return`${value>=10||index===0?value.toFixed(0):value.toFixed(1)} ${units[index]}`}
function duration(value:number):string{if(!Number.isFinite(value))return"—";if(value<60)return`${Math.round(value)}s`;if(value<3600)return`${Math.round(value/60)}m`;if(value<86400)return`${Math.round(value/3600)}h`;return`${Math.round(value/86400)}d`}
function statusClass(raw:unknown):string{return`status-${String(raw||"neutral").toLowerCase().replace(/[^a-z0-9_-]/g,"")}`}
function actionsFor(row:Record<string,unknown>):ActionDefinition[]{return(props.actions||[]).filter((action)=>(!action.resourceTypes?.length||action.resourceTypes.includes(String(row.type||"")))&&(!action.resourceStates?.length||action.resourceStates.includes(String(row.state||""))))}
const hasActions=computed(()=>Boolean(props.actions?.length));
</script>

<template>
  <div class="table-wrap">
    <table><thead><tr><th v-for="column in columns" :key="column.key" :style="{width:column.width}"><button type="button" @click="emit('sort',column.key)">{{column.label}}<SortAscending :size="12"/></button></th><th v-if="hasActions" class="actions-column"><span class="sr-only">Actions</span></th></tr></thead>
      <tbody><tr v-for="(row,index) in rows" :key="String(row.id||row.resource_id||index)" :class="{selected:selected===String(row.id||row.resource_id||'')}" @dblclick="emit('select',row)">
        <td v-for="column in columns" :key="column.key"><span v-if="column.format==='status'" class="status" :class="statusClass(value(row,column.key))">{{format(value(row,column.key),column)}}</span><span v-else :class="{mono:column.format==='bytes'||column.format==='number'}">{{format(value(row,column.key),column)}}</span></td>
        <td v-if="hasActions" class="row-actions"><details><summary aria-label="Resource actions"><DotsThree :size="19" weight="bold"/></summary><div><button v-for="action in actionsFor(row)" :key="action.id" type="button" :class="{critical:action.tone==='critical'}" @click="emit('action',action,row)">{{action.label}}</button></div></details></td>
      </tr></tbody>
    </table>
  </div>
</template>

<style scoped>
/* Keep the absolute screen-reader label inside the table's scroll container. */
.actions-column{position:relative}
.table-wrap{width:100%;overflow:auto;border:1px solid var(--border);border-radius:var(--radius);background:var(--surface)}table{width:100%;border-collapse:collapse;min-width:760px}th{height:40px;padding:0 14px;background:var(--bg-raised);border-bottom:1px solid var(--border);text-align:left;color:var(--subtle);font:10px/1 "Panel Mono",monospace;text-transform:uppercase;letter-spacing:.08em;white-space:nowrap}th button{border:0;background:transparent;color:inherit;padding:0;display:flex;align-items:center;gap:6px;cursor:pointer;text-transform:inherit;letter-spacing:inherit;font:inherit}td{height:50px;padding:9px 14px;border-bottom:1px solid var(--border);white-space:nowrap;max-width:360px;overflow:hidden;text-overflow:ellipsis}tbody tr:last-child td{border-bottom:0}tbody tr:hover td,tbody tr.selected td{background:var(--surface-2)}.actions-column{width:46px}.row-actions{overflow:visible;padding:0 8px;text-align:right}.row-actions details{position:relative}.row-actions summary{list-style:none;width:30px;height:30px;display:grid;place-items:center;border-radius:6px;cursor:pointer;color:var(--muted);margin-left:auto}.row-actions summary::-webkit-details-marker{display:none}.row-actions summary:hover{background:var(--surface-3);color:var(--text)}.row-actions details[open] div{position:absolute;z-index:10;right:0;top:33px;min-width:170px;background:var(--surface);border:1px solid var(--border-strong);border-radius:var(--radius);box-shadow:var(--shadow);padding:5px;display:grid}.row-actions details button{border:0;background:transparent;color:var(--text);padding:9px 10px;text-align:left;border-radius:5px;cursor:pointer;font-size:12px}.row-actions details button:hover{background:var(--surface-2)}.row-actions details button.critical{color:var(--critical)}.sr-only{position:absolute;width:1px;height:1px;padding:0;margin:-1px;overflow:hidden;clip:rect(0,0,0,0);white-space:nowrap;border:0}
</style>
