<script setup lang="ts">
import { computed, nextTick, onMounted, ref } from "vue";
import { PhArrowRight as ArrowRight, PhCommand as Command, PhMagnifyingGlass as MagnifyingGlass, PhX as X } from "@phosphor-icons/vue";
import { navigation, pages } from "../domain";
import { router } from "../router";
import { sessionStore } from "../store";
import { fuzzyScore } from "../consoleLogic";

const query=ref("");const selected=ref(0);const input=ref<HTMLInputElement|null>(null);
interface PaletteCommand { id:string;label:string;route:string;group:string;keywords:string;kind:"page"|"action" }
const commands=computed<PaletteCommand[]>(()=>{
  const pageCommands:PaletteCommand[]=navigation.flatMap((group)=>group.items.map((item)=>({id:item.id,label:item.label,route:item.route,group:group.label,keywords:item.keywords.join(" "),kind:"page" as const})));
  const actionCommands:PaletteCommand[]=Object.values(pages).flatMap((page)=>page.createAction?[{id:`${page.id}:${page.createAction.id}`,label:page.createAction.label,route:page.id==="dashboard"?"/":`/${navigation.flatMap((group)=>group.items).find((item)=>item.pageId===page.id)?.route.replaceAll("/","")??page.id}`,group:page.title,keywords:`${page.title} new create ${page.resourceKind}`,kind:"action" as const}]:[]);
  const term=query.value.trim().toLowerCase();
  return pageCommands.concat(actionCommands)
    .map((item)=>({item,score:term?fuzzyScore(term,`${item.label} ${item.group} ${item.keywords}`):1}))
    .filter((entry)=>entry.score>0)
    .sort((left,right)=>right.score-left.score)
    .slice(0,12)
    .map((entry)=>entry.item);
});
onMounted(()=>void nextTick(()=>input.value?.focus()));
function choose(index=selected.value):void{const item=commands.value[index];if(!item)return;router.push(item.route);sessionStore.setCommandOpen(false)}
function keydown(event:KeyboardEvent):void{if(event.key==="ArrowDown"){event.preventDefault();selected.value=Math.min(selected.value+1,commands.value.length-1)}else if(event.key==="ArrowUp"){event.preventDefault();selected.value=Math.max(selected.value-1,0)}else if(event.key==="Enter"){event.preventDefault();choose()}else if(event.key==="Escape")sessionStore.setCommandOpen(false)}
</script>

<template>
  <div class="palette-layer" role="presentation" @mousedown.self="sessionStore.setCommandOpen(false)">
    <section class="palette" role="dialog" aria-modal="true" aria-label="Navigate and run actions" @keydown="keydown">
      <header><MagnifyingGlass :size="20"/><input ref="input" v-model="query" type="search" placeholder="Go to a resource area…" @input="selected=0"/><button type="button" aria-label="Close" @click="sessionStore.setCommandOpen(false)"><X :size="17"/></button></header>
      <div class="results"><button v-for="(item,index) in commands" :key="item.id" type="button" :class="{selected:index===selected}" @mouseenter="selected=index" @click="choose(index)"><span><small>{{item.group}}</small><strong>{{item.label}}</strong></span><ArrowRight :size="15"/></button><p v-if="!commands.length">No resource area matches “{{query}}”.</p></div>
      <footer><span><kbd>↑</kbd><kbd>↓</kbd> Select</span><span><kbd>↵</kbd> Open</span><span><kbd>esc</kbd> Close</span><span class="command-hint"><Command :size="12"/>K</span></footer>
    </section>
  </div>
</template>

<style scoped>
.palette-layer{position:fixed;z-index:100;inset:0;background:rgba(2,6,10,.65);backdrop-filter:blur(8px);display:flex;justify-content:center;align-items:flex-start;padding:12vh 20px}
.palette{width:min(650px,100%);border:1px solid var(--border-strong);border-radius:var(--radius-lg);background:var(--surface-glass);backdrop-filter:blur(24px) saturate(1.3);box-shadow:var(--shadow-lg);overflow:hidden;animation:palette-in .18s cubic-bezier(.3,.7,.3,1)}
@keyframes palette-in{from{transform:scale(.97) translateY(-8px);opacity:0}}
.palette>header{height:62px;display:flex;align-items:center;gap:12px;padding:0 16px;border-bottom:1px solid var(--border)}
.palette>header>svg{color:var(--accent)}
.palette input{flex:1;border:0;outline:0;background:transparent;color:var(--text);font-size:16px}
.palette input::placeholder{color:var(--faint)}
.palette header button{width:31px;height:31px;border:0;border-radius:var(--radius-xs);background:transparent;color:var(--subtle);display:grid;place-items:center;cursor:pointer;transition:background .1s ease,color .1s ease}
.palette header button:hover{background:var(--surface-2);color:var(--text)}
.results{padding:7px;max-height:460px;overflow:auto}
.results button{width:100%;min-height:51px;border:0;border-radius:var(--radius-sm);background:transparent;color:var(--text);padding:8px 11px;display:flex;justify-content:space-between;align-items:center;text-align:left;cursor:pointer;transition:background .08s ease}
.results button.selected{background:var(--accent-soft)}
.results button>span{display:grid;gap:4px}
.results small{color:var(--subtle);font:600 9px/1 var(--font-mono);text-transform:uppercase;letter-spacing:.1em}
.results strong{font-size:13px}
.results button>svg{color:var(--accent);opacity:0;transition:opacity .1s ease}
.results button.selected>svg{opacity:1}
.results>p{padding:30px;text-align:center;color:var(--muted)}
.palette footer{min-height:42px;padding:0 14px;border-top:1px solid var(--border);background:var(--bg-raised);display:flex;align-items:center;gap:14px;color:var(--subtle);font-size:10px}
.palette footer span{display:flex;align-items:center;gap:4px}
.palette kbd{font:9px/1 var(--font-mono);border:1px solid var(--border);border-radius:var(--radius-xs);background:var(--surface);padding:3px 5px;color:var(--muted)}
.command-hint{margin-left:auto}
</style>

