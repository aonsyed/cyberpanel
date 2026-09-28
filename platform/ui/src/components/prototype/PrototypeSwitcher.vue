<script setup lang="ts">
// PROTOTYPE — floating variant switcher. Throwaway; lives on the prototype
// branch once a winner is chosen. Gates on import.meta.env.DEV so a stray
// merge cannot ship the bar to users.
import { computed, onBeforeUnmount, onMounted } from "vue";
import { PhCaretLeft as CaretLeft, PhCaretRight as CaretRight, PhFlask as Flask } from "@phosphor-icons/vue";

const props = defineProps<{ variants: Array<{ key: string; name: string }>; current: string }>();
const emit = defineEmits<{ select: [key: string] }>();

const index = computed(() => Math.max(0, props.variants.findIndex((variant) => variant.key === props.current)));
const label = computed(() => {
  const variant = props.variants[index.value];
  return variant ? `${variant.key} · ${variant.name}` : props.current;
});

function cycle(direction: 1 | -1): void {
  const next = props.variants[(index.value + direction + props.variants.length) % props.variants.length];
  if (next) emit("select", next.key);
}

function keydown(event: KeyboardEvent): void {
  const target = event.target as HTMLElement | null;
  if (target && (target.tagName === "INPUT" || target.tagName === "TEXTAREA" || target.isContentEditable)) return;
  if (event.key === "ArrowLeft") cycle(-1);
  else if (event.key === "ArrowRight") cycle(1);
}

onMounted(() => window.addEventListener("keydown", keydown));
onBeforeUnmount(() => window.removeEventListener("keydown", keydown));
</script>

<template>
  <div v-if="true" class="proto-bar" role="navigation" aria-label="Prototype variant switcher">
    <button type="button" aria-label="Previous variant" @click="cycle(-1)"><CaretLeft :size="16" weight="bold"/></button>
    <span class="proto-label"><Flask :size="14"/><strong>{{ label }}</strong><small>← → to flip</small></span>
    <button type="button" aria-label="Next variant" @click="cycle(1)"><CaretRight :size="16" weight="bold"/></button>
  </div>
</template>

<style scoped>
.proto-bar {
  position: fixed; z-index: 200; bottom: 18px; left: 50%; transform: translateX(-50%);
  display: flex; align-items: center; gap: 0;
  background: #111; color: #fff;
  border: 1px solid #444; border-radius: 99px;
  padding: 4px; box-shadow: 0 8px 32px rgba(0,0,0,.5);
  font-family: system-ui, sans-serif;
  user-select: none;
}
.proto-bar button {
  width: 32px; height: 32px; border: 0; border-radius: 50%;
  background: transparent; color: #aaa; cursor: pointer;
  display: grid; place-items: center;
  transition: background .1s ease, color .1s ease;
}
.proto-bar button:hover { background: #333; color: #fff; }
.proto-label {
  display: flex; align-items: center; gap: 7px; padding: 0 12px;
  font-size: 12px; white-space: nowrap;
}
.proto-label svg { color: #f0b04f; }
.proto-label strong { font-size: 12px; }
.proto-label small { color: #777; font-size: 10px; }
</style>
