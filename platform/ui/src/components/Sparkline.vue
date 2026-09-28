<script setup lang="ts">
import { computed } from "vue";
import { sparklineGeometry } from "../consoleLogic";

const props = withDefaults(defineProps<{ values: number[]; width?: number; height?: number; tone?: "accent" | "healthy" | "warning" | "critical" }>(), { width: 150, height: 34, tone: "accent" });
const geometry = computed(() => sparklineGeometry(props.values, props.width, props.height));
const trend = computed(() => {
  const finite = props.values.filter((value) => Number.isFinite(value));
  if (finite.length < 2) return 0;
  const first = finite[0]!;
  const last = finite[finite.length - 1]!;
  return first === 0 ? 0 : (last - first) / Math.abs(first);
});
</script>

<template>
  <svg v-if="geometry.line" :width="width" :height="height" :viewBox="`0 0 ${width} ${height}`" :class="`spark spark-${tone}`" :data-trend="trend >= 0 ? 'up' : 'down'" role="img" aria-label="Recent value trend">
    <path :d="geometry.area" class="spark-area" />
    <path :d="geometry.line" class="spark-line" fill="none" />
  </svg>
</template>

<style scoped>
.spark { display: block; }
.spark-line { stroke: currentColor; stroke-width: 1.6; stroke-linecap: round; stroke-linejoin: round; }
.spark-area { fill: currentColor; opacity: .13; }
.spark-accent { color: var(--accent); }
.spark-healthy { color: var(--healthy); }
.spark-warning { color: var(--warning); }
.spark-critical { color: var(--critical); }
</style>
