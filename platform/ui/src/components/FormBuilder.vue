<script setup lang="ts">
// Form field renderer that replaces the metadata-driven ActionDrawer fields.
// Every field gets a proper visual component — no raw JSON textareas.
import { computed, reactive, watch } from "vue";
import { PhPlus, PhTrash, PhX } from "@phosphor-icons/vue";
import type { FieldDefinition } from "../domain";

const props = defineProps<{
  fields: FieldDefinition[];
  modelValue: Record<string, unknown>;
  errors?: Record<string, string> | undefined;
  disabled?: boolean | undefined;
}>();
const emit = defineEmits<{ "update:modelValue": [value: Record<string, unknown>] }>();

const values = reactive<Record<string, unknown>>({ ...props.modelValue });
watch(() => props.modelValue, (next) => { Object.keys(values).forEach(k => delete values[k]); Object.assign(values, next); }, { deep: true });
watch(values, () => emit("update:modelValue", { ...values }), { deep: true });

// For list-type fields (privileges, cidrs, etc.) we manage arrays
const listItems = reactive<Record<string, string>>({});

function addListItem(key: string): void {
  const input = (listItems[key] ?? "").trim();
  if (!input) return;
  const current = Array.isArray(values[key]) ? [...values[key] as string[]] : [];
  if (!current.includes(input)) { current.push(input); values[key] = current; }
  listItems[key] = "";
}
function removeListItem(key: string, index: number): void {
  const current = Array.isArray(values[key]) ? [...values[key] as string[]] : [];
  current.splice(index, 1); values[key] = current;
}

function fieldOptions(field: FieldDefinition): Array<{ label: string; value: string }> {
  return field.options ?? [];
}

// Determine if a field should render as a list-input instead of a textarea
function isListField(field: FieldDefinition): boolean {
  return field.type === "json" || (field.key.includes("privileges") || field.key.includes("cidrs") || field.key.includes("interfaces") || field.key.includes("values"));
}

// Parse existing JSON value into list items for display
function initListFromValue(field: FieldDefinition): void {
  if (Array.isArray(values[field.key])) return;
  const raw = values[field.key];
  if (typeof raw === "string" && raw.trim()) {
    try { const parsed = JSON.parse(raw); if (Array.isArray(parsed)) values[field.key] = parsed; }
    catch { /* keep as string */ }
  }
}
props.fields.filter(isListField).forEach(initListFromValue);
</script>

<template>
  <div class="form-builder">
    <div v-for="field in fields" :key="field.key" class="field-group">
      <label :for="`f-${field.key}`" class="field-label">
        {{ field.label }}
        <span v-if="field.required" class="required">*</span>
      </label>

      <!-- Select dropdown -->
      <select v-if="field.type === 'select'" :id="`f-${field.key}`" :value="String(values[field.key] ?? '')" @change="values[field.key] = ($event.target as HTMLSelectElement).value" class="input select" :disabled="disabled ?? undefined">
        <option value="" disabled>Select…</option>
        <option v-for="opt in fieldOptions(field)" :key="opt.value" :value="opt.value">{{ opt.label }}</option>
      </select>

      <!-- Boolean toggle -->
      <div v-else-if="field.type === 'boolean'" class="toggle-row">
        <label class="toggle" :for="`f-${field.key}`">
          <input :id="`f-${field.key}`" :checked="Boolean(values[field.key])" @change="values[field.key] = ($event.target as HTMLInputElement).checked" :disabled="disabled ?? undefined" class="toggle-input"/>
          <span class="toggle-track"><span class="toggle-thumb"/></span>
          <span class="toggle-label">{{ values[field.key] ? "Enabled" : "Disabled" }}</span>
        </label>
      </div>

      <!-- List input (replaces JSON textarea for arrays) -->
      <div v-else-if="isListField(field)" class="list-input">
        <div v-if="Array.isArray(values[field.key]) && (values[field.key] as string[]).length" class="list-items">
          <span v-for="(item, i) in (values[field.key] as string[])" :key="i" class="chip">
            {{ item }}
            <button type="button" class="chip-remove" :disabled="disabled ?? undefined" @click="removeListItem(field.key, i)" aria-label="Remove">
              <PhX :size="11"/>
            </button>
          </span>
        </div>
        <div class="list-add">
          <input :value="listItems[field.key] ?? ''" @input="listItems[field.key] = ($event.target as HTMLInputElement).value" type="text" class="input" :placeholder="`Add ${field.label.toLowerCase()}…`" :disabled="disabled ?? undefined" @keydown.enter.prevent="addListItem(field.key)"/>
          <button type="button" class="button button-small" :disabled="disabled || !(listItems[field.key] ?? '').trim()" @click="addListItem(field.key)">
            <PhPlus :size="14"/> Add
          </button>
        </div>
      </div>

      <!-- Textarea (for actual text content, not JSON) -->
      <textarea v-else-if="field.type === 'textarea'" :id="`f-${field.key}`" :value="String(values[field.key] ?? '')" @input="values[field.key] = ($event.target as HTMLTextAreaElement).value" class="input textarea" :rows="3" :disabled="disabled ?? undefined" :placeholder="field.helper ?? ''"/>

      <!-- Password -->
      <input v-else-if="field.type === 'password'" :id="`f-${field.key}`" :value="String(values[field.key] ?? '')" @input="values[field.key] = ($event.target as HTMLInputElement).value" type="password" class="input" :disabled="disabled ?? undefined" autocomplete="new-password"/>

      <!-- Number -->
      <input v-else-if="field.type === 'number'" :id="`f-${field.key}`" :value="String(values[field.key] ?? '')" @input="values[field.key] = ($event.target as HTMLInputElement).value" type="number" class="input" :disabled="disabled ?? undefined"/>

      <!-- Default: text input -->
      <input v-else :id="`f-${field.key}`" :value="String(values[field.key] ?? '')" @input="values[field.key] = ($event.target as HTMLInputElement).value" type="text" class="input" :disabled="disabled ?? undefined" :placeholder="field.helper ?? ''"/>

      <p v-if="field.helper && field.type !== 'textarea'" class="field-help">{{ field.helper }}</p>
      <p v-if="errors?.[field.key]" class="field-error">{{ errors[field.key] }}</p>
    </div>
  </div>
</template>

<style scoped>
.form-builder{display:grid;gap:20px}
.field-group{display:grid;gap:7px}
.field-label{font-size:13px;font-weight:600;color:var(--text);display:flex;align-items:center;gap:4px}
.required{color:var(--critical);font-weight:700}
.field-help{color:var(--subtle);font-size:12px;margin:0;line-height:1.4}
.field-error{color:var(--critical);font-size:12px;margin:0}

.input{width:100%;min-height:42px;border:1px solid var(--border-strong);border-radius:var(--radius);background:var(--bg-raised);color:var(--text);padding:10px 13px;font-size:14px;transition:border-color .16s ease,box-shadow .16s ease}
.input:focus{outline:none;border-color:var(--accent);box-shadow:0 0 0 3px var(--accent-soft)}
.input:disabled{opacity:.5}
.textarea{min-height:80px;resize:vertical;font-family:inherit}
.select{appearance:none;background-image:url("data:image/svg+xml,%3Csvg xmlns='http://www.w3.org/2000/svg' width='12' height='12' fill='%2393a5b0' viewBox='0 0 256 256'%3E%3Cpath d='M228,92a12,12,0,0,0-17-17L128,158,45,75A12,12,0,0,0,28,92l92,92a12,12,0,0,0,17,0Z'/%3E%3C/svg%3E");background-repeat:no-repeat;background-position:right 12px center;padding-right:36px}

/* Toggle switch */
.toggle-row{display:flex;align-items:center;min-height:42px}
.toggle{display:flex;align-items:center;gap:10px;cursor:pointer}
.toggle-input{display:none}
.toggle-track{width:44px;height:24px;border-radius:99px;background:var(--surface-3);border:1px solid var(--border-strong);position:relative;transition:background .16s ease,border-color .16s ease;flex-shrink:0}
.toggle-thumb{position:absolute;top:2px;left:2px;width:18px;height:18px;border-radius:50%;background:var(--muted);transition:transform .16s ease,background .16s ease}
.toggle-input:checked + .toggle-track{background:var(--accent);border-color:var(--accent-deep)}
.toggle-input:checked + .toggle-track .toggle-thumb{transform:translateX(20px);background:white}
.toggle-label{font-size:13px;color:var(--muted);font-weight:550}

/* List input with chips */
.list-input{display:grid;gap:8px}
.list-items{display:flex;flex-wrap:wrap;gap:6px}
.chip{display:inline-flex;align-items:center;gap:5px;padding:5px 10px;border-radius:99px;font-size:12px;font-weight:550;background:var(--accent-soft);color:var(--accent);border:1px solid color-mix(in srgb,var(--accent),transparent 75%)}
.chip-remove{display:grid;place-items:center;width:16px;height:16px;border:0;border-radius:50%;background:transparent;color:inherit;cursor:pointer;padding:0;opacity:.6;transition:opacity .1s ease}
.chip-remove:hover{opacity:1}
.list-add{display:flex;gap:8px}
.list-add .input{flex:1}
</style>
