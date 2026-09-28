<script setup lang="ts">
// File browser — breadcrumb navigation, folder/file icon grid, upload dropzone.
import { computed, inject, onMounted, ref } from "vue";
import {
  PhArrowClockwise, PhCaretRight, PhDownload, PhFile,
  PhFileArchive, PhFileCode, PhFileImage, PhFileText,
  PhFileHtml, PhFolder, PhFolderOpen, PhHouse, PhPencil,
  PhTrash, PhUpload, PhCloudArrowUp,
} from "@phosphor-icons/vue";
import type { APIClient } from "../api";
import { sessionStore } from "../store";

const api = inject<APIClient>("api")!;
const loading = ref(true);
const error = ref("");
const sites = ref<Record<string, unknown>[]>([]);
const activeSite = ref("");
const currentPath = ref("");
const entries = ref<Record<string, unknown>[]>([]);
const dragOver = ref(false);

const tenantId = computed(() => sessionStore.state.tenantId || undefined);
onMounted(() => void load());

async function load(): Promise<void> {
  loading.value = true; error.value = "";
  try {
    if (api.available("hosting.site.list")) {
      const response = await api.invoke<unknown>("hosting.site.list", { tenantId: tenantId.value, payload: { limit: 100 } });
      const result = response.result;
      sites.value = Array.isArray(result) ? result as Record<string, unknown>[] : (result as { items?: Record<string, unknown>[] })?.items ?? [];
      if (sites.value.length && !activeSite.value) {
        activeSite.value = String(sites.value[0]?.primary_hostname ?? sites.value[0]?.id ?? "");
        await loadDirectory();
      }
    }
  } catch (cause) { error.value = cause instanceof Error ? cause.message : "Failed to load sites."; }
  finally { loading.value = false; }
}

async function loadDirectory(): Promise<void> {
  if (!activeSite.value) { entries.value = []; return; }
    if (!api.available("access.files.list")) { entries.value = []; return; }
  try {
    const response = await api.invoke<unknown>("access.files.list", {
      tenantId: tenantId.value,
      payload: { root: "public", path: currentPath.value || "/" },
    });
    const result = response.result;
    entries.value = Array.isArray(result) ? result as Record<string, unknown>[] : (result as { items?: Record<string, unknown>[] })?.items ?? [];
    // Sort: folders first, then files, alphabetically
    entries.value.sort((a, b) => {
      const aDir = a.kind === "directory" || a.type === "directory";
      const bDir = b.kind === "directory" || b.type === "directory";
      if (aDir !== bDir) return aDir ? -1 : 1;
      return String(a.name ?? "").localeCompare(String(b.name ?? ""));
    });
  } catch { entries.value = []; }
}

function navigateTo(name: string): void {
  const entry = entries.value.find(e => String(e.name) === name);
  if (entry && (entry.kind === "directory" || entry.type === "directory")) {
    currentPath.value = currentPath.value === "" ? name : `${currentPath.value}/${name}`;
    void loadDirectory();
  }
}

function navigateCrumb(index: number): void {
  const parts = currentPath.value.split("/");
  currentPath.value = parts.slice(0, index + 1).join("/");
  void loadDirectory();
}

function fileIcon(name: string, isDir: boolean): unknown {
  if (isDir) return currentPath.value ? PhFolderOpen : PhFolder;
  const ext = name.split(".").pop()?.toLowerCase() ?? "";
  if (["jpg", "png", "gif", "svg", "webp", "ico"].includes(ext)) return PhFileImage;
  if (["zip", "tar", "gz", "bz2", "xz", "7z"].includes(ext)) return PhFileArchive;
  if (["php", "js", "ts", "py", "rb", "go", "rs"].includes(ext)) return PhFileCode;
  if (["html", "htm", "xml", "json", "yaml", "yml"].includes(ext)) return PhFileHtml;
  if (["txt", "md", "log", "conf"].includes(ext)) return PhFileText;
  return PhFile;
}

function fmtSize(size: unknown): string {
  const num = Number(size);
  if (!Number.isFinite(num) || num <= 0) return "";
  const units = ["B", "KB", "MB", "GB"]; let amount = num, i = 0;
  while (amount >= 1024 && i < units.length - 1) { amount /= 1024; i++; }
  return `${amount >= 10 || i === 0 ? amount.toFixed(0) : amount.toFixed(1)} ${units[i]}`;
}

function onDrop(event: DragEvent): void {
  dragOver.value = false;
  const files = event.dataTransfer?.files;
  if (files?.length) {
    // Upload logic would go here via access.upload.begin
  }
}
</script>

<template>
  <main class="files-page">
    <header class="page-header">
      <div>
        <h2>Files</h2>
        <p>{{ entries.length }} item{{ entries.length === 1 ? '' : 's' }} in {{ activeSite || 'no site' }}</p>
      </div>
      <div class="header-actions">
        <button class="button" type="button" :disabled="loading" @click="load">
          <PhArrowClockwise :size="15" :class="{ spinning: loading }"/> Refresh
        </button>
        <button class="button button-primary" type="button">
          <PhUpload :size="16"/> Upload
        </button>
      </div>
    </header>

    <!-- Site selector -->
    <div v-if="sites.length > 1" class="site-selector">
      <label>Site</label>
      <select v-model="activeSite" class="input select" @change="currentPath = ''; loadDirectory()">
        <option v-for="site in sites" :key="String(site.id)" :value="String(site.primary_hostname ?? site.id)">{{ site.primary_hostname ?? site.id }}</option>
      </select>
    </div>

    <p v-if="error" class="error-banner">{{ error }}</p>
    <div v-if="loading" class="loading"><span v-for="i in 4" :key="i" class="skeleton" style="height:80px"/></div>

    <div v-if="!loading && activeSite" class="browser-area">
      <!-- Breadcrumb -->
      <nav class="breadcrumb">
        <button type="button" class="crumb" @click="currentPath = ''; loadDirectory()">
          <PhHouse :size="14"/> root
        </button>
        <template v-for="(part, i) in currentPath.split('/').filter(Boolean)" :key="i">
          <PhCaretRight :size="10" class="crumb-sep"/>
          <button type="button" class="crumb" @click="navigateCrumb(i)">{{ part }}</button>
        </template>
      </nav>

      <!-- Upload dropzone -->
      <div class="dropzone" :class="{ over: dragOver }" @dragover.prevent="dragOver = true" @dragleave="dragOver = false" @drop.prevent="onDrop">
        <PhCloudArrowUp :size="24"/>
        <p>Drag files here to upload to <strong>/{{ currentPath }}</strong></p>
      </div>

      <!-- File grid -->
      <div v-if="entries.length" class="file-grid">
        <button v-for="(entry, i) in entries" :key="i" type="button" class="file-item" :class="{ dir: entry.kind === 'directory' || entry.type === 'directory' }" @dblclick="navigateTo(String(entry.name))" @click="entry.kind === 'directory' || entry.type === 'directory' ? navigateTo(String(entry.name)) : undefined">
          <component :is="fileIcon(String(entry.name), entry.kind === 'directory' || entry.type === 'directory')" :size="28" weight="duotone" class="file-icon"/>
          <span class="file-name">{{ entry.name }}</span>
          <span v-if="entry.size" class="file-size">{{ fmtSize(entry.size) }}</span>
        </button>
      </div>

      <div v-if="!entries.length" class="empty-hint">
        <PhFolder :size="24"/>
        <p>This directory is empty. Drop files above to upload.</p>
      </div>
    </div>

    <div v-if="!loading && !sites.length && !error" class="empty-state">
      <PhFolder :size="48" weight="duotone"/>
      <h3>No websites yet</h3>
      <p>Create a website first, then you can upload files to it here.</p>
      <button class="button button-primary" type="button">Create a Site</button>
    </div>
  </main>
</template>

<style scoped>
.files-page{padding:32px clamp(18px,3vw,48px) 64px;max-width:1400px;margin:0 auto}
.page-header{display:flex;justify-content:space-between;align-items:center;gap:20px;margin-bottom:24px}
.page-header h2{margin:0 0 4px;font-size:clamp(24px,2.5vw,32px);letter-spacing:-.04em;font-weight:700}
.page-header p{margin:0;color:var(--muted);font-size:14px}
.header-actions{display:flex;gap:8px}
.error-banner{padding:14px 16px;border-left:3px solid var(--critical);border-radius:var(--radius-xs);background:var(--critical-soft);color:var(--critical);margin:0 0 16px}
.loading{display:grid;gap:10px}

.site-selector{display:flex;align-items:center;gap:12px;margin-bottom:16px}
.site-selector label{font-size:13px;font-weight:600;color:var(--subtle)}
.site-selector .select{max-width:300px}

.browser-area{border:1px solid var(--border);border-radius:var(--radius-lg);background:var(--surface);box-shadow:var(--shadow-sm);overflow:hidden}

.breadcrumb{display:flex;align-items:center;gap:4px;padding:12px 16px;border-bottom:1px solid var(--border);background:var(--bg-raised);flex-wrap:wrap}
.crumb{display:flex;align-items:center;gap:4px;border:0;background:transparent;color:var(--accent);font-size:13px;font-weight:550;cursor:pointer;padding:4px 8px;border-radius:var(--radius-xs);transition:background .1s ease}
.crumb:hover{background:var(--accent-soft)}
.crumb-sep{color:var(--faint)}

.dropzone{display:grid;place-items:center;gap:8px;padding:20px;margin:12px;border:2px dashed var(--border-strong);border-radius:var(--radius);color:var(--subtle);text-align:center;transition:border-color .16s ease,background .16s ease;cursor:pointer}
.dropzone.over{border-color:var(--accent);background:var(--accent-softer);color:var(--accent)}
.dropzone svg{opacity:.7}
.dropzone p{margin:0;font-size:13px}
.dropzone strong{color:inherit}

.file-grid{display:grid;grid-template-columns:repeat(auto-fill,minmax(140px,1fr));gap:6px;padding:12px}
.file-item{display:flex;flex-direction:column;align-items:center;gap:6px;padding:16px 8px;border:1px solid transparent;border-radius:var(--radius);background:transparent;cursor:pointer;text-align:center;transition:background .1s ease,border-color .1s ease}
.file-item:hover{background:var(--surface-2);border-color:var(--border)}
.file-item.dir .file-icon{color:var(--accent)}
.file-item .file-icon{color:var(--muted)}
.file-name{font-size:12px;font-weight:500;word-break:break-all;line-height:1.3;max-width:100%;overflow:hidden;text-overflow:ellipsis;white-space:nowrap}
.file-size{font-size:10px;color:var(--subtle);font-family:var(--font-mono)}

.empty-hint{display:grid;place-items:center;gap:10px;padding:40px 24px;color:var(--subtle);text-align:center}
.empty-hint p{margin:0;font-size:13px}
.empty-state{display:grid;place-items:center;gap:14px;padding:64px 24px;text-align:center;border:1px dashed var(--border-strong);border-radius:var(--radius-lg)}
.empty-state svg{color:var(--faint)}
.empty-state h3{margin:0;font-size:18px}
.empty-state p{margin:0;color:var(--muted);font-size:13px;max-width:44ch;line-height:1.5}
.spinning{animation:spin .8s linear infinite}
@keyframes spin{to{transform:rotate(1turn)}}
</style>
