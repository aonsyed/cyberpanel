import { computed, reactive, readonly } from "vue";
import type { OperationDescription } from "./api";

export interface ViewerTenant { membership_id:string;tenant_id:string;name:string;kind:string;membership_state:string;tenant_state:string;selectable:boolean }
export interface ViewerProjection { principal_id:string;username:string;email?:string;display_name:string;locale:string;theme:string;assurance:number|string;authz_epoch:number;session_expires_at?:string;tenants:ViewerTenant[] }
export interface Viewer { id: string; username:string;displayName: string; email?: string; tenantId: string; tenantName: string; assurance: number|string; locale: string; tenants:ViewerTenant[] }
export interface Notice { id: string; tone: "info" | "healthy" | "warning" | "critical"; title: string; body: string; createdAt: Date; timeout?: number }

const internal = reactive({
  viewer: null as Viewer | null,
  tenantId: localStorage.getItem("panel.tenant") || "",
  operations: [] as OperationDescription[],
  notices: [] as Notice[],
  navigationCollapsed: localStorage.getItem("panel.nav.collapsed") === "true",
  commandOpen: false,
  theme: (localStorage.getItem("panel.theme") || "system") as "system" | "light" | "dark",
  online: navigator.onLine
});

export const sessionStore = {
  state: readonly(internal),
  authenticated: computed(() => internal.viewer !== null),
  setViewer(viewer: Viewer | null) { internal.viewer = viewer; if (viewer && !internal.tenantId) this.setTenant(viewer.tenantId); },
  setProjection(projection:ViewerProjection|null){if(!projection){internal.viewer=null;return}const selectable=projection.tenants.filter((tenant)=>tenant.selectable);const selected=selectable.find((tenant)=>tenant.tenant_id===internal.tenantId)||selectable[0];if(!selected){internal.viewer=null;return}internal.viewer={id:projection.principal_id,username:projection.username,displayName:projection.display_name,email:projection.email||"",tenantId:selected.tenant_id,tenantName:selected.name,assurance:projection.assurance,locale:projection.locale,tenants:projection.tenants};this.setTenant(selected.tenant_id)},
  setTenant(id: string) { internal.tenantId = id; localStorage.setItem("panel.tenant", id); },
  setOperations(operations: OperationDescription[]) { internal.operations = operations; },
  toggleNavigation() { internal.navigationCollapsed = !internal.navigationCollapsed; localStorage.setItem("panel.nav.collapsed", String(internal.navigationCollapsed)); },
  setCommandOpen(open: boolean) { internal.commandOpen = open; },
  setTheme(theme: "system" | "light" | "dark") { internal.theme = theme; localStorage.setItem("panel.theme", theme); document.documentElement.dataset.theme = theme; },
  setOnline(online: boolean) { internal.online = online; },
  notify(notice: Omit<Notice, "id" | "createdAt">) {
    const id = `notice_${crypto.randomUUID()}`; internal.notices.push({ ...notice, id, createdAt: new Date() });
    if (notice.timeout !== 0) window.setTimeout(() => this.dismiss(id), notice.timeout || 6000);
  },
  dismiss(id: string) { const index = internal.notices.findIndex((notice) => notice.id === id); if (index >= 0) internal.notices.splice(index, 1); }
};
