import { ref } from "vue";

const currentPath = ref(window.location.pathname);

window.addEventListener("popstate", () => { currentPath.value = window.location.pathname; });

export const router = {
  currentPath,
  push(path: string) {
    if (path === currentPath.value) return;
    history.pushState({}, "", path); currentPath.value = path;
    window.scrollTo({ top: 0, behavior: "auto" });
  },
  replace(path: string) { history.replaceState({}, "", path); currentPath.value = path; }
};
