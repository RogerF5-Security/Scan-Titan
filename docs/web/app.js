"use strict";

function bindTabs(selector) {
  document.querySelectorAll(selector).forEach((list) => {
    const tabs = Array.from(list.querySelectorAll('[role="tab"]'));
    function activate(tab) {
      tabs.forEach((candidate) => {
        const selected = candidate === tab;
        candidate.setAttribute("aria-selected", String(selected));
        candidate.tabIndex = selected ? 0 : -1;
        document.getElementById(
          candidate.getAttribute("aria-controls"),
        ).hidden = !selected;
      });
    }
    tabs.forEach((tab, index) => {
      tab.addEventListener("click", () => activate(tab));
      tab.addEventListener("keydown", (event) => {
        let next;
        if (["ArrowRight", "ArrowDown"].includes(event.key))
          next = (index + 1) % tabs.length;
        if (["ArrowLeft", "ArrowUp"].includes(event.key))
          next = (index + tabs.length - 1) % tabs.length;
        if (event.key === "Home") next = 0;
        if (event.key === "End") next = tabs.length - 1;
        if (next !== undefined) {
          event.preventDefault();
          activate(tabs[next]);
          tabs[next].focus();
        }
      });
    });
  });
}

bindTabs('[role="tablist"]');
const menuToggle = document.querySelector(".menu-toggle");
const navigation = document.getElementById("nav-links");
function closeNavigation() {
  navigation.classList.remove("is-open");
  menuToggle.setAttribute("aria-expanded", "false");
  menuToggle.setAttribute("aria-label", "Abrir navegación");
}
menuToggle.addEventListener("click", () => {
  const expanded = menuToggle.getAttribute("aria-expanded") !== "true";
  menuToggle.setAttribute("aria-expanded", String(expanded));
  menuToggle.setAttribute(
    "aria-label",
    expanded ? "Cerrar navegación" : "Abrir navegación",
  );
  navigation.classList.toggle("is-open", expanded);
});
navigation
  .querySelectorAll("a")
  .forEach((link) => link.addEventListener("click", closeNavigation));
document.addEventListener("keydown", (event) => {
  if (event.key === "Escape" && navigation.classList.contains("is-open")) {
    closeNavigation();
    menuToggle.focus();
  }
});

document.getElementById("copy-command").addEventListener("click", async () => {
  const active = document.querySelector('.os-tabs [aria-selected="true"]');
  const code = document.querySelector(
    `#${active.getAttribute("aria-controls")} code`,
  );
  const status = document.getElementById("copy-status");
  try {
    if (!navigator.clipboard) throw new Error("Portapapeles no disponible");
    await navigator.clipboard.writeText(code.textContent);
    status.textContent = `Comandos de ${active.textContent} copiados.`;
  } catch {
    const range = document.createRange();
    range.selectNodeContents(code);
    const selection = window.getSelection();
    selection.removeAllRanges();
    selection.addRange(range);
    status.textContent =
      "No se pudo copiar automáticamente. Texto seleccionado para copiarlo manualmente.";
  }
});
