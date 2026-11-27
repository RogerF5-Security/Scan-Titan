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

const workflow = document.querySelector("[data-workflow]");
if (workflow) {
  const stages = [
    {
      kicker: "ETAPA 01 · DESCUBRIMIENTO",
      title: "Reconocimiento correlacionado",
      description:
        "Nmap, WhatWeb, subfinder y el navegador construyen una superficie común antes de iniciar las comprobaciones.",
      events: [
        ["✓", "443/tcp abierto · HTTPS"],
        ["✓", "tecnología: nginx + Python"],
        ["→", "superficie normalizada para la siguiente etapa"],
      ],
      cpu: "18.4%",
      ram: "286 MB",
      state: "DESCUBRIENDO",
    },
    {
      kicker: "ETAPA 02 · FILTRO DE RUTAS",
      title: "Solo señales HTTP útiles",
      description:
        "El filtro concurrente devuelve una lista cruda del mismo origen y conserva exclusivamente las respuestas HTTP 200 y 403.",
      events: [
        ["✓", "/api/productos · HTTP 200"],
        ["✓", "/admin · HTTP 403"],
        ["↷", "302, 404 y respuestas fuera de alcance descartadas"],
      ],
      cpu: "12.1%",
      ram: "244 MB",
      state: "FILTRANDO",
    },
    {
      kicker: "ETAPA 03 · VALIDACIÓN",
      title: "Pruebas inteligentes sin bloqueos",
      description:
        "Workers acotados ejecutan comprobaciones LFI, XSS, SSRF y de rutas. Cada prueba tiene un timeout estricto y los saltos quedan registrados.",
      events: [
        ["✓", "pool concurrente · 8 workers"],
        ["!", "probe agotada · salto limpio registrado"],
        ["→", "Nuclei y ZAP reciben semillas normalizadas"],
      ],
      cpu: "36.7%",
      ram: "412 MB",
      state: "VALIDANDO",
    },
    {
      kicker: "ETAPA 04 · EVIDENCIA",
      title: "Reporte verificable y exportación",
      description:
        "Los hallazgos, el inventario y la telemetría se separan. Las salidas crudas de motores externos se centralizan para revisión técnica.",
      events: [
        ["✓", "hallazgos deduplicados con evidencia"],
        ["✓", "CPU y RAM del árbol de procesos registradas"],
        ["→", "HTML + XLSX + JSON/XML externos"],
      ],
      cpu: "9.8%",
      ram: "318 MB",
      state: "REPORTANDO",
    },
  ];
  const buttons = Array.from(workflow.querySelectorAll("[data-flow-step]"));
  const eventBox = document.getElementById("flow-events");
  const toggle = document.getElementById("flow-toggle");
  const prefersReducedMotion = window.matchMedia(
    "(prefers-reduced-motion: reduce)",
  ).matches;
  let activeStep = 0;
  let paused = prefersReducedMotion;
  let timer;

  function renderEvents(events) {
    eventBox.replaceChildren();
    events.forEach(([mark, message], index) => {
      const line = document.createElement("code");
      const badge = document.createElement("b");
      badge.textContent = mark;
      line.style.animationDelay = `${index * 55}ms`;
      line.append(badge, ` ${message}`);
      eventBox.append(line);
    });
  }

  function activateStep(index) {
    activeStep = index;
    const stage = stages[index];
    buttons.forEach((button, buttonIndex) => {
      const selected = buttonIndex === index;
      button.classList.toggle("is-active", selected);
      if (selected) button.setAttribute("aria-current", "step");
      else button.removeAttribute("aria-current");
    });
    document.getElementById("flow-kicker").textContent = stage.kicker;
    document.getElementById("flow-title").textContent = stage.title;
    document.getElementById("flow-description").textContent = stage.description;
    document.getElementById("flow-cpu").textContent = stage.cpu;
    document.getElementById("flow-ram").textContent = stage.ram;
    document.getElementById("flow-state").textContent = stage.state;
    renderEvents(stage.events);
  }

  function updateAutoplay() {
    window.clearInterval(timer);
    toggle.setAttribute("aria-pressed", String(paused));
    toggle.textContent = paused ? "INICIAR AUTOPLAY" : "PAUSAR AUTOPLAY";
    if (!paused) {
      timer = window.setInterval(
        () => activateStep((activeStep + 1) % stages.length),
        4200,
      );
    }
  }

  buttons.forEach((button, index) => {
    button.addEventListener("click", () => {
      activateStep(index);
      updateAutoplay();
    });
  });
  toggle.addEventListener("click", () => {
    paused = !paused;
    updateAutoplay();
  });
  document.addEventListener("visibilitychange", () => {
    if (document.hidden) window.clearInterval(timer);
    else updateAutoplay();
  });
  activateStep(0);
  updateAutoplay();
}
