// Tooltips for anything carrying a data-hint attribute.
//
// Native title tooltips only appear on hover, after a delay, and never on
// click or touch. This shows the same text immediately on hover or keyboard
// focus, and keeps it open when the element is clicked or tapped.
(function () {
  const OPEN_CLASS = "hint-open";
  let tip = null;
  let anchor = null;
  let sticky = false;

  function tooltip() {
    if (!tip) {
      tip = document.createElement("div");
      tip.id = "hint-tip";
      tip.className = "hint-tip";
      tip.setAttribute("role", "tooltip");
      tip.hidden = true;
      document.body.append(tip);
    }
    return tip;
  }

  function place(target) {
    const node = tooltip();
    const margin = 8;
    const rect = target.getBoundingClientRect();
    node.style.maxWidth = `${Math.min(340, window.innerWidth - 2 * margin)}px`;
    node.hidden = false;
    const size = node.getBoundingClientRect();
    const above = rect.top >= size.height + margin;
    const top = above ? rect.top - size.height - 6 : rect.bottom + 6;
    const left = Math.min(
      Math.max(margin, rect.left),
      Math.max(margin, window.innerWidth - size.width - margin),
    );
    node.style.top = `${Math.max(margin, top)}px`;
    node.style.left = `${left}px`;
    node.dataset.placement = above ? "above" : "below";
  }

  function show(target, { pinned = false } = {}) {
    const text = target.dataset.hint;
    if (!text) return;
    const node = tooltip();
    node.textContent = text;
    if (anchor && anchor !== target) hide({ force: true });
    anchor = target;
    sticky = pinned;
    target.classList.add(OPEN_CLASS);
    target.setAttribute("aria-describedby", "hint-tip");
    place(target);
  }

  function hide({ force = false } = {}) {
    if (!anchor || (sticky && !force)) return;
    tooltip().hidden = true;
    anchor.classList.remove(OPEN_CLASS);
    anchor.removeAttribute("aria-describedby");
    anchor = null;
    sticky = false;
  }

  function target(event) {
    return event.target instanceof Element ? event.target.closest("[data-hint]") : null;
  }

  document.addEventListener("mouseover", (event) => {
    const node = target(event);
    if (node) show(node);
    else if (!sticky) hide();
  });

  document.addEventListener("mouseout", (event) => {
    const node = target(event);
    const moved = event.relatedTarget;
    // Moving onto a child of the same element is not leaving it.
    if (node && !(moved instanceof Node && node.contains(moved)) && !sticky) hide();
  });

  // A click pins the tooltip open, so it also works on touch screens. Option
  // buttons keep their own click behaviour; pinning would fight with it.
  document.addEventListener("click", (event) => {
    const node = target(event);
    if (!node || node.classList.contains("opt")) {
      hide({ force: true });
      return;
    }
    if (anchor === node && sticky) hide({ force: true });
    else show(node, { pinned: true });
  });

  // Focus shows the hint but does not pin it, so the click that follows a
  // mouse press can still pin it rather than closing it again.
  document.addEventListener("focusin", (event) => {
    const node = target(event);
    if (node) show(node);
  });

  document.addEventListener("focusout", () => hide({ force: true }));

  document.addEventListener("keydown", (event) => {
    if (event.key === "Escape") hide({ force: true });
  });

  // Scrolling moves the anchor, so follow it rather than closing: the page
  // scrolls smoothly, and a hover during that animation would be lost.
  let frame = null;
  function follow() {
    frame = null;
    if (!anchor) return;
    const rect = anchor.getBoundingClientRect();
    if (rect.bottom < 0 || rect.top > window.innerHeight) hide({ force: true });
    else place(anchor);
  }

  window.addEventListener(
    "scroll",
    () => {
      if (anchor && frame === null) frame = requestAnimationFrame(follow);
    },
    true,
  );
  window.addEventListener("resize", () => hide({ force: true }));

  window.AivssHints = {
    // Attaches hint text and, for elements that cannot be focused on their
    // own, makes them reachable by keyboard.
    attach(element, text) {
      if (!element || !text) return element;
      element.dataset.hint = text;
      element.removeAttribute("title");
      if (!element.matches("a, button, input, select, textarea, summary, [tabindex]")) {
        element.tabIndex = 0;
      }
      return element;
    },
  };

  // Static markup declares hints with a data-hint attribute; give those the
  // same keyboard access.
  document.addEventListener("DOMContentLoaded", () => {
    for (const node of document.querySelectorAll("[data-hint]")) {
      window.AivssHints.attach(node, node.dataset.hint);
    }
  });
})();
