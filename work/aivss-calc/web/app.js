// OWASP Agentic Top 10 example cards and the full-report dialog.
// Text is always inserted with textContent, never as HTML.
const grid = document.getElementById("grid");
const detail = document.getElementById("detail");
const detailTitle = document.getElementById("detail-title");
const detailBody = document.getElementById("detail-body");
const sortBy = document.getElementById("sort-by");
const closeDetailBtn = document.getElementById("close-detail");

let rows = [];

function node(tag, props = {}, ...children) {
  const el = document.createElement(tag);
  for (const [key, value] of Object.entries(props)) {
    if (value === undefined || value === null) continue;
    if (key === "class") el.className = value;
    else if (key === "text") el.textContent = value;
    else if (key.startsWith("on")) el.addEventListener(key.slice(2), value);
    else el.setAttribute(key, value);
  }
  for (const child of children) {
    if (child !== null && child !== undefined) el.append(child);
  }
  return el;
}

async function fetchJson(apiPath, staticPath) {
  try {
    const apiRes = await fetch(apiPath);
    if (apiRes.ok) return apiRes.json();
  } catch (_) {
    /* local API unavailable — use static bundle */
  }
  const staticRes = await fetch(staticPath);
  if (!staticRes.ok) throw new Error(`HTTP ${staticRes.status}`);
  return staticRes.json();
}

function scoreWidth(value) {
  if (value == null || Number.isNaN(value)) return "0%";
  return `${Math.max(0, Math.min(10, value)) * 10}%`;
}

function formatScore(value) {
  return value == null ? "—" : Number(value).toFixed(1);
}

function overlayNode(row) {
  const label = row.aivss_recommended_label;
  if (!label) return null;
  const escalated =
    row.escalated === true ||
    (row.aivss_recommended_timeline &&
      row.bod_timeline &&
      row.aivss_recommended_timeline !== row.bod_timeline);
  if (!escalated) return null;
  return node("span", { class: "overlay", text: `AIVSS overlay: ${label}` });
}

function card(row) {
  const bar = node("span");
  bar.style.width = scoreWidth(row.aivss);
  return node(
    "article",
    { class: "card" },
    node("div", { class: "card-icon", text: row.asi.replace("ASI", "") }),
    node(
      "div",
      { class: "card-head" },
      node("div", { class: "asi-id", text: row.asi }),
      node("div", {
        class: `class-pill class-${row.agentic_effect_class}`,
        text: row.agentic_effect_class,
      }),
    ),
    node("h3", { class: "card-name", text: row.name }),
    node("p", { class: "card-desc", text: row.title }),
    node(
      "div",
      { class: "score-box score-box-full" },
      node("div", { class: "score-label", text: `AIVSS · ${row.aivss_band}` }),
      node("div", { class: "score-value aivss", text: formatScore(row.aivss) }),
      node("div", { class: "bar" }, bar),
      node("div", {
        class: "score-sub",
        text: `${row.cvss_nomenclature} ${formatScore(row.cvss_bte)} · U ${row.agentic_uplift_u ?? "—"}`,
      }),
    ),
    node(
      "div",
      { class: "timeline" },
      node("strong", { text: "SSVC / BOD analogy: " }),
      row.bod_timeline_label || "—",
      overlayNode(row),
    ),
    node(
      "div",
      { class: "card-actions" },
      node("button", {
        type: "button",
        class: "btn btn-primary btn-sm",
        text: "Open in calculator",
        onclick: () => window.AivssCalculator.openExample(row.asi),
      }),
      node("button", {
        type: "button",
        class: "btn btn-card btn-sm",
        text: "Full report",
        onclick: () => showDetail(row.asi),
      }),
    ),
  );
}

function renderCards(data) {
  const key = sortBy.value;
  const sorted = [...data].sort((a, b) => {
    if (key === "asi") return a.asi.localeCompare(b.asi);
    if (key === "class") return a.agentic_effect_class.localeCompare(b.agentic_effect_class);
    return (b.aivss ?? -1) - (a.aivss ?? -1);
  });
  grid.replaceChildren(...sorted.map(card));
}

async function loadTop10() {
  grid.replaceChildren(node("p", { class: "loading", text: "Loading OWASP Agentic Top 10 scores…" }));
  rows = await fetchJson("/api/top10", "data/top10.json");
  if (!Array.isArray(rows) || rows.length === 0) {
    throw new Error("No ASI scenarios returned");
  }
  renderCards(rows);
}

function hideDetail() {
  detail.classList.add("hidden");
  detailBody.replaceChildren();
  document.body.style.overflow = "";
}

function meta(label, value) {
  return node("span", {}, node("strong", { text: `${label}: ` }), value);
}

async function showDetail(asi) {
  detail.classList.remove("hidden");
  document.body.style.overflow = "hidden";
  detailTitle.textContent = `${asi} — Full Assessment`;
  detailBody.replaceChildren(node("p", { class: "loading", text: "Loading report…" }));

  let payload;
  try {
    payload = await fetchJson(
      `/api/scenario/${encodeURIComponent(asi)}`,
      `data/${asi.toLowerCase()}.json`,
    );
  } catch (err) {
    detailBody.replaceChildren(node("p", { class: "error", text: `Failed to load ${asi}: ${err.message}` }));
    return;
  }

  const report = payload.report;
  if (!report?.scores) {
    detailBody.replaceChildren(node("p", { class: "error", text: `Invalid report payload for ${asi}.` }));
    return;
  }

  const decision = report.decision ?? {};
  const ssvc = decision.ssvc;
  const bodLabel = decision.bod_2604_analogy_label || decision.bod_2604_label || "—";
  const metaRow = node(
    "div",
    { class: "detail-meta" },
    meta("AIVSS", `${formatScore(report.scores.aivss)} ${report.scores.aivss_band}`),
    meta(report.scores.cvss_nomenclature, formatScore(report.scores.cvss_bte)),
    meta("Effect class", report.scores.agentic_effect_class ?? "—"),
    meta("U", String(report.scores.agentic_uplift_u ?? "—")),
    meta("BOD analogy", bodLabel),
    decision.escalated && decision.aivss_recommended_label
      ? meta("Overlay", decision.aivss_recommended_label)
      : null,
  );
  const ssvcRow = ssvc
    ? node(
        "div",
        { class: "detail-ssvc" },
        node("strong", { text: "SSVC decision table: " }),
        node("code", { text: ssvc.decision_table }),
        " · outcomes ",
        node("code", { text: ssvc.outcome_namespace }),
      )
    : null;
  detailBody.replaceChildren(
    metaRow,
    ssvcRow ?? "",
    node("pre", { text: JSON.stringify(report, null, 2) }),
  );
}

sortBy.addEventListener("change", () => renderCards(rows));
closeDetailBtn.addEventListener("click", hideDetail);
detail.addEventListener("click", (e) => {
  if (e.target === detail) hideDetail();
});
document.addEventListener("keydown", (e) => {
  if (e.key === "Escape" && !detail.classList.contains("hidden")) hideDetail();
});

loadTop10().catch((err) => {
  grid.replaceChildren(
    node("p", { class: "error", text: `Failed to load examples: ${err.message}. Run aivss-calc demo.` }),
  );
});
