// Interactive AIVSS calculator: metric form, presets, share links, results.
// All scoring is delegated to window.AivssEngine (the Python reference code).
// Text is always inserted with textContent, never as HTML.
(function () {
  const BASE_GROUPS = [
    ["Exploitability", ["AV", "AC", "AT", "PR", "UI"]],
    ["Vulnerable system impact", ["VC", "VI", "VA"]],
    ["Subsequent system impact", ["SC", "SI", "SA"]],
  ];
  const DECISION_BASIS = {
    cisa_bod_26_04: "BOD 26-04 compliance deadline",
    informative_bod_26_04_cve_guidance: "BOD 26-04 guidance for a CVE (informative)",
    informative_bod_26_04_analogy: "BOD 26-04 analogy for a non-CVE finding (informative)",
  };
  // Plain-language hints for the most common incomplete-input errors.
  const DECISION_HINTS = [
    ["publicly_exposed must be", "Choose whether the asset is publicly exposed."],
    ["publicly_exposed_source must be", "Enter where the exposure information comes from."],
    ["cisa_kev must be explicitly", "Answer whether the CVE is listed in CISA KEV."],
    ["KEV-listed CVEs require", "Choose Automatable and Technical impact (the CISA Vulnrichment values)."],
    ["automatable is required", "Choose whether exploitation is automatable."],
    ["technical_impact is required", "Choose the technical impact."],
  ];
  const DECISION_KEYS = {
    publicly_exposed: "pe",
    automatable: "au",
    technical_impact: "ti",
    evidence: "ev",
    kev: "kev",
  };

  const $ = (id) => document.getElementById(id);
  const state = {
    cvss: {},
    supplemental: [],
    aivss: {},
    legacyVector: null,
    decision: emptyDecision(),
    presetId: null,
    edited: false,
  };
  let catalog = null;
  let calcSeq = 0;
  let calcTimer = null;

  function emptyDecision() {
    return {
      enabled: false,
      publicly_exposed: null,
      automatable: null,
      technical_impact: null,
      evidence: "none",
      kev: null,
      source: "",
      cve: "",
      fceb: false,
    };
  }

  function el(tag, props = {}, ...children) {
    const node = document.createElement(tag);
    for (const [key, value] of Object.entries(props)) {
      if (value === undefined || value === null) continue;
      if (key === "class") node.className = value;
      else if (key === "hint") window.AivssHints.attach(node, value);
      else if (key === "text") node.textContent = value;
      else if (key.startsWith("on")) node.addEventListener(key.slice(2), value);
      else node.setAttribute(key, value);
    }
    for (const child of children) {
      if (child !== null && child !== undefined) {
        node.append(child instanceof Node ? child : String(child));
      }
    }
    return node;
  }

  // ── CVSS metric metadata ──
  function cvssOrder() {
    const m = catalog.cvss_metrics;
    return [m.base, m.threat, m.requirements, m.modified].flatMap(Object.keys);
  }

  function cvssInfo(metric) {
    return catalog.cvss_metric_info[metric];
  }

  function isBase(metric) {
    return Boolean(catalog.cvss_metrics.base[metric]);
  }

  // ── Vectors ──
  function cvssVector() {
    const parts = cvssOrder()
      .filter((metric) => state.cvss[metric] && (isBase(metric) || state.cvss[metric] !== "X"))
      .map((metric) => `${metric}:${state.cvss[metric]}`);
    return ["CVSS:4.0", ...parts, ...state.supplemental].join("/");
  }

  function agenticOrder() {
    return [...catalog.rubric.classifying_metrics, ...catalog.rubric.uplift_metrics];
  }

  function aivssVector() {
    const order = agenticOrder();
    const parts = order.map((metric) => `${metric}:${state.aivss[metric] ?? "?"}`);
    return [`AIVSS:${catalog.versions.spec}`, ...parts].join("/");
  }

  function parseVector(text, prefix) {
    const parts = text.trim().split("/");
    if (parts[0] !== prefix) throw new Error(`Vector must begin with ${prefix}`);
    return parts.slice(1).map((part) => {
      const [key, value] = part.split(":");
      return [key, value];
    });
  }

  function applyVectors(cvssText, aivssText) {
    const known = new Set(cvssOrder());
    state.cvss = {};
    state.supplemental = [];
    for (const [key, value] of parseVector(cvssText, "CVSS:4.0")) {
      if (known.has(key)) state.cvss[key] = value;
      else state.supplemental.push(`${key}:${value}`);
    }
    // A draft eight-metric vector is mapped to the five-metric form: EX becomes
    // ES, and SR, PT, CA and TD are dropped.
    const parsed = Object.fromEntries(parseVector(aivssText, `AIVSS:${catalog.versions.spec}`));
    const legacy = ["EX", "PT", "CA", "TD"].some((key) => key in parsed);
    // Keep the draft vector so the engine can report the migration it implies.
    state.legacyVector = legacy ? aivssText.trim() : null;
    if (legacy) {
      if (parsed.EX && !parsed.ES) parsed.ES = parsed.EX;
    }
    state.aivss = Object.fromEntries(
      agenticOrder().filter((m) => parsed[m]).map((m) => [m, parsed[m]]),
    );
  }

  function missingMetrics() {
    const base = Object.keys(catalog.cvss_metrics.base).filter((m) => !state.cvss[m]);
    const aivss = agenticOrder().filter((m) => !state.aivss[m]);
    return { base, aivss };
  }

  // ── Form rendering ──
  function optionButton(label, code, pressed, hint, onClick) {
    return el(
      "button",
      {
        type: "button",
        class: "opt",
        "aria-pressed": String(pressed),
        hint,
        onclick: onClick,
      },
      el("span", { class: "opt-label", text: label }),
      el("span", { class: "opt-code", text: code }),
    );
  }

  function metricGroup({ name, code, summary, options, description }) {
    return el(
      "div",
      { class: "metric-group" },
      el(
        "span",
        { class: "metric-name", hint: summary },
        name,
        " ",
        el("abbr", { text: code }),
      ),
      el("div", { class: "options", role: "group", "aria-label": name }, ...options),
      description ? el("p", { class: "metric-desc", text: description }) : null,
    );
  }

  function cvssGroup(metric) {
    const info = cvssInfo(metric);
    // Optional groups show "Not Defined" (X) as selected until a value is picked.
    const current = state.cvss[metric] ?? (isBase(metric) ? null : "X");
    const options = Object.entries(info.values).map(([code, value]) =>
      optionButton(value.label, code, current === code, value.summary, () => {
        state.cvss[metric] = code;
        changed();
      }),
    );
    return metricGroup({
      name: info.name,
      code: metric,
      summary: info.summary,
      options,
      description: current ? info.values[current].summary : "Not selected yet.",
    });
  }

  function aivssGroup(metric) {
    const values = catalog.rubric.metrics[metric];
    const selected = state.aivss[metric];
    const options = Object.entries(values).map(([code, info]) =>
      optionButton(info.label, code, selected === code, info.summary, () => {
        state.aivss[metric] = code;
        changed();
      }),
    );
    return metricGroup({
      name: catalog.metric_names[metric],
      code: metric,
      summary: catalog.metric_summaries[metric],
      options,
      description: selected && values[selected] ? values[selected].summary : "Not selected yet.",
    });
  }

  function subgroup(title, metrics, render) {
    return el(
      "div",
      { class: "metric-subgroup" },
      el("h4", { class: "subgroup-title", text: title }),
      ...metrics.map(render),
    );
  }

  function panelNote(containerId, text) {
    const container = $(containerId);
    const panel = container.parentElement;
    let note = panel.querySelector(".panel-note.group-note");
    if (!note) {
      note = el("p", { class: "panel-note group-note" });
      panel.insertBefore(note, container);
    }
    note.textContent = text;
  }

  function renderForm() {
    const m = catalog.cvss_metrics;
    panelNote("cvss-base", catalog.cvss_groups.base.summary);
    panelNote("cvss-threat", catalog.cvss_groups.threat.summary);
    panelNote("cvss-env", catalog.cvss_groups.environmental.summary);
    $("cvss-base").replaceChildren(
      ...BASE_GROUPS.map(([title, metrics]) => subgroup(title, metrics, cvssGroup)),
    );
    $("cvss-threat").replaceChildren(...Object.keys(m.threat).map(cvssGroup));
    const modified = Object.keys(m.modified);
    $("cvss-env").replaceChildren(
      subgroup("Security requirements", Object.keys(m.requirements), cvssGroup),
      subgroup("Modified exploitability", modified.slice(0, 5), cvssGroup),
      subgroup("Modified vulnerable system impact", modified.slice(5, 8), cvssGroup),
      subgroup("Modified subsequent system impact", modified.slice(8), cvssGroup),
    );
    $("aivss-classifying").replaceChildren(...catalog.rubric.classifying_metrics.map(aivssGroup));
    $("aivss-uplift").replaceChildren(...catalog.rubric.uplift_metrics.map(aivssGroup));
    renderDecisionForm();
    renderPresets();
    $("cvss-input").value = cvssVector();
    $("aivss-input").value = aivssVector();
  }

  function renderDecisionForm() {
    const d = state.decision;
    $("decision-enabled").checked = d.enabled;
    $("decision-fields").hidden = !d.enabled;
    $("exposure-source").value = d.source;
    $("cve-id").value = d.cve;
    $("fceb-scope").checked = d.fceb;
    if (d.cve || d.kev !== null || d.fceb) $("decision-panel").querySelector(".cve-details").open = true;
    for (const container of document.querySelectorAll("[data-decision]")) {
      const key = container.dataset.decision;
      const info = catalog.decision_inputs[key] ?? {};
      const choices = container.dataset.choices.split(",").map((c) => c.split(":"));
      container.replaceChildren(
        ...choices.map(([value, label]) =>
          el(
            "button",
            {
              type: "button",
              class: "opt",
              "aria-pressed": String(d[key] === value),
              hint: info.values?.[value],
              onclick: () => {
                d[key] = d[key] === value && key !== "evidence" ? null : value;
                changed();
              },
            },
            el("span", { class: "opt-label", text: label }),
          ),
        ),
      );
      const group = container.closest(".metric-group");
      const name = group.querySelector(".metric-name");
      if (info.summary) window.AivssHints.attach(name, info.summary);
      let description = group.querySelector(".metric-desc");
      if (!description) {
        description = el("p", { class: "metric-desc" });
        group.append(description);
      }
      description.textContent = info.values?.[d[key]] ?? "Not selected yet.";
    }
  }

  function renderPresets() {
    const active = state.edited ? null : state.presetId;
    $("preset-list").replaceChildren(
      ...catalog.presets.map((preset) =>
        el(
          "button",
          {
            type: "button",
            class: "preset",
            "aria-pressed": String(preset.id === active),
            hint: `${preset.name} — ${preset.title}`,
            onclick: () => loadPreset(preset.id),
          },
          el("span", { class: "preset-id", text: preset.id }),
          el("span", { class: "preset-name", text: preset.name }),
        ),
      ),
    );
    const status = $("preset-status");
    const preset = catalog.presets.find((p) => p.id === state.presetId);
    if (!preset) status.textContent = state.edited ? "Custom finding" : "";
    else if (state.edited) status.textContent = `Custom — edited from ${preset.id}`;
    else status.textContent = `${preset.id}: ${preset.title}`;
  }

  // ── State changes ──
  function changed({ fromPreset = false } = {}) {
    if (!fromPreset) state.edited = true;
    renderForm();
    writeUrl();
    scheduleCalculate();
  }

  function loadPreset(id) {
    const preset = catalog.presets.find((p) => p.id === id);
    if (!preset) return;
    applyVectors(preset.cvss_vector, preset.aivss_vector);
    const evidence = Object.keys(preset.evidence).find((k) => preset.evidence[k]) || "none";
    state.decision = {
      ...emptyDecision(),
      enabled: true,
      publicly_exposed: String(preset.publicly_exposed),
      automatable: String(preset.automatable),
      technical_impact: preset.technical_impact,
      evidence,
      source: "synthetic deployment inventory fixture",
    };
    state.presetId = id;
    state.edited = false;
    hideError("vector-error");
    changed({ fromPreset: true });
  }

  function writeUrl() {
    const params = new URLSearchParams();
    if (state.presetId && !state.edited) {
      params.set("example", state.presetId);
    } else {
      params.set("cvss", cvssVector());
      params.set("aivss", aivssVector());
      const d = state.decision;
      if (d.enabled) {
        params.set("rt", "1");
        for (const [key, short] of Object.entries(DECISION_KEYS)) {
          if (d[key] !== null && !(key === "evidence" && d[key] === "none")) params.set(short, d[key]);
        }
        if (d.source) params.set("src", d.source);
        if (d.cve) params.set("cve", d.cve);
        if (d.fceb) params.set("fceb", "1");
      }
    }
    const query = params.toString().replace(/%2F/g, "/").replace(/%3A/g, ":");
    history.replaceState(null, "", `${location.pathname}?${query}${location.hash}`);
  }

  function readUrl() {
    const params = new URLSearchParams(location.search);
    const example = params.get("example");
    if (example && catalog.presets.some((p) => p.id === example.toUpperCase())) {
      loadPreset(example.toUpperCase());
      return true;
    }
    if (!params.get("cvss") || !params.get("aivss")) return false;
    try {
      applyVectors(params.get("cvss"), params.get("aivss"));
    } catch (err) {
      showError("vector-error", `Could not load vectors from the link: ${err.message}`);
      return false;
    }
    const d = emptyDecision();
    d.enabled = params.get("rt") === "1";
    for (const [key, short] of Object.entries(DECISION_KEYS)) {
      if (params.has(short)) d[key] = params.get(short);
    }
    d.source = params.get("src") || "";
    d.cve = params.get("cve") || "";
    d.fceb = params.get("fceb") === "1";
    state.decision = d;
    state.presetId = null;
    state.edited = true;
    changed();
    return true;
  }

  // ── Calculation ──
  function decisionRequest() {
    const d = state.decision;
    if (!d.enabled) return null;
    const bool = (value) => (value === null ? null : value === "true");
    const hasCve = d.cve.trim() !== "";
    const request = {
      publicly_exposed: bool(d.publicly_exposed),
      publicly_exposed_source: d.source.trim() || null,
      decision_data_observed_at: new Date().toISOString().replace(/\.\d+Z$/, "Z"),
      evidence: { poc: d.evidence === "poc", observed_local: d.evidence === "observed_local" },
    };
    if (hasCve) {
      request.cve_id = d.cve.trim();
      request.evidence.cisa_kev = bool(d.kev);
      request.fceb_bod_2604_scope = d.fceb;
    }
    if (hasCve && d.kev === "true") {
      request.vulnrichment_automatable = bool(d.automatable);
      request.vulnrichment_technical_impact = d.technical_impact;
    } else {
      request.automatable = bool(d.automatable);
      request.technical_impact = d.technical_impact;
    }
    return request;
  }

  function scheduleCalculate() {
    clearTimeout(calcTimer);
    calcTimer = setTimeout(calculate, 60);
  }

  async function calculate() {
    const seq = ++calcSeq;
    const missing = missingMetrics();
    const problems = [];
    if (missing.base.length) problems.push(`CVSS Base metrics: ${missing.base.join(", ")}`);
    if (missing.aivss.length) problems.push(`Agentic AI metrics: ${missing.aivss.join(", ")}`);
    if (problems.length) {
      $("result").hidden = true;
      showError("result-error", `Select the remaining metrics — ${problems.join("; ")}.`);
      return;
    }
    let result;
    try {
      result = await window.AivssEngine.calculate({
        cvss_vector: cvssVector(),
        aivss_vector: aivssVector(),
        migrated_from: state.legacyVector,
        decision: decisionRequest(),
      });
    } catch (err) {
      if (seq !== calcSeq) return;
      $("result").hidden = true;
      showError("result-error", err.message);
      return;
    }
    if (seq !== calcSeq) return;
    hideError("result-error");
    renderResult(result);
  }

  function renderResult(result) {
    const p = result.profile;
    $("result").hidden = false;
    $("result-score").textContent = p.aivss.toFixed(1);
    const rating = $("result-rating");
    rating.textContent = p.severity_rating;
    rating.className = `rating rating-${p.severity_rating.toLowerCase()}`;
    $("result-bar").style.width = `${p.aivss * 10}%`;
    const cls = $("result-class");
    cls.textContent = p.agentic_effect_class;
    cls.className = `class-pill class-${p.agentic_effect_class}`;
    $("result-class-label").textContent = catalog.effect_classes[p.agentic_effect_class];
    $("result-class-status").textContent =
      `Effect Class status: ${p.agentic_effect_class_status}. It selects the Table 6 column; ` +
      `AIVSS is never lower than ${p.cvss_nomenclature} (${ruleText(p.rule)}).`;
    $("result-cvss-label").textContent = p.cvss_nomenclature;
    $("result-cvss").textContent = p.cvss_bte.toFixed(1);
    $("result-cvss-band").textContent = p.cvss_band;
    $("result-u").textContent = p.agentic_uplift_u ?? "—";
    const provisional = $("result-provisional");
    provisional.hidden = !p.provisional;
    provisional.textContent = p.provisional
      ? "Provisional: at least one of LC, CP, AP or RH is X (insufficient evidence). Resolve it before publishing."
      : "";
    const migration = $("result-migration");
    migration.hidden = !p.migration;
    migration.textContent = p.migration ? p.migration.note : "";
    $("result-macrovector").textContent = p.macrovector;
    $("out-cvss").textContent = p.cvss_vector;
    $("out-aivss").textContent = p.aivss_vector;
    renderDecision(result);
    $("result-json").textContent = JSON.stringify(result, null, 2);
  }

  function ruleText(rule) {
    if (rule === "cell") return "the Table 6 cell applies";
    if (rule === "cvss_bte_floor") return "the CVSS-BTE floor applies";
    return "A0 or AX keep CVSS-BTE unchanged";
  }

  function decisionHint(message) {
    const hint = DECISION_HINTS.find(([prefix]) => message.startsWith(prefix));
    return hint ? hint[1] : `Inputs incomplete: ${message}`;
  }

  function fact(label, hint, ...value) {
    return el(
      "div",
      { class: "decision-row" },
      el("dt", { text: label, hint }),
      el("dd", {}, ...value),
    );
  }

  function renderDecision(result) {
    const box = $("decision-result");
    if (!state.decision.enabled) {
      box.replaceChildren(
        el("p", { class: "muted small", text: "Enable the remediation timeline to add the Conformance Level 2 SSVC / BOD 26-04 decision." }),
      );
      return;
    }
    if (result.decision_error) {
      box.replaceChildren(
        el("h4", { class: "decision-title", text: "Remediation timeline" }),
        el("p", { class: "inline-error", text: decisionHint(result.decision_error) }),
      );
      return;
    }
    const d = result.decision;
    const baselineKey = d.bod_2604_timeline || d.bod_2604_guidance_timeline || d.bod_2604_analogy_timeline;
    const baselineLabel = d.bod_2604_label || d.bod_2604_guidance_label || d.bod_2604_analogy_label;
    let overlay;
    if (!d.aivss_recommended_timeline) {
      overlay = `Not computed (${d.overlay_status}).`;
    } else if (d.overlay_status === "provisional") {
      overlay = "Provisional: the Effect Class is AX, so the A2 overlay cannot trigger.";
    } else if (d.escalated) {
      overlay = "Escalated one tier because the Effect Class is A2.";
    } else if (d.overlay_triggered) {
      overlay = "A2 overlay triggered, but the baseline is already at the 3-day ceiling.";
    } else {
      overlay = "No escalation (Effect Class is not A2).";
    }
    const rows = [
      fact(
        "BOD 26-04 baseline",
        catalog.result_info.bod_baseline,
        el("span", { class: "timeline-key", text: baselineKey }),
        ` ${baselineLabel}`,
        el("span", { class: "muted small block", text: DECISION_BASIS[d.decision_basis] || d.decision_basis }),
      ),
      fact(
        "AIVSS recommendation",
        catalog.result_info.aivss_recommendation,
        d.aivss_recommended_timeline
          ? el("span", { class: "timeline-key accent", text: d.aivss_recommended_timeline })
          : null,
        d.aivss_recommended_timeline ? ` ${d.aivss_recommended_label}` : null,
        el("span", { class: "muted small block", text: `${overlay} Overlay status: ${d.overlay_status}.` }),
      ),
      fact(
        "Exploitation evidence",
        catalog.decision_inputs.evidence.summary,
        d.exploitation.rationale,
      ),
    ];
    const notes = [el("p", { class: "muted small", text: d.note })];
    if (d.missing_metadata_faq_applied) {
      notes.push(
        el("p", {
          class: "muted small",
          text: "CISA's missing-metadata rule was applied: Automatable no and Technical Impact total.",
        }),
      );
    }
    const tableId = d.ssvc?.decision_table || d.bod_2604_decision_table;
    if (tableId) {
      const source = d.ssvc?.decision_table_source || d.bod_2604_model_source;
      notes.push(
        el(
          "p",
          { class: "muted small" },
          "Decision table: ",
          source
            ? el("a", { href: source, target: "_blank", rel: "noopener" }, el("code", { text: tableId }))
            : el("code", { text: tableId }),
          " (CERT/CC SSVC, CISA BOD 26-04).",
        ),
      );
    }
    box.replaceChildren(
      el("h4", { class: "decision-title", text: "Remediation timeline" }),
      el("dl", { class: "decision-facts" }, ...rows),
      ...notes,
    );
  }

  // ── Small helpers ──
  function showError(id, message) {
    const node = $(id);
    node.textContent = message;
    node.hidden = false;
  }

  function hideError(id) {
    $(id).hidden = true;
  }

  async function copyText(text, button) {
    try {
      await navigator.clipboard.writeText(text);
      const original = button.textContent;
      button.textContent = "Copied";
      setTimeout(() => { button.textContent = original; }, 1500);
    } catch {
      window.prompt("Copy this:", text);
    }
  }

  function applyStaticHints() {
    const inputs = catalog.decision_inputs;
    const results = catalog.result_info;
    const hint = (selector, text) => {
      window.AivssHints.attach(document.querySelector(selector), text);
    };
    hint("#decision-enabled ~ span", inputs.enabled.summary);
    hint("#exposure-source", inputs.publicly_exposed_source.summary);
    hint('label:has(> #exposure-source) .field-label', inputs.publicly_exposed_source.summary);
    hint("#cve-id", inputs.cve_id.summary);
    hint('label:has(> #cve-id) .field-label', inputs.cve_id.summary);
    hint("#fceb-scope ~ span", inputs.fceb_bod_2604_scope.summary);
    hint(".result-card .score-label", results.severity);
    hint("#result-rating", results.severity_rating);
    hint(".result-facts div:nth-child(1) dt", results.effect_class);
    hint(".result-facts div:nth-child(2) dt", results.cvss_bte);
    hint(".result-facts div:nth-child(3) dt", results.uplift);
    hint(".result-facts div:nth-child(4) dt", results.macrovector);
    hint("#result-class", results.effect_class);
    hint("#result-macrovector", results.macrovector);
  }

  function bindStaticControls() {
    $("vector-form").addEventListener("submit", async (event) => {
      event.preventDefault();
      const cvss = $("cvss-input").value.trim();
      const aivss = $("aivss-input").value.trim();
      try {
        await window.AivssEngine.calculate({ cvss_vector: cvss, aivss_vector: aivss, decision: null });
        applyVectors(cvss, aivss);
      } catch (err) {
        showError("vector-error", err.message);
        return;
      }
      hideError("vector-error");
      state.presetId = null;
      changed();
    });
    $("decision-enabled").addEventListener("change", (event) => {
      state.decision.enabled = event.target.checked;
      changed();
    });
    $("fceb-scope").addEventListener("change", (event) => {
      state.decision.fceb = event.target.checked;
      changed();
    });
    for (const [id, key] of [["exposure-source", "source"], ["cve-id", "cve"]]) {
      $(id).addEventListener("input", (event) => {
        state.decision[key] = event.target.value;
        state.edited = true;
        renderPresets();
        writeUrl();
        scheduleCalculate();
      });
    }
    document.querySelectorAll("[data-copy]").forEach((button) => {
      button.addEventListener("click", () => copyText($(button.dataset.copy).textContent, button));
    });
    $("share-link").addEventListener("click", (event) => {
      const url = new URL(location.href);
      url.hash = "";
      copyText(url.toString(), event.currentTarget);
    });
  }

  async function init() {
    bindStaticControls();
    const status = $("engine-status");
    try {
      const engine = await window.AivssEngine.ready((message) => { status.textContent = message; });
      catalog = engine.catalog;
      applyStaticHints();
    } catch (err) {
      status.textContent = "";
      showError(
        "result-error",
        `The calculator runtime could not load (${err.message}). It needs internet access to fetch Pyodide; the CLI works offline.`,
      );
      $("preset-status").textContent = "Unavailable";
      return;
    }
    status.hidden = true;
    if (!readUrl()) loadPreset(catalog.presets[0].id);
  }

  window.AivssCalculator = {
    async openExample(id) {
      await window.AivssEngine.ready();
      if (!catalog) return;
      loadPreset(id);
      $("calculator").scrollIntoView({ behavior: "smooth" });
    },
  };

  init();
})();
