// AIVSS calculation engine.
//
// Runs the reference Python package (aivss_calc) in the browser with Pyodide,
// so the page and the CLI share one implementation. The rest of the page only
// talks to window.AivssEngine.{ready, catalog, calculate}.
(function () {
  let enginePromise = null;

  function loadScript(src) {
    return new Promise((resolve, reject) => {
      const script = document.createElement("script");
      script.src = src;
      script.onload = resolve;
      script.onerror = () => reject(new Error(`Could not load ${src}`));
      document.head.appendChild(script);
    });
  }

  async function fetchOk(path) {
    const res = await fetch(path);
    if (!res.ok) throw new Error(`HTTP ${res.status} for ${path}`);
    return res;
  }

  async function boot(onStatus) {
    onStatus("Loading calculator runtime…");
    const manifest = await (await fetchOk("py/manifest.json")).json();
    await loadScript(`${manifest.pyodide_index_url}pyodide.js`);
    const pyodide = await window.loadPyodide({ indexURL: manifest.pyodide_index_url });

    onStatus("Installing AIVSS calculator…");
    await pyodide.loadPackage("micropip");
    await pyodide.pyimport("micropip").install(manifest.packages);
    const bundle = await (await fetchOk(manifest.bundle)).arrayBuffer();
    pyodide.unpackArchive(bundle, "zip");

    const handle = pyodide.runPython(
      "from aivss_calc.api import handle_web_request\nhandle_web_request",
    );
    const call = (request) => {
      const response = JSON.parse(handle(JSON.stringify(request)));
      if (!response.ok) throw new Error(response.error);
      return response.result;
    };
    return { call, manifest, catalog: call({ op: "catalog" }) };
  }

  window.AivssEngine = {
    ready(onStatus = () => {}) {
      if (!enginePromise) {
        enginePromise = boot(onStatus).catch((err) => {
          enginePromise = null;
          throw err;
        });
      }
      return enginePromise;
    },
    async calculate(request) {
      const engine = await this.ready();
      return engine.call({ op: "calculate", ...request });
    },
  };
})();
