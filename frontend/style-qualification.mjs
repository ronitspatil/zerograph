import { readFile, writeFile } from "node:fs/promises";
import { createServer } from "node:http";
import { chromium } from "../deploy/browser/node_modules/playwright/index.mjs";

// CSS-only fixture: representative existing selectors and native controls, no auth data.
const fixture = `<!doctype html><html><head><link rel="stylesheet" href="/style.css"></head><body>
<div class="app-shell"><aside class="sidebar"><nav><button class="nav-item active">Overview</button></nav></aside>
<main class="main-content"><h1>Security overview</h1><h2>Access graph</h2><h3>Data source</h3><p>Fixture description</p>
<section class="panel"><div class="panel-heading"><h2>Panel</h2></div>
<button id="primary" class="button button-primary">Primary</button>
<button class="button button-outline">Outline</button><button class="button button-ghost button-small">Ghost</button>
<button class="button button-primary" disabled>Disabled</button><a class="button button-primary" href="#">Link button</a>
<div class="form-panel"><label>Inventory<input placeholder="Inventory"></label>
<label>JSON<textarea placeholder="JSON inventory">Fixture</textarea></label>
<label>Source<select><option>Snapshot</option></select></label>
<label>Date<input type="date" value="2026-10-02"></label>
<label class="checkbox-row"><input type="checkbox">Complete coverage</label></div>
<div class="graph-toolbar"><div class="search-field"><input placeholder="Search"></div></div>
<input id="hops" type="range" min="1" max="5" value="3">
<span class="pill green">confirmed</span><span class="pill amber">conditional</span>
<table><thead><tr><th>Source</th><th>Status</th></tr></thead><tbody><tr><td>snapshot</td><td>completed</td></tr></tbody></table>
<div class="graph-panel"><div class="graph-canvas"></div></div></section></main></div>
<main class="login-shell"><div class="login-card"><h1>Every identity.</h1><p>Sign in</p><a class="button button-primary" href="#">Organization</a></div></main>
</body></html>`;
const selectors = [
  "body",
  "h1",
  "h2",
  "h3",
  "p",
  ".sidebar",
  ".nav-item",
  ".panel",
  ".panel-heading",
  "#primary",
  ".button-outline",
  ".button-ghost",
  "button:disabled",
  "a.button",
  ".form-panel label",
  ".form-panel input",
  ".form-panel textarea",
  ".form-panel select",
  "input[type=date]",
  "input[type=checkbox]",
  ".search-field input",
  "#hops",
  ".pill.green",
  ".pill.amber",
  "table",
  "th",
  "td",
  ".graph-canvas",
  ".login-shell",
  ".login-card",
  ".login-card h1",
];
const properties = [
  "font-family",
  "font-size",
  "font-weight",
  "line-height",
  "letter-spacing",
  "color",
  "background-color",
  "border-width",
  "border-color",
  "border-style",
  "border-radius",
  "padding",
  "margin",
  "width",
  "height",
  "display",
  "position",
  "box-shadow",
  "outline-width",
  "outline-style",
  "outline-color",
  "outline-offset",
  "opacity",
  "cursor",
  "appearance",
  "accent-color",
  "resize",
  "text-align",
  "text-decoration-line",
];

const [baselineFile, migratedFile, resultFile] = process.argv.slice(2);
if (!baselineFile || !migratedFile || !resultFile)
  throw new Error("Provide baseline CSS, migrated CSS and result paths");
const styles = [
  await readFile(baselineFile, "utf8"),
  await readFile(migratedFile, "utf8"),
];
let activeStyle = 0;
const server = createServer((request, response) => {
  response.setHeader(
    "Content-Type",
    request.url === "/style.css" ? "text/css" : "text/html",
  );
  response.end(request.url === "/style.css" ? styles[activeStyle] : fixture);
});
await new Promise((resolve, reject) => {
  server.once("error", reject);
  server.listen(0, "127.0.0.1", resolve);
});
let browser;
try {
  browser = await chromium.launch({
    headless: true,
    executablePath: process.env.ZG_STYLE_CHROME || undefined,
  });
  const comparisons = [];
  for (const width of [1440, 390]) {
    const captures = [];
    for (activeStyle = 0; activeStyle < 2; activeStyle++) {
      const page = await browser.newPage({ viewport: { width, height: 1000 } });
      await page.goto(`http://127.0.0.1:${server.address().port}/`, {
        waitUntil: "networkidle",
        timeout: 15000,
      });
      const capture = await page.evaluate(
        ({ selectors, properties }) =>
          Object.fromEntries(
            selectors.map((selector) => {
              const element = document.querySelector(selector);
              if (!element) throw new Error("Missing style fixture selector");
              const style = getComputedStyle(element);
              return [
                selector,
                Object.fromEntries(
                  properties.map((property) => [
                    property,
                    style.getPropertyValue(property),
                  ]),
                ),
              ];
            }),
          ),
        { selectors, properties },
      );
      for (const selector of [
        ".form-panel input",
        ".form-panel textarea",
        ".search-field input",
      ]) {
        capture[selector + "::placeholder"] = await page
          .locator(selector)
          .first()
          .evaluate((element) => {
            const style = getComputedStyle(element, "::placeholder");
            return { color: style.color, opacity: style.opacity };
          });
      }
      await page.keyboard.press("Tab");
      await page.locator("#primary").focus();
      capture["#primary:focus-visible"] = await page
        .locator("#primary")
        .evaluate((element) => {
          const style = getComputedStyle(element);
          return { outline: style.outline, outlineOffset: style.outlineOffset };
        });
      captures.push(capture);
      await page.close();
    }
    const differences = [];
    let checked = 0;
    for (const [selector, values] of Object.entries(captures[0])) {
      for (const [property, before] of Object.entries(values)) {
        checked++;
        const after = captures[1][selector][property];
        if (before !== after)
          differences.push({ selector, property, before, after });
      }
    }
    comparisons.push({ width, checked, differences });
  }
  await writeFile(
    resultFile,
    JSON.stringify({ browser: browser.version(), comparisons }, null, 2) + "\n",
  );
  console.log(
    JSON.stringify(
      comparisons.map(({ width, checked, differences }) => ({
        width,
        checked,
        differences: differences.length,
      })),
    ),
  );
  process.exitCode = comparisons.some((item) => item.differences.length)
    ? 1
    : 0;
} finally {
  if (browser) await browser.close();
  await new Promise((resolve) => server.close(resolve));
}
