// Run with the project's installed Playwright available on NODE_PATH.
// Isolated real-component layout regression; no live API or database access.
const { chromium } = require('playwright');
const { createRequire } = require('node:module');
const path = require('node:path');
const assert = require('node:assert/strict');
const root = path.resolve(__dirname, '..');
const requireUI = createRequire(path.join(root, 'package.json'));

(async () => {
  const { createServer } = await import(requireUI.resolve('vite'));
  const entry = `import { createApp, h } from 'vue';
    import DataTable from '/src/components/DataTable.vue'; import '/src/styles.css';
    createApp({render:()=>h(DataTable,{
      columns:[{key:'name',label:'Database'},{key:'site',label:'Site'},{key:'state',label:'State'}],
      rows:[{id:'fixture',name:'layout_database',site:'site-'+ 'a'.repeat(64),state:'active'}],
      actions:[{id:'console',label:'Open console',operation:'database.console.issue'}]
    })}).mount('#app');`;
  const server = await createServer({ root, server: { host: '127.0.0.1', port: 0 }, plugins: [{
    name: 'table-layout-fixture',
    resolveId(id) { if (id === '/fixture-entry.js') return root + '/fixture-entry.js'; },
    load(id) { if (id === root + '/fixture-entry.js') return entry; },
    configureServer(instance) {
      instance.middlewares.use((req, res, next) => {
        if (req.url !== '/layout') return next();
        res.setHeader('Content-Type', 'text/html');
        res.end('<!doctype html><html><head><meta name="viewport" content="width=device-width, initial-scale=1"></head><body><div id="app"></div><script type="module" src="/fixture-entry.js"></script></body></html>');
      });
    }
  }] });
  await server.listen();
  const browser = await chromium.launch({ headless: true });
  try {
    const page = await browser.newPage({ viewport: { width: 1366, height: 900 } });
    await page.goto(server.resolvedUrls.local[0] + 'layout');
    await page.getByLabel('Resource actions', { exact: true }).click();
    for (const width of [1366, 390]) {
      await page.setViewportSize({ width, height: 900 });
      const dimensions = await page.evaluate(() => {
        window.scrollTo(9999, 0);
        const wrapper = document.querySelector('.table-wrap');
        return { viewport: innerWidth, document: document.documentElement.scrollWidth, scrollX, tableViewport: wrapper.clientWidth, tableContent: wrapper.scrollWidth };
      });
      console.log(JSON.stringify(dimensions));
      assert.equal(dimensions.document, width, 'table must not expand page scroll extent');
      assert.equal(dimensions.scrollX, 0, 'page must not scroll into blank space');
      if (width === 390) {
        assert(dimensions.tableContent > dimensions.tableViewport, 'wide table remains locally scrollable');
        await page.locator('.table-wrap').evaluate(element => { element.scrollLeft = element.scrollWidth; });
        const menu = await page.getByRole('button', { name: 'Open console', exact: true }).boundingBox();
        assert(menu && menu.x >= 0 && menu.x + menu.width <= width, 'row menu remains inside viewport');
      }
    }
  } finally { await browser.close(); await server.close(); }
})().catch(error => { console.error(error); process.exitCode = 1; });
