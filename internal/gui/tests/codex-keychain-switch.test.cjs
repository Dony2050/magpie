// #2367: a successful account switch explains Codex's own next keychain
// prompt. File storage, a failed switch and an unchanged account don't.
const assert = require("node:assert/strict");
const fs = require("node:fs/promises");
const path = require("node:path");
const { test } = require("node:test");
const { chromium, webkit } = require("playwright");

const assets = path.resolve(__dirname, "../assets");
const keys = [
  "Authorize Codex after switching accounts",
  "Magpie asks Codex to read its keychain sign-in after switching. If macOS asks for access to Codex Auth, choose Always Allow to save permission; Allow approves only that request. Later credential updates may require authorization again. A Codex app already running may still need to be quit and reopened to use the new account.",
  "Retry authorization",
  "Waiting for Codex authorization… Choose Always Allow in the macOS prompt.",
  "Codex's keychain permission is saved.",
  "Codex authorization did not finish. Retry, or quit and reopen Codex and choose Always Allow in its macOS prompt. The account switch is kept.",
];

async function open(t, engine, lang, width, keychain = true, fail = false, authMode = "ok") {
  const browser = await (engine === "webkit" ? webkit.launch() : chromium.launch({ channel: "chromium" }));
  t.after(() => browser.close());
  const page = await browser.newPage({ viewport: { width, height: 800 }, reducedMotion: "reduce" });
  page.setDefaultTimeout(5000);
  const errors = [], posts = [];
  page.on("pageerror", (e) => errors.push(e.message));
  let user = "work@example.com";
  let authCount = 0, finishAuth;
  await page.addInitScript(() => {
    const fetchBefore = window.fetch;
    window.fetch = (url, options) => {
      if (String(url).includes("codex/keychain/authorize")) options?.signal?.addEventListener("abort", () => { window.authorizationAborted = true; });
      return fetchBefore(url, options);
    };
  });
  const data = () => ({
    providers: [{
      id: "codex", name: "Codex", icon: "codex-color", chat: "", responses: "", anthropic: "", catalog: "",
      models: [{ id: "gpt-6", name: "GPT-6", on: true }], agents: [], fallback: [], headers: {}, keyList: [],
      account: { agent: "codex", agentName: "Codex", user, plan: "PLUS", ...(keychain == null ? {} : { keychain }),
        logins: ["work@example.com", "spare@example.com"].map((u) => ({ user: u, plan: "PLUS", active: u === user, on: true })) },
    }], presets: [], excluded: [], gateway: { running: true, window: true },
  });
  await page.route("**/*", async (route) => {
    const url = new URL(route.request().url());
    const json = (v) => route.fulfill({ json: v });
    if (url.pathname === "/boot.js") return route.fulfill({ contentType: "text/javascript", body: `window.bootPrefs = {lang:"${lang}",theme:"light",web:true};` });
    if (url.pathname === "/wails/runtime.js") return route.fulfill({ contentType: "text/javascript", body: "export const Window = {};" });
    if (url.pathname === "/api/state") return json({ agents: [], profiles: [], settings: { lang, theme: "light" } });
    if (url.pathname === "/api/providers") return json(data());
    if (route.request().method() === "POST") {
      const body = route.request().postDataJSON();
      posts.push({ path: url.pathname, body });
      if (url.pathname === "/api/codex/keychain/authorize") {
        authCount++;
        if (authMode === "retry" && authCount === 1) return route.fulfill({ status: 400, json: { error: "permission was not saved" } });
        if (authMode === "pending") await new Promise((resolve) => { finishAuth = resolve; });
        return json({ authorized: true }).catch(() => {});
      }
      if (fail) return route.fulfill({ status: 400, json: { error: "The keychain didn't take the sign-in" } });
      if (url.pathname === "/api/login/switch") user = authMode === "switched-again" ? "later@example.com" : body.user;
      if (url.pathname === "/api/provider/keeplogin" && body.keepLoginAs) user = body.keepLoginAs;
      if (url.pathname === "/api/login/forget" || url.pathname === "/api/login/off") user = "spare@example.com";
      return json(data());
    }
    if (url.pathname.startsWith("/api/")) return json({});
    const file = url.pathname === "/app.js" && process.env.MAGPIE_APP_JS || path.join(assets, url.pathname === "/" ? "index.html" : url.pathname);
    const contentType = { ".html": "text/html", ".js": "text/javascript", ".css": "text/css", ".svg": "image/svg+xml", ".png": "image/png" }[path.extname(file)];
    return route.fulfill({ body: await fs.readFile(file), contentType });
  });
  await page.goto("http://magpie.test/?view=providers");
  await page.locator(".row.provider", { hasText: "Codex" }).first().click();
  await page.locator(".editor .acc").first().waitFor();
  return { page, posts, errors, finishAuth: () => finishAuth?.() };
}

for (const engine of (process.env.BROWSER ? [process.env.BROWSER] : ["chromium", "webkit"])) {
  for (const lang of ["en", "zh", "zh-TW", "ja", "de"]) {
    for (const width of [900, 480]) {
      test(`${engine} ${lang} ${width}: keychain switches explain Always Allow`, async (t) => {
        const { page, posts, errors } = await open(t, engine, lang, width);
        const translated = await page.evaluate(([l, ks]) => ks.map((k) => l === "en" ? k : I18N[l][k]), [lang, keys]);
        assert.ok(translated.every(Boolean), "all guidance is translated");
        const before = await page.evaluate(() => scrollY);
        const row = page.locator(".editor .acc", { hasText: "spare@example.com" });
        await row.locator("button").last().click();
        const dialog = page.locator(".codex-keychain-dialog");
        await dialog.waitFor();
        assert.equal(await dialog.locator("h2").textContent(), translated[0]);
        assert.equal(await dialog.locator("#codexKeychainMessage").textContent(), translated[1]);
        await page.waitForFunction((text) => document.querySelector('.codex-keychain-dialog [role="status"]')?.textContent === text,
          await page.evaluate((l) => l === "en" ? "Codex's keychain permission is saved." : I18N[l]["Codex's keychain permission is saved."], lang));
        assert.equal(await dialog.locator("button:visible").count(), 1, "authorized switch only needs Got it");
        assert.equal(await dialog.locator("button:visible").evaluate((e) => e === document.activeElement), true);
        assert.equal(await page.evaluate(() => scrollY), before, "notice doesn't scroll the page");
        assert.equal(await page.evaluate(() => document.scrollingElement.scrollWidth <= innerWidth), true);
        assert.ok(await dialog.evaluate((d) => d.getBoundingClientRect().left >= 0 && d.getBoundingClientRect().right <= innerWidth));
        await page.keyboard.press("Tab");
        assert.equal(await dialog.locator("button:visible").evaluate((e) => e === document.activeElement), true);
        if (process.env.ARTIFACT_DIR && engine === "chromium" && lang === "zh" && width === 900) {
          await fs.mkdir(process.env.ARTIFACT_DIR, { recursive: true });
          await page.screenshot({ path: path.join(process.env.ARTIFACT_DIR, "codex-keychain-switch-zh.png") });
        }
        await page.keyboard.press("Escape");
        await dialog.waitFor({ state: "detached" });
        assert.deepEqual(posts, [
          { path: "/api/login/switch", body: { agent: "codex", user: "spare@example.com" } },
          { path: "/api/codex/keychain/authorize", body: { user: "spare@example.com" } },
        ]);
        assert.deepEqual(errors, []);
      });
    }
  }
  for (const [name, keychain, fail] of [["file", false, false], ["old server", null, false], ["refused switch", true, true]]) {
    test(`${engine}: ${name} has no completed-switch keychain dialog`, async (t) => {
      const { page, posts, errors } = await open(t, engine, "en", 900, keychain, fail);
      const changed = await page.evaluate(() => accountAction("login/switch", { agent: "codex", user: "spare@example.com" }, ""));
      assert.equal(changed, !fail);
      assert.equal(posts.length, 1);
      assert.equal(await page.locator(".codex-keychain-dialog").count(), 0);
      assert.deepEqual(errors, []);
    });
  }
  test(`${engine}: staying on the same account and reordering don't show a switch dialog`, async (t) => {
    const { page, errors } = await open(t, engine, "en", 900);
    await page.evaluate(() => accountAction("login/switch", { agent: "codex", user: "work@example.com" }, ""));
    await page.evaluate(() => accountAction("provider/arrange", { id: "codex", accountOrder: ["spare@example.com", "work@example.com"] }, ""));
    // An unrelated action must not claim Codex was switched by it, even if
    // a background Codex switch appears in the returned snapshot meanwhile.
    await page.evaluate(() => accountAction("login/switch", { agent: "claude", user: "spare@example.com" }, ""));
    for (const [action, body] of [
      ["provider/keeplogin", { id: "codex", keepLogin: true, keepLoginAs: "work@example.com" }],
      ["login/forget", { agent: "codex", user: "work@example.com" }],
      ["login/off", { agent: "codex", user: "work@example.com" }],
    ]) await page.evaluate(([p, b]) => accountAction(p, b, "", true), [action, body]);
    assert.equal(await page.locator(".codex-keychain-dialog").count(), 0);
    assert.deepEqual(errors, []);
  });
  test(`${engine}: a later account change is not authorized by this switch`, async (t) => {
    const { page, posts, errors } = await open(t, engine, "en", 900, true, false, "switched-again");
    const changed = await page.evaluate(() => accountAction("login/switch", { agent: "codex", user: "spare@example.com" }, ""));
    assert.equal(changed, true);
    assert.equal(await page.evaluate(() => providers.providers[0].account.user), "later@example.com");
    assert.equal(await page.locator(".codex-keychain-dialog").count(), 0);
    assert.deepEqual(posts, [{ path: "/api/login/switch", body: { agent: "codex", user: "spare@example.com" } }]);
    assert.deepEqual(errors, []);
  });
  for (const lang of ["en", "zh", "zh-TW", "ja", "de"]) {
    test(`${engine} ${lang}: failed authorization keeps the switch and retries authorization only`, async (t) => {
      const { page, posts, errors } = await open(t, engine, lang, 480, true, false, "retry");
      const changed = await page.evaluate(() => accountAction("login/switch", { agent: "codex", user: "spare@example.com" }, ""));
      assert.equal(changed, true);
      const dialog = page.locator(".codex-keychain-dialog");
      const retry = dialog.locator("button").first();
      await retry.waitFor({ state: "visible" });
      assert.equal(await page.evaluate(() => providers.providers[0].account.user), "spare@example.com");
      const translated = await page.evaluate(([l, ks]) => ks.map((k) => l === "en" ? k : I18N[l][k]), [lang, keys]);
      assert.ok(translated.every(Boolean));
      assert.equal(await dialog.locator('[role="status"]').textContent(), translated[5]);
      assert.equal(await retry.textContent(), translated[2]);
      await retry.click();
      await page.waitForFunction((text) => document.querySelector('.codex-keychain-dialog [role="status"]')?.textContent === text, translated[4]);
      assert.equal(posts.filter((p) => p.path === "/api/login/switch").length, 1);
      assert.equal(posts.filter((p) => p.path === "/api/codex/keychain/authorize").length, 2);
      assert.equal(await retry.isVisible(), false);
      assert.deepEqual(errors, []);
    });
  }
  test(`${engine}: closing a waiting authorization cancels its request`, async (t) => {
    const { page, posts, finishAuth } = await open(t, engine, "en", 480, true, false, "pending");
    await page.locator(".editor .acc", { hasText: "spare@example.com" }).locator("button").last().click();
    const dialog = page.locator(".codex-keychain-dialog");
    await dialog.waitFor();
    await page.waitForFunction(() => document.querySelector('.codex-keychain-dialog [role="status"]')?.textContent.includes("Waiting"));
    assert.deepEqual(posts, [
      { path: "/api/login/switch", body: { user: "spare@example.com", agent: "codex" } },
      { path: "/api/codex/keychain/authorize", body: { user: "spare@example.com" } },
    ]);
    await page.keyboard.press("Escape");
    assert.equal(await page.evaluate(() => window.authorizationAborted), true);
    finishAuth();
    await dialog.waitFor({ state: "detached" });
    assert.equal(await page.evaluate(() => providers.providers[0].account.user), "spare@example.com");
  });
}
