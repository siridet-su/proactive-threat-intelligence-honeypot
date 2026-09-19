import { createHmac } from "node:crypto";
import { expect, test } from "@playwright/test";

const authSecret = "fa013-browser-test-secret-32-characters";

function browserSessionToken() {
  const payload = Buffer.from(JSON.stringify({
    sessionId: "browser-test-session",
    operatorId: "browser-test",
    role: "Supporter",
    mustChangePassword: false,
    expiresAt: Date.now() + 60 * 60 * 1000,
  })).toString("base64url");
  const signature = createHmac("sha256", authSecret).update(payload).digest("base64url");
  return `${payload}.${signature}`;
}

function closedSession(id, path = "/var/log", sourceIp = "198.51.100.7") {
  return {
    sessionId: id,
    sourceIp,
    closedAt: "2026-09-19T00:00:00.000Z",
    cwdState: {
      path,
      status: "confirmed",
      observedAt: "2026-09-19T00:00:00.000Z",
      sourceEventId: null,
    },
    auditSummary: { visitedPaths: [path], homeOnly: false, eventCount: 3 },
  };
}

const liveSession = {
  sessionId: "live-session",
  sourceIp: "192.0.2.10",
  cwdState: {
    path: "/var/log",
    status: "confirmed",
    observedAt: "2026-09-19T00:00:00.000Z",
    sourceEventId: null,
  },
  auditSummary: { visitedPaths: ["/var/log"], homeOnly: false, eventCount: 3 },
};

const defaultClosedSession = closedSession("closed-session");
const deepHop = {
  id: "deep-hop",
  sessionId: "closed-session",
  fromPath: "/var",
  toPath: "/etc",
  command: "cd /etc",
  action: "change",
  status: "confirmed",
  at: "2026-09-19T00:00:30.000Z",
  hopNumber: 3,
};
const firstHistoryHop = {
  id: "hop-two",
  sessionId: "closed-session",
  fromPath: "/",
  toPath: "/var",
  command: "cd /var",
  action: "change",
  status: "confirmed",
  at: "2026-09-19T00:00:20.000Z",
  hopNumber: 2,
};
const secondHistoryHop = {
  id: "hop-one",
  sessionId: "closed-session",
  fromPath: "/home",
  toPath: "/",
  command: "cd /",
  action: "change",
  status: "confirmed",
  at: "2026-09-19T00:00:10.000Z",
  hopNumber: 1,
};

const snapshot = {
  nodes: [],
  sessions: [liveSession],
  recentClosedSessions: [defaultClosedSession],
  truncated: false,
  generatedAt: "2026-09-19T00:00:00.000Z",
  latestTelemetryAt: null,
};

function deferred() {
  let resolve;
  const promise = new Promise((nextResolve) => { resolve = nextResolve; });
  return { promise, resolve };
}

function monitorBrowserFailures(page) {
  if (page.__fa013BrowserFailures) return;
  const failures = [];
  page.__fa013BrowserFailures = failures;
  page.on("pageerror", (error) => failures.push(`pageerror: ${error.message}`));
  page.on("console", (message) => {
    if (message.type() !== "error") return;
    const location = message.location().url;
    const intentionalErrorFixture = location.includes("/api/sessions/live-session/cwd-history?hop=error-hop");
    if (!intentionalErrorFixture) failures.push(`console.error: ${message.text()} (${location})`);
  });
}

async function assertNoBrowserFailures(page) {
  await expect(page.__fa013BrowserFailures).toEqual([]);
}

async function installApiFixtures(page, { deferDirectLookup = false } = {}) {
  await page.context().addCookies([{
    name: "pti_session",
    value: browserSessionToken(),
    domain: "127.0.0.1",
    path: "/",
  }]);
  const directLookup = deferred();
  const stalePageTwo = deferred();
  const retainedLookup = deferred();
  const requests = [];
  const historyRequests = [];

  await page.route("**/api/auth/session", (route) => route.fulfill({
    status: 200,
    contentType: "application/json",
    body: JSON.stringify({ operatorId: "browser-test", role: "Analyst", fullName: "Browser Test" }),
  }));
  await page.route("**/api/threats", (route) => route.fulfill({
    status: 200,
    contentType: "application/json",
    body: "[]",
  }));
  await page.route("**/api/threats/stream", (route) => route.fulfill({
    status: 200,
    contentType: "text/event-stream",
    headers: { "Cache-Control": "no-cache", Connection: "keep-alive" },
    body: `event: snapshot\ndata: ${JSON.stringify({ type: "snapshot", data: [] })}\n\n`,
  }));
  await page.route("**/api/filesystem-topology/stream", (route) => route.fulfill({
    status: 200,
    contentType: "text/event-stream",
    headers: { "Cache-Control": "no-cache", Connection: "keep-alive" },
    body: `event: snapshot\ndata: ${JSON.stringify({ data: snapshot })}\n\nevent: topology.update\ndata: ${JSON.stringify({ data: snapshot })}\n\n`,
  }));
  await page.route("**/api/filesystem-topology", (route) => route.fulfill({
    status: 200,
    contentType: "application/json",
    body: JSON.stringify(snapshot),
  }));
  await page.route("**/api/filesystem-topology/audit-summary**", (route) => route.fulfill({
    status: 200,
    contentType: "application/json",
    body: JSON.stringify({
      totalSessions: 2,
      homeOnlyCount: 0,
      distinctPaths: [
        { path: "/var/log", sessionCount: 2 },
        { path: "/etc", sessionCount: 1 },
      ],
    }),
  }));
  await page.route("**/api/filesystem-topology/audit-sessions**", async (route) => {
    const url = new URL(route.request().url());
    const query = url.searchParams.get("q") ?? url.searchParams.get("search") ?? "";
    const cursor = url.searchParams.get("cursor");
    requests.push({ query, cursor, hideHome: url.searchParams.get("hideHome"), targetPath: url.searchParams.get("targetPath") });
    if (url.searchParams.get("search") === "retained-a") {
      await retainedLookup.promise;
      await route.fulfill({ status: 200, contentType: "application/json", body: JSON.stringify({ items: [closedSession("retained-a", "/var/log", "198.51.100.61")], nextCursor: null }) }).catch(() => {});
      return;
    }
    if (query === "complete-query") {
      const pageOne = [closedSession("complete-one", "/var/log", "198.51.100.21"), closedSession("complete-two", "/var/log", "198.51.100.22")];
      const pageTwo = [pageOne[1], closedSession("complete-three", "/var/log", "198.51.100.23")];
      await route.fulfill({ status: 200, contentType: "application/json", body: JSON.stringify(cursor ? { items: pageTwo, nextCursor: null } : { items: pageOne, nextCursor: "complete-page-two" }) });
      return;
    }
    if (query === "attack") {
      if (cursor === "attack-page-two") {
        await stalePageTwo.promise;
        await route.fulfill({ status: 200, contentType: "application/json", body: JSON.stringify({ items: [closedSession("stale-page-two", "/var/log", "198.51.100.99")], nextCursor: null }) }).catch(() => {});
      } else {
        await route.fulfill({ status: 200, contentType: "application/json", body: JSON.stringify({ items: [closedSession("attack-one", "/var/log", "198.51.100.31")], nextCursor: "attack-page-two" }) });
      }
      return;
    }
    if (query === "new-query") {
      await route.fulfill({ status: 200, contentType: "application/json", body: JSON.stringify({ items: [closedSession("new-query-result", "/var/log", "198.51.100.41")], nextCursor: null }) });
      return;
    }
    await route.fulfill({ status: 200, contentType: "application/json", body: JSON.stringify({ items: [defaultClosedSession], nextCursor: null }) });
  });
  await page.route("**/api/sessions/*/cwd-history**", async (route) => {
    const url = new URL(route.request().url());
    const sessionId = url.pathname.split("/")[3];
    const hop = url.searchParams.get("hop");
    const cursor = url.searchParams.get("cursor");
    historyRequests.push({ sessionId, hop, cursor });
    if (hop === "deep-hop") {
      if (deferDirectLookup) await directLookup.promise;
      await route.fulfill({ status: 200, contentType: "application/json", body: JSON.stringify({ item: { ...deepHop, sessionId } }) });
      return;
    }
    if (hop === "missing-hop") {
      await route.fulfill({ status: 200, contentType: "application/json", body: JSON.stringify({ item: null }) });
      return;
    }
    if (hop === "error-hop") {
      await route.fulfill({ status: 500, contentType: "application/json", body: JSON.stringify({ error: "fixture lookup failure" }) });
      return;
    }
    if (cursor === "earlier") {
      await route.fulfill({ status: 200, contentType: "application/json", body: JSON.stringify({ items: [{ ...deepHop, sessionId }, { ...secondHistoryHop, sessionId }], nextCursor: null, totalItems: 3, totalSuccessfulItems: 3, complete: true }) });
      return;
    }
    await route.fulfill({ status: 200, contentType: "application/json", body: JSON.stringify({ items: [{ ...firstHistoryHop, sessionId }, { ...secondHistoryHop, sessionId }], nextCursor: "earlier", totalItems: 3, totalSuccessfulItems: 3, complete: false }) });
  });
  await page.route("**/api/sessions/*/actions/terminate**", (route) => route.fulfill({
    status: 200,
    contentType: "application/json",
    body: JSON.stringify({ available: true, action: null }),
  }));

  return {
    requests,
    historyRequests,
    resolveDirectLookup: directLookup.resolve,
    resolveStalePageTwo: stalePageTwo.resolve,
    resolveRetainedLookup: retainedLookup.resolve,
  };
}

async function openAuditPage(page, options = {}) {
  monitorBrowserFailures(page);
  const fixtures = await installApiFixtures(page, options);
  await page.goto(options.url ?? "/filesystem-activity?view=audit&sessionId=live-session&hop=deep-hop");
  await expect(page.getByRole("toolbar", { name: "Audit session and replay toolbar" })).toBeVisible({ timeout: 15_000 });
  await expect(page.getByRole("combobox").first()).toBeVisible();
  await assertNoBrowserFailures(page);
  return fixtures;
}

async function selectTargetPath(page) {
  await page.getByRole("combobox").nth(1).click();
  await page.getByRole("option", { name: /\/var\/log \d+ sessions/ }).click();
}

test.describe("FA-013 real-browser evidence", () => {
  test("A: the real FilesystemActivity owner performs scoped remote pagination and discards stale pages", async ({ page }) => {
    const fixtures = await openAuditPage(page);
    await page.getByRole("button", { name: /Exclude home-only/ }).click();
    await selectTargetPath(page);
    await page.getByRole("combobox").first().click();
    const search = page.getByPlaceholder("Search IP, session ID, or path...");
    await search.pressSequentially("complete-query");
    await expect(search).toHaveValue("complete-query");
    await expect.poll(() => fixtures.requests.at(-1)?.query).toBe("complete-query");
    await expect(page.getByRole("option", { name: /198\.51\.100\.21/ })).toBeVisible();
    expect(fixtures.requests.at(-1)).toMatchObject({ query: "complete-query", cursor: null, hideHome: "1", targetPath: "/var/log" });
    await page.getByRole("button", { name: "Load more matching sessions" }).click();
    await expect(page.getByRole("option", { name: /198\.51\.100\.23/ })).toBeVisible();
    await expect(page.getByText("All matching search results loaded (3)")).toBeVisible();
    expect(await page.getByRole("listbox").getByRole("option").count()).toBe(3);

    await search.fill("attack");
    await expect(page.getByRole("option", { name: /198\.51\.100\.31/ })).toBeVisible();
    await page.getByRole("button", { name: "Load more matching sessions" }).click();
    await expect(page.getByText("Loading search results…")).toBeVisible();
    await search.fill("new-query");
    await expect(page.getByRole("option", { name: /198\.51\.100\.41/ })).toBeVisible();
    fixtures.resolveStalePageTwo();
    await expect(page.getByRole("option", { name: /198\.51\.100\.99/ })).toHaveCount(0);
    await expect(page.getByText("All matching search results loaded (1)")).toBeVisible();
    expect(fixtures.requests.filter((request) => request.query === "attack" && request.cursor === "attack-page-two")).toHaveLength(1);
    await assertNoBrowserFailures(page);
  });

  test("B: the production URL owner retains and resolves deep hops beyond page one", async ({ page }) => {
    const fixtures = await openAuditPage(page, { deferDirectLookup: true });
    await expect(page).toHaveURL(/sessionId=live-session&hop=deep-hop/);
    await expect.poll(() => fixtures.historyRequests.some((request) => request.hop === "deep-hop")).toBe(true);
    fixtures.resolveDirectLookup();
    await expect(page.getByTestId("anchored-hop-banner")).toBeVisible();
    await page.getByRole("button", { name: "Load earlier hops" }).click();
    await expect(page.getByTestId("anchored-hop-banner")).toHaveCount(0);
    await expect(page.getByText("Complete retained history loaded")).toBeVisible();
    await expect(page).toHaveURL(/sessionId=live-session&hop=deep-hop/);

    await page.goto("/filesystem-activity?view=audit&sessionId=live-session&hop=missing-hop");
    await expect(page.getByTestId("hop-resolution-banner")).toContainText("Requested hop unavailable");
    await expect(page).toHaveURL(/hop=missing-hop/);
    await page.getByRole("button", { name: "Show latest hop" }).click();
    await expect(page).toHaveURL(/sessionId=live-session(?:$|&)/);

    await page.goto("/filesystem-activity?view=audit&sessionId=live-session&hop=error-hop");
    await expect(page.getByTestId("hop-resolution-banner")).toContainText("Error resolving requested hop");
    await expect(page).toHaveURL(/hop=error-hop/);
    await page.getByRole("button", { name: "Clear hop" }).click();
    await expect(page).toHaveURL(/sessionId=live-session(?:$|&)/);
    await assertNoBrowserFailures(page);
  });

  test("C: actual browser Back/Forward restores view, session, filters, and hop without feedback entries", async ({ page }) => {
    monitorBrowserFailures(page);
    const fixtures = await installApiFixtures(page);

    const assertFilesystemState = async ({
      search,
      live,
      sessionIp,
      hideHome,
      targetPath,
      selectedContext,
    }) => {
      await expect.poll(() => page.evaluate(() => `${window.location.pathname}${window.location.search}`))
        .toBe(`/filesystem-activity${search}`);
      await expect(page.getByRole("tab", {
        name: live ? "Live Topology" : "Session Audit & Replay",
        selected: true,
      })).toBeVisible();
      if (live) return;

      await expect(page.getByRole("toolbar", { name: "Audit session and replay toolbar" })).toBeVisible();
      await expect(page.getByRole("combobox").first()).toContainText(sessionIp);
      await expect(page.getByRole("button", { name: "Exclude home-only" }))
        .toHaveAttribute("aria-pressed", String(hideHome));
      await expect(page.getByRole("combobox").nth(1)).toContainText(targetPath);
      await expect(page.locator("strong").filter({ hasText: selectedContext }).first())
        .toHaveText(selectedContext);
    };

    // Start on the production Live page, then build the rest through its UI.
    await page.goto("/filesystem-activity");
    await expect(page.getByRole("tab", { name: "Live Topology" })).toBeVisible({ timeout: 15_000 });
    await assertFilesystemState({
      search: "",
      live: true,
      sessionIp: "",
      hideHome: false,
      targetPath: "",
      selectedContext: "",
    });

    await page.getByRole("tab", { name: "Session Audit & Replay" }).evaluate((element) => element.click());
    await expect(page.getByRole("toolbar", { name: "Audit session and replay toolbar" })).toBeVisible();
    await assertFilesystemState({
      search: "?view=audit&sessionId=live-session",
      live: false,
      sessionIp: "192.0.2.10",
      hideHome: false,
      targetPath: "All paths",
      selectedContext: "/var",
    });

    await page.getByRole("combobox").first().click();
    await page.getByRole("option", { name: /198\.51\.100\.7/ }).click();
    await expect(page.getByTitle("Previous hop", { exact: true })).toBeVisible();
    await assertFilesystemState({
      search: "?view=audit&sessionId=closed-session",
      live: false,
      sessionIp: "198.51.100.7",
      hideHome: false,
      targetPath: "All paths",
      selectedContext: "/var",
    });

    await page.getByRole("button", { name: /Exclude home-only/ }).click();
    await assertFilesystemState({
      search: "?view=audit&sessionId=closed-session&hideHome=1",
      live: false,
      sessionIp: "198.51.100.7",
      hideHome: true,
      targetPath: "All paths",
      selectedContext: "/var",
    });

    await selectTargetPath(page);
    await assertFilesystemState({
      search: "?view=audit&sessionId=closed-session&hideHome=1&targetPath=%2Fvar%2Flog",
      live: false,
      sessionIp: "198.51.100.7",
      hideHome: true,
      targetPath: "/var/log",
      selectedContext: "/var",
    });

    const historyLength = await page.evaluate(() => window.history.length);
    await page.getByTitle("Previous hop", { exact: true }).click();
    await assertFilesystemState({
      search: "?view=audit&sessionId=closed-session&hideHome=1&targetPath=%2Fvar%2Flog&hop=hop-one",
      live: false,
      sessionIp: "198.51.100.7",
      hideHome: true,
      targetPath: "/var/log",
      selectedContext: "/",
    });
    expect(await page.evaluate(() => window.history.length)).toBe(historyLength + 1);

    // Traverse the complete production-created audit stack backward through
    // session selection, filters, and hop, then forward to the same tip.
    await page.goBack();
    await assertFilesystemState({
      search: "?view=audit&sessionId=closed-session&hideHome=1&targetPath=%2Fvar%2Flog",
      live: false,
      sessionIp: "198.51.100.7",
      hideHome: true,
      targetPath: "/var/log",
      selectedContext: "/var",
    });
    await page.goBack();
    await assertFilesystemState({
      search: "?view=audit&sessionId=closed-session&hideHome=1",
      live: false,
      sessionIp: "198.51.100.7",
      hideHome: true,
      targetPath: "All paths",
      selectedContext: "/var",
    });
    await page.evaluate(() => window.history.back());
    await assertFilesystemState({
      search: "?view=audit&sessionId=closed-session",
      live: false,
      sessionIp: "198.51.100.7",
      hideHome: false,
      targetPath: "All paths",
      selectedContext: "/var",
    });
    await page.evaluate(() => window.history.back());
    await assertFilesystemState({
      search: "?view=audit&sessionId=live-session",
      live: false,
      sessionIp: "192.0.2.10",
      hideHome: false,
      targetPath: "All paths",
      selectedContext: "/var",
    });
    await page.goForward();
    await assertFilesystemState({
      search: "?view=audit&sessionId=closed-session",
      live: false,
      sessionIp: "198.51.100.7",
      hideHome: false,
      targetPath: "All paths",
      selectedContext: "/var",
    });
    await page.goForward();
    await assertFilesystemState({
      search: "?view=audit&sessionId=closed-session&hideHome=1",
      live: false,
      sessionIp: "198.51.100.7",
      hideHome: true,
      targetPath: "All paths",
      selectedContext: "/var",
    });
    await page.goForward();
    await assertFilesystemState({
      search: "?view=audit&sessionId=closed-session&hideHome=1&targetPath=%2Fvar%2Flog",
      live: false,
      sessionIp: "198.51.100.7",
      hideHome: true,
      targetPath: "/var/log",
      selectedContext: "/var",
    });
    await page.goForward();
    await assertFilesystemState({
      search: "?view=audit&sessionId=closed-session&hideHome=1&targetPath=%2Fvar%2Flog&hop=hop-one",
      live: false,
      sessionIp: "198.51.100.7",
      hideHome: true,
      targetPath: "/var/log",
      selectedContext: "/",
    });
    expect(await page.evaluate(() => window.history.length)).toBe(historyLength + 1);

    // Keep this document and mounted coordinator alive. Same-document entries
    // create A and B, then Back starts A's deferred lookup before Forward
    // supersedes it with known session B.
    await page.evaluate(() => {
      window.history.pushState(
        null,
        "",
        "/filesystem-activity?view=audit&sessionId=retained-a&hideHome=1&targetPath=%2Fvar%2Flog&hop=hop-two",
      );
      window.history.pushState(
        null,
        "",
        "/filesystem-activity?view=audit&sessionId=closed-session&hideHome=1&targetPath=%2Fvar%2Flog&hop=hop-one",
      );
    });
    await page.goBack();
    await expect.poll(() => fixtures.requests.some((request) => request.query === "retained-a")).toBe(true);
    await expect(page).toHaveURL(/sessionId=retained-a/);
    await page.goForward();
    await assertFilesystemState({
      search: "?view=audit&sessionId=closed-session&hideHome=1&targetPath=%2Fvar%2Flog&hop=hop-one",
      live: false,
      sessionIp: "198.51.100.7",
      hideHome: true,
      targetPath: "/var/log",
      selectedContext: "/",
    });
    const delayedHistoryLength = await page.evaluate(() => window.history.length);
    fixtures.resolveRetainedLookup();
    await expect.poll(() => page.evaluate(() => `${window.location.pathname}${window.location.search}`))
      .toBe("/filesystem-activity?view=audit&sessionId=closed-session&hideHome=1&targetPath=%2Fvar%2Flog&hop=hop-one");
    await expect(page.getByRole("combobox").first()).toContainText("198.51.100.7");
    await expect(page.getByRole("button", { name: "Exclude home-only" })).toHaveAttribute("aria-pressed", "true");
    await expect(page.getByRole("combobox").nth(1)).toContainText("/var/log");
    await expect(page.locator("strong").filter({ hasText: "/" }).first()).toHaveText("/");
    await expect(page.getByText(/retained-a has expired/)).toHaveCount(0);
    expect(fixtures.requests.filter((request) => request.query === "retained-a")).toHaveLength(1);
    expect(await page.evaluate(() => window.history.length)).toBe(delayedHistoryLength);
    await assertNoBrowserFailures(page);
  });

  test("G: audit toolbar and timeline transitions remain reachable at narrow, tablet, and desktop widths", async ({ page }) => {
    for (const viewport of [{ width: 375, height: 900 }, { width: 768, height: 900 }, { width: 1440, height: 900 }]) {
      await page.setViewportSize(viewport);
      await openAuditPage(page);
      const toolbar = page.getByRole("toolbar", { name: "Audit session and replay toolbar" });
      await expect(toolbar).toBeVisible();
      const controls = [
        page.getByRole("combobox").first(),
        page.getByRole("combobox").nth(1),
        page.getByRole("button", { name: /Exclude home-only/ }),
        page.getByRole("button", { name: "Enter Fullscreen Audit Studio" }),
      ];
      for (const control of controls) {
        await expect(control).toBeVisible();
        const box = await control.boundingBox();
        expect(box).not.toBeNull();
        expect(box.x).toBeGreaterThanOrEqual(0);
        expect(box.y).toBeGreaterThanOrEqual(0);
        expect(box.x + box.width).toBeLessThanOrEqual(viewport.width);
        expect(box.y + box.height).toBeLessThanOrEqual(viewport.height);
      }
      const noOverflow = await page.evaluate(() => ({
        page: document.documentElement.scrollWidth <= window.innerWidth,
        toolbar: [...document.querySelectorAll('[aria-label="Audit session and replay toolbar"]')].every((element) => element.scrollWidth <= element.clientWidth),
      }));
      expect(noOverflow).toEqual({ page: true, toolbar: true });
      const timelineToggle = page.locator('[title="Collapse timeline sidebar"], [title="Show timeline sidebar"], [title="Collapse timeline panel"], [title="Show timeline panel"]').first();
      await timelineToggle.click();
      const timelinePanel = page.locator('[aria-hidden="true"][inert]').last();
      await expect(timelinePanel).toHaveAttribute("aria-hidden", "true");
      await expect(timelinePanel).toHaveAttribute("inert", "");
      await page.locator('[title="Show timeline sidebar"], [title="Show timeline panel"]').first().click();
      await expect(page.locator('[data-forensic-tab-panel="replay"]')).toBeVisible();
      await assertNoBrowserFailures(page);
    }
  });

  test("H: reduced motion makes production replay transitions immediate while controls remain functional", async ({ page }) => {
    await page.emulateMedia({ reducedMotion: "reduce" });
    await openAuditPage(page);
    await page.getByRole("button", { name: "Response" }).click();
    await expect(page.locator('[data-forensic-tab-panel="actions"]')).toBeVisible();
    await page.getByRole("button", { name: "Command data" }).click();
    await expect(page.locator('[data-forensic-tab-panel="commands"]')).toBeVisible();
    const transitionDurations = await page.locator('[class*="motion-reduce:transition-none"]').evaluateAll((elements) =>
      elements.map((element) => getComputedStyle(element).transitionDuration),
    );
    expect(transitionDurations.length).toBeGreaterThan(0);
    expect(transitionDurations.every((duration) => duration === "0s")).toBe(true);
    expect(await page.evaluate(() => document.getAnimations().filter((animation) => animation.playState === "running").length)).toBe(0);
    await assertNoBrowserFailures(page);
  });
});
