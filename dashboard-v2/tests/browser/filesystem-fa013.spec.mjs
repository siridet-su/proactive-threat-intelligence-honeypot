import { expect, test } from "@playwright/test";
import {
  assertNoBrowserFailures,
  installApiFixtures,
  monitorBrowserFailures,
  openAuditPage,
  selectTargetPath,
} from "./fixtures/filesystem.mjs";

test.describe("FA-013 real-browser evidence", () => {
  test("production minimal: Live -> Audit -> Back -> Live -> Forward -> Audit", async ({ page }) => {
    monitorBrowserFailures(page);
    await installApiFixtures(page);
    await page.addInitScript(() => {
      window.__fa013HistoryWrites = [];
      for (const method of ["pushState", "replaceState"]) {
        const original = window.history[method];
        window.history[method] = function (...args) {
          window.__fa013HistoryWrites.push({ method, url: args[2] ?? null });
          return original.apply(this, args);
        };
      }
    });
    await page.goto("/filesystem-activity");
    await expect(page.getByRole("tab", { name: "Live Topology" })).toBeVisible({ timeout: 15_000 });
    await page.evaluate(() => { window.__fa013HistoryWrites.length = 0; });
    await page.getByRole("tab", { name: "Session Audit & Replay" }).evaluate((element) => element.click());
    await expect(page.getByRole("toolbar", { name: "Audit session and replay toolbar" })).toBeVisible();
    await expect(page).toHaveURL("/filesystem-activity?view=audit&sessionId=live-session");
    expect(await page.evaluate(() => window.__fa013HistoryWrites.filter(({ method }) => method === "pushState"))).toHaveLength(1);
    await page.evaluate(() => { window.__fa013HistoryWrites.length = 0; });
    await page.goBack();
    await expect(page.getByRole("tab", { name: "Live Topology" })).toBeVisible({ timeout: 15_000 });
    await expect(page).toHaveURL("/filesystem-activity");
    const writesAfterBack = await page.evaluate(() => window.__fa013HistoryWrites);
    expect(writesAfterBack.filter(({ method }) => method === "pushState")).toEqual([]);
    expect(writesAfterBack.filter(({ method, url }) => method === "replaceState" && url !== "/filesystem-activity")).toEqual([]);
    await expect(page.getByRole("toolbar", { name: "Global filesystem controls" })).toBeVisible();
    await expect(page.getByRole("toolbar", { name: "Audit session and replay toolbar" })).toHaveCount(0);
    await expect(page.getByRole("button", { name: /Inspect source 192\.0\.2\.10; 1 session/ })).toBeVisible();
    await page.goForward();
    await expect(page.getByRole("tab", { name: "Session Audit & Replay", selected: true })).toBeVisible();
    await expect(page).toHaveURL("/filesystem-activity?view=audit&sessionId=live-session");
    await assertNoBrowserFailures(page);
  });

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
    const anchoredHopNote = page.getByRole("note").filter({ hasText: "Anchored deep hop" });
    await expect(anchoredHopNote).toBeVisible();
    await page.getByRole("button", { name: /Load earlier moves/ }).click();
    await expect(anchoredHopNote).toHaveCount(0);
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
      const escapedContext = selectedContext.replace(/[.*+?^${}()|[\]\\]/g, "\\$&");
      await expect(page.getByRole("button", {
        name: new RegExp(`^Inspect directory ${escapedContext} \\(.*active hop target`),
      })).toBeVisible();
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
    expect(await page.evaluate(() => window.history.length)).toBe(historyLength + 1);

    // The original production Live entry is a real Back/Forward destination.
    await page.goBack();
    await expect(page.getByRole("tab", { name: "Live Topology" })).toBeVisible({ timeout: 15_000 });
    await assertFilesystemState({
      search: "",
      live: true,
      sessionIp: "",
      hideHome: false,
      targetPath: "",
      selectedContext: "",
    });
    await expect(page.getByRole("toolbar", { name: "Audit session and replay toolbar" })).toHaveCount(0);
    await expect(page.getByRole("combobox")).toHaveCount(0);
    await expect(page.getByTitle("Previous hop", { exact: true })).toHaveCount(0);
    expect(await page.evaluate(() => window.history.length)).toBe(historyLength + 1);

    await page.goForward();
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
    await expect(page.getByRole("button", {
      name: /^Inspect directory \/ \(.*active hop target/,
    })).toBeVisible();
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
      const timelineViewButton = page.getByRole("button", { name: "Timeline", exact: true });
      if (await timelineViewButton.isVisible()) await timelineViewButton.click();
      await expect(page.locator('[data-forensic-tab-panel="replay"]')).toBeVisible();
      await assertNoBrowserFailures(page);
    }
  });

  test("H: reduced motion makes production replay transitions immediate while controls remain functional", async ({ page }) => {
    await page.emulateMedia({ reducedMotion: "reduce" });
    await openAuditPage(page);
    await page.getByRole("tab", { name: "Response" }).click();
    await expect(page.locator('[data-forensic-tab-panel="actions"]')).toBeVisible();
    await page.getByRole("tab", { name: "Evidence" }).click();
    await expect(page.locator('[data-forensic-tab-panel="evidence"]')).toBeVisible();
    const transitionDurations = await page.locator('[class*="motion-reduce:transition-none"]').evaluateAll((elements) =>
      elements.map((element) => getComputedStyle(element).transitionDuration),
    );
    expect(transitionDurations.length).toBeGreaterThan(0);
    expect(transitionDurations.every((duration) => duration === "0s")).toBe(true);
    expect(await page.evaluate(() => document.getAnimations().filter((animation) => animation.playState === "running").length)).toBe(0);
    await assertNoBrowserFailures(page);
  });

  test("I: verified entered, changed, failed, and revisit transitions remain truthful at desktop and mobile widths", async ({ page }) => {
    for (const viewport of [{ width: 375, height: 900 }, { width: 1440, height: 900 }]) {
      await page.setViewportSize(viewport);
      monitorBrowserFailures(page);
      await installApiFixtures(page, { transitionReplay: true });
      await page.goto("/filesystem-activity?view=audit&sessionId=closed-session");

      const overlay = page.getByTestId("verified-transition-overlay");
      const sequence = page.getByRole("list", { name: "Verified CWD transition sequence" });
      const route = page.getByRole("list", { name: "Verified directory route" });
      await expect(overlay).toBeVisible({ timeout: 15_000 });
      await expect(sequence.getByRole("listitem")).toHaveCount(4);
      await expect(sequence).toContainText("entry at /home/cowrie");
      await expect(sequence).toContainText("transition from /home/cowrie to /tmp");
      await expect(sequence).toContainText("failed change at origin /tmp; destination unavailable or unverified");
      await expect(sequence).toContainText("transition from /tmp to /home/cowrie");

      const revisit = overlay.locator('[data-transition-event-id="replay-revisit"][data-transition-state="current"][data-transition-kind="directed"]');
      await expect(revisit).toHaveAttribute("data-transition-kind", "directed");
      await expect(revisit).toHaveAttribute("data-transition-route", "/tmp→/home/cowrie");

      const timelineViewButton = page.getByRole("button", { name: "Timeline", exact: true });
      const mapViewButton = page.getByRole("button", { name: "Map", exact: true });
      if (await timelineViewButton.isVisible()) await timelineViewButton.click();
      const routeEvents = route.getByRole("button");
      await expect(routeEvents).toHaveCount(4);
      await routeEvents.nth(2).click();
      if (await mapViewButton.isVisible()) await mapViewButton.click();
      const failed = overlay.locator('[data-transition-event-id="replay-failed"][data-transition-state="current"][data-transition-kind="failed-origin"]');
      await expect(failed).toHaveAttribute("data-transition-kind", "failed-origin");
      await expect(failed).toHaveAttribute("data-transition-marker-path", "/tmp");
      await expect(overlay.locator('[data-transition-event-id="replay-failed"][data-transition-kind="directed"]')).toHaveCount(0);
      expect(await page.evaluate(() => document.documentElement.outerHTML.includes("/unverified-hostile-destination"))).toBe(false);

      if (await timelineViewButton.isVisible()) await timelineViewButton.click();
      await routeEvents.nth(1).click();
      if (await mapViewButton.isVisible()) await mapViewButton.click();
      const changed = overlay.locator('[data-transition-event-id="replay-change"][data-transition-state="current"][data-transition-kind="directed"]');
      await expect(changed).toHaveAttribute("data-transition-route", "/home/cowrie→/tmp");

      if (await timelineViewButton.isVisible()) await timelineViewButton.click();
      await routeEvents.nth(0).click();
      if (await mapViewButton.isVisible()) await mapViewButton.click();
      const entered = overlay.locator('[data-transition-event-id="replay-entered"][data-transition-state="current"][data-transition-kind="entry"]');
      await expect(entered).toHaveAttribute("data-transition-kind", "entry");
      await expect(entered).toHaveAttribute("data-transition-marker-path", "/home/cowrie");

      if (await timelineViewButton.isVisible()) await timelineViewButton.click();
      await routeEvents.nth(3).click();
      if (await mapViewButton.isVisible()) await mapViewButton.click();
      await expect(revisit).toHaveAttribute("data-transition-state", "current");
      expect(await page.evaluate(() => document.documentElement.scrollWidth <= window.innerWidth)).toBe(true);

      await page.getByRole("button", { name: "View settings" }).click();
      await page.getByRole("group", { name: "Minimap visibility" }).getByRole("button", { name: "Show" }).click();
      await expect(page.getByTestId("topology-minimap")).toBeVisible();
      await assertNoBrowserFailures(page);
    }
  });

  test("J: one audit workspace preserves local canvas and mobile-panel state across fullscreen toggles", async ({ page }) => {
    await page.setViewportSize({ width: 1440, height: 900 });
    monitorBrowserFailures(page);
    const fixtures = await installApiFixtures(page, { transitionReplay: true });
    await page.goto("/filesystem-activity?view=audit&sessionId=closed-session&hop=replay-change");
    await expect(page.getByTestId("verified-transition-overlay")).toBeVisible({ timeout: 15_000 });

    await page.getByRole("button", { name: "View settings" }).click();
    await page.getByRole("group", { name: "Minimap visibility" }).getByRole("button", { name: "Show" }).click();
    const zoomStatus = page.locator('[aria-live="polite"][aria-label^="Zoom "]');
    const fittedZoomLabel = await zoomStatus.getAttribute("aria-label");
    await page.getByRole("button", { name: "Zoom in" }).click();
    await expect(zoomStatus).not.toHaveAttribute("aria-label", fittedZoomLabel ?? "");
    const adjustedZoomLabel = await zoomStatus.getAttribute("aria-label");
    expect(adjustedZoomLabel).not.toBeNull();
    await expect(page.getByTestId("topology-minimap")).toBeVisible();
    const selectedDirectory = page.getByRole("button", { name: /^Inspect directory \/tmp / });
    await selectedDirectory.click();
    await expect(selectedDirectory).toHaveAttribute("aria-pressed", "true");
    const splitter = page.getByRole("separator", { name: /Resize timeline panel/ });
    const initialTimelineWidth = Number(await splitter.getAttribute("aria-valuenow"));
    const splitterBox = await splitter.boundingBox();
    expect(splitterBox).not.toBeNull();
    await page.mouse.move(splitterBox.x + splitterBox.width / 2, splitterBox.y + splitterBox.height / 2);
    await page.mouse.down();
    await page.mouse.move(splitterBox.x - 24, splitterBox.y + splitterBox.height / 2);
    await page.mouse.up();
    await expect(splitter).not.toHaveAttribute("aria-valuenow", String(initialTimelineWidth));
    const adjustedTimelineWidth = await splitter.getAttribute("aria-valuenow");
    expect(adjustedTimelineWidth).not.toBeNull();
    await expect(page).toHaveURL(/hop=replay-change/);
    const historyRequestCount = fixtures.historyRequests.length;

    for (let iteration = 0; iteration < 10; iteration += 1) {
      await page.getByRole("button", { name: "Enter Fullscreen Audit Studio" }).click();
      const dialog = page.getByRole("dialog", { name: "Audit Replay Studio Fullscreen" });
      await expect(dialog).toBeVisible();
      expect(await dialog.evaluate((element) => element.contains(document.activeElement))).toBe(true);
      await expect(page.getByTestId("verified-transition-overlay")).toHaveCount(1);
      await expect(page.getByTestId("topology-minimap")).toBeVisible();
      await expect(zoomStatus).toHaveAttribute("aria-label", adjustedZoomLabel ?? "");
      await expect(selectedDirectory).toHaveAttribute("aria-pressed", "true");
      await expect(splitter).toHaveAttribute("aria-valuenow", adjustedTimelineWidth ?? "");
      await expect(page).toHaveURL(/hop=replay-change/);

      if (iteration === 9) {
        await page.keyboard.press("Escape");
      } else {
        await page.getByRole("button", { name: "Exit Fullscreen Studio" }).click();
      }
      await expect(page.getByRole("dialog", { name: "Audit Replay Studio Fullscreen" })).toHaveCount(0);
      await expect(page.getByTestId("verified-transition-overlay")).toHaveCount(1);
      await expect(page.getByTestId("topology-minimap")).toBeVisible();
      await expect(zoomStatus).toHaveAttribute("aria-label", adjustedZoomLabel ?? "");
      await expect(selectedDirectory).toHaveAttribute("aria-pressed", "true");
      await expect(splitter).toHaveAttribute("aria-valuenow", adjustedTimelineWidth ?? "");
      await expect(page.getByRole("button", { name: "Enter Fullscreen Audit Studio" })).toBeFocused();
    }
    expect(fixtures.historyRequests).toHaveLength(historyRequestCount);

    await page.setViewportSize({ width: 375, height: 900 });
    await page.getByRole("button", { name: "Timeline", exact: true }).click();
    await expect(page.locator('[data-forensic-tab-panel="replay"]')).toBeVisible();
    await page.getByRole("button", { name: "Enter Fullscreen Audit Studio" }).click();
    await expect(page.getByRole("dialog", { name: "Audit Replay Studio Fullscreen" })).toBeVisible();
    await expect(page.locator('[data-forensic-tab-panel="replay"]')).toBeVisible();
    await page.getByRole("button", { name: "Exit Fullscreen Studio" }).click();
    await expect(page.locator('[data-forensic-tab-panel="replay"]')).toBeVisible();
    await assertNoBrowserFailures(page);
  });
});
