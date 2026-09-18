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

const closedSession = {
  sessionId: "closed-session",
  sourceIp: "198.51.100.7",
  closedAt: "2026-09-19T00:00:00.000Z",
  cwdState: {
    path: "/var/log",
    status: "confirmed",
    observedAt: "2026-09-19T00:00:00.000Z",
    sourceEventId: null,
  },
  auditSummary: { visitedPaths: ["/var/log", "/etc"], homeOnly: false, eventCount: 3 },
};

const snapshot = {
  nodes: [],
  sessions: [liveSession],
  recentClosedSessions: [closedSession],
  truncated: false,
  generatedAt: "2026-09-19T00:00:00.000Z",
  latestTelemetryAt: null,
};

const history = [
  { id: "deep-hop", sessionId: "closed-session", fromPath: "/var", toPath: "/etc", command: "cd /etc", action: "change", status: "confirmed", at: "2026-09-19T00:00:30.000Z" },
  { id: "hop-two", sessionId: "closed-session", fromPath: "/", toPath: "/var", command: "cd /var", action: "change", status: "confirmed", at: "2026-09-19T00:00:20.000Z" },
];

async function installApiFixtures(page) {
  await page.context().addCookies([{
    name: "pti_session",
    value: browserSessionToken(),
    domain: "127.0.0.1",
    path: "/",
  }]);
  await page.addInitScript((fixtureSnapshot) => {
    class FixtureEventSource {
      static CONNECTING = 0;
      static OPEN = 1;
      static CLOSED = 2;
      readyState = FixtureEventSource.CONNECTING;
      url;
      onopen = null;
      onmessage = null;
      onerror = null;

      constructor(url) {
        this.url = url;
        queueMicrotask(() => {
          this.readyState = FixtureEventSource.OPEN;
          this.onopen?.(new Event("open"));
          const event = new MessageEvent("snapshot", { data: JSON.stringify({ data: fixtureSnapshot }) });
          this.onsnapshot?.(event);
          this["ontopology.update"]?.(new MessageEvent("topology.update", { data: JSON.stringify({ data: fixtureSnapshot }) }));
        });
      }

      addEventListener(type, listener) {
        this[`on${type}`] = listener;
      }

      removeEventListener() {}
      close() { this.readyState = FixtureEventSource.CLOSED; }
    }
    window.EventSource = FixtureEventSource;
  }, snapshot);
  await page.route("**/api/auth/session", (route) => route.fulfill({
    status: 200,
    contentType: "application/json",
    body: JSON.stringify({ operatorId: "browser-test", role: "Analyst", fullName: "Browser Test" }),
  }));

  await page.route("**/api/filesystem-topology/stream", (route) => route.fulfill({
    status: 200,
    contentType: "text/event-stream",
    body: `data: ${JSON.stringify(snapshot)}\n\n`,
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
    if (url.searchParams.get("search") === "closed-session") {
      await route.fulfill({ status: 200, contentType: "application/json", body: JSON.stringify({ items: [closedSession], nextCursor: null }) });
      return;
    }
    await route.fulfill({
      status: 200,
      contentType: "application/json",
      body: JSON.stringify({ items: [closedSession], nextCursor: null }),
    });
  });

  await page.route("**/api/sessions/*/cwd-history**", async (route) => {
    const sessionId = new URL(route.request().url()).pathname.split("/")[3];
    const url = new URL(route.request().url());
    if (url.searchParams.get("hop") === "deep-hop") {
      await route.fulfill({ status: 200, contentType: "application/json", body: JSON.stringify({ item: { ...history[0], sessionId } }) });
      return;
    }
    await route.fulfill({
      status: 200,
      contentType: "application/json",
      body: JSON.stringify({ items: history.map((item) => ({ ...item, sessionId })), nextCursor: null, totalItems: 2, totalSuccessfulItems: 2, complete: true }),
    });
  });

  await page.route("**/api/sessions/*/actions/terminate**", (route) => route.fulfill({
    status: 200,
    contentType: "application/json",
    body: JSON.stringify({ available: true, action: null }),
  }));
}

async function openAuditPage(page) {
  await installApiFixtures(page);
  await page.goto("/filesystem-activity?view=audit&sessionId=live-session&hop=deep-hop");
  await expect(page.getByRole("toolbar", { name: "Audit session and replay toolbar" })).toBeVisible();
  await expect(page.getByRole("combobox").first()).toBeVisible();
}

test.describe("FA-013 real-browser evidence", () => {
  test("G: audit toolbar remains reachable and un-clipped at narrow, tablet, and desktop widths", async ({ page }) => {
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
      const timelineToggle = page.locator('[title="Collapse timeline panel"], [title="Show timeline panel"]').first();
      await expect(timelineToggle).toBeVisible();
      await timelineToggle.click();
      await expect(page.locator('[title="Collapse timeline panel"], [title="Show timeline panel"]').first()).toBeVisible();
    }
  });

  test("H: reduced motion makes the production replay transition immediate while tabs remain functional", async ({ page }) => {
    await page.emulateMedia({ reducedMotion: "reduce" });
    await openAuditPage(page);
    const responseTab = page.getByRole("button", { name: "Response" });
    const commandTab = page.getByRole("button", { name: "Command data" });
    await responseTab.click();
    await expect(page.locator('[data-forensic-tab-panel="actions"]')).toBeVisible();
    await commandTab.click();
    await expect(page.locator('[data-forensic-tab-panel="commands"]')).toBeVisible();

    const transitionDurations = await page.locator('[class*="motion-reduce:transition-none"]').evaluateAll((elements) =>
      elements.map((element) => getComputedStyle(element).transitionDuration),
    );
    expect(transitionDurations.length).toBeGreaterThan(0);
    expect(transitionDurations.every((duration) => duration === "0s")).toBe(true);
    expect(await page.evaluate(() => document.getAnimations().filter((animation) => animation.playState === "running").length)).toBe(0);
  });
});
