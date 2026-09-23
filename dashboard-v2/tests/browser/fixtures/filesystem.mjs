import { createHmac } from "node:crypto";
import { expect } from "@playwright/test";

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

export function closedSession(id, path = "/var/log", sourceIp = "198.51.100.7") {
  return {
    sessionId: id,
    sourceIp,
    lifecycle: {
      startedAt: null,
      closedAt: "2026-09-19T00:00:00.000Z",
    },
    cwdState: {
      path,
      status: "confirmed",
      observedAt: "2026-09-19T00:00:00.000Z",
      sourceEventId: null,
    },
    auditSummary: { visitedPaths: [path], homeOnly: false, eventCount: 3 },
  };
}

export function activeSession() {
  return {
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
}

function deferred() {
  let resolve;
  const promise = new Promise((nextResolve) => { resolve = nextResolve; });
  return { promise, resolve };
}

export function monitorBrowserFailures(page) {
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

export async function assertNoBrowserFailures(page) {
  await expect(page.__fa013BrowserFailures).toEqual([]);
}

export async function installApiFixtures(page, {
  deferDirectLookup = false,
  transitionReplay = false,
} = {}) {
  await page.context().addCookies([{
    name: "pti_session",
    value: browserSessionToken(),
    domain: "127.0.0.1",
    path: "/",
  }]);

  const liveSession = activeSession();
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
  const transitionReplayHistory = [
    {
      id: "replay-revisit",
      sessionId: "closed-session",
      fromPath: "/tmp",
      toPath: "/home/cowrie",
      command: "cd /home/cowrie",
      action: "changed",
      status: "confirmed",
      at: "2026-09-19T00:00:40.000Z",
      hopNumber: 4,
    },
    {
      id: "replay-failed",
      sessionId: "closed-session",
      fromPath: "/tmp",
      toPath: "/unverified-hostile-destination",
      command: "cd /unverified-hostile-destination",
      action: "failed_change",
      status: "conditional_candidate",
      at: "2026-09-19T00:00:30.000Z",
      hopNumber: 3,
    },
    {
      id: "replay-change",
      sessionId: "closed-session",
      fromPath: "/home/cowrie",
      toPath: "/tmp",
      command: "cd /tmp",
      action: "changed",
      status: "confirmed",
      at: "2026-09-19T00:00:20.000Z",
      hopNumber: 2,
    },
    {
      id: "replay-entered",
      sessionId: "closed-session",
      fromPath: "/home/cowrie",
      toPath: "/home/cowrie",
      command: null,
      action: "entered",
      status: "confirmed",
      at: "2026-09-19T00:00:10.000Z",
      hopNumber: 1,
    },
  ];
  const snapshot = {
    nodes: [],
    sessions: [liveSession],
    recentClosedSessions: [defaultClosedSession],
    truncated: false,
    generatedAt: "2026-09-19T00:00:00.000Z",
    latestTelemetryAt: null,
  };
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
    if (transitionReplay) {
      const selectedReplayHop = transitionReplayHistory.find((event) => event.id === hop);
      if (hop && selectedReplayHop) {
        await route.fulfill({
          status: 200,
          contentType: "application/json",
          body: JSON.stringify({ item: { ...selectedReplayHop, sessionId } }),
        });
        return;
      }
      await route.fulfill({
        status: 200,
        contentType: "application/json",
        body: JSON.stringify({
          items: transitionReplayHistory.map((event) => ({ ...event, sessionId })),
          nextCursor: null,
          totalItems: transitionReplayHistory.length,
          totalSuccessfulItems: transitionReplayHistory.filter((event) => event.action !== "failed_change").length,
          complete: true,
        }),
      });
      return;
    }
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

export async function openAuditPage(page, options = {}) {
  monitorBrowserFailures(page);
  const fixtures = await installApiFixtures(page, options);
  await page.goto(options.url ?? "/filesystem-activity?view=audit&sessionId=live-session&hop=deep-hop");
  await expect(page.getByRole("toolbar", { name: "Audit session and replay toolbar" })).toBeVisible({ timeout: 15_000 });
  await expect(page.getByRole("combobox").first()).toBeVisible();
  await assertNoBrowserFailures(page);
  return fixtures;
}

export async function selectTargetPath(page) {
  await page.getByRole("combobox").nth(1).click();
  await page.getByRole("option", { name: /\/var\/log \d+ sessions/ }).click();
}
