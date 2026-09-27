import { describe, expect, it } from "vitest";
import { renderToStaticMarkup } from "react-dom/server";
import { createElement } from "react";
import { decodedQueryForDisplay, reportedClient, requestTargetForDisplay } from "@/lib/web-http-presentation";

describe("HTTP request presentation", () => {
  it("labels a reported client without treating it as verified identity", () => {
    expect(reportedClient("Mozilla/5.0 Firefox/156.0")).toBe("Firefox 156.0");
    expect(reportedClient("curl/8.18.0")).toBe("curl 8.18.0");
    expect(reportedClient(null)).toBeNull();
  });

  it("keeps an encoded query separate from the decoded reading aid", () => {
    const raw = "q=%3Cscript%3Ealert(1)%3C%2Fscript%3E";
    expect(decodedQueryForDisplay(raw)).toBe("q=<script>alert(1)</script>");
    expect(raw).toContain("%3Cscript%3E");
    expect(decodedQueryForDisplay("q=%ZZ")).toBeNull();
  });

  it("renders submitted XSS as inert escaped text, not executable HTML", () => {
    const decoded = decodedQueryForDisplay("q=%3Cscript%3Ealert(1)%3C%2Fscript%3E");
    const html = renderToStaticMarkup(createElement("code", null, decoded));
    expect(html).toContain("q=&lt;script&gt;alert(1)&lt;/script&gt;");
    expect(html).not.toContain("<script>alert(1)</script>");
  });

  it("shows captured path and query literally to Admin, but keeps them hidden otherwise", () => {
    const payload = { rawPath: "/<script>alert(1)</script>", query: "q=%3Csvg%20onload%3Dalert(1)%3E", truncatedFields: [] };
    const result = requestTargetForDisplay("[redacted-path]", payload, true);
    expect(result.target).toBe("/<script>alert(1)</script>?q=%3Csvg%20onload%3Dalert(1)%3E");
    expect(requestTargetForDisplay("[redacted-path]", payload, false).target).toBe("[redacted-path]");
    const html = renderToStaticMarkup(createElement("code", null, result.target));
    expect(html).toContain("&lt;script&gt;");
    expect(html).not.toContain("<script>");
  });

  it("does not invent an old path and marks captured truncation", () => {
    expect(requestTargetForDisplay("[redacted-path]", undefined, true).target).toBe("[original path not stored]");
    expect(requestTargetForDisplay("/login", { rawPath: "/long", query: null, truncatedFields: ["http.raw_path"] }, true))
      .toEqual({ target: "/long", truncated: true });
  });
});
