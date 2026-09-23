// @vitest-environment happy-dom
import { act, createElement } from "react";
import { createRoot, type Root } from "react-dom/client";
import { afterEach, beforeEach, describe, expect, it, vi } from "vitest";

import { TimelineSplitter } from "../src/components/filesystem/TimelineSplitter";
import { useTimelineDrag } from "../src/components/filesystem/useTimelineDrag";
import {
  DEFAULT_TIMELINE_SIDEBAR_WIDTH,
  MAX_TIMELINE_SIDEBAR_WIDTH,
  MIN_TIMELINE_SIDEBAR_WIDTH,
} from "../src/components/filesystem/filesystemUtils";

// @ts-expect-error React act environment flag
globalThis.IS_REACT_ACT_ENVIRONMENT = true;

function pointerEvent(
  type: string,
  { pointerId, pointerType, clientX }: { pointerId: number; pointerType: string; clientX: number },
): Event {
  const event = new Event(type, { bubbles: true, cancelable: true });
  Object.defineProperties(event, {
    pointerId: { value: pointerId },
    pointerType: { value: pointerType },
    clientX: { value: clientX },
    isPrimary: { value: true },
    button: { value: 0 },
  });
  return event;
}

function SplitterProbe() {
  const drag = useTimelineDrag();
  return createElement(
    "div",
    null,
    createElement(TimelineSplitter, {
      isDragging: drag.isDraggingTimeline,
      width: drag.timelineWidth,
      onPointerDown: drag.handleSplitterPointerDown,
      onPointerMove: drag.handleSplitterPointerMove,
      onPointerUp: drag.handleSplitterPointerUp,
      onPointerCancel: drag.handleSplitterPointerCancel,
      onDoubleClick: drag.handleResetTimelineWidth,
      onKeyDown: drag.handleSplitterKeyDown,
    }),
  );
}

describe("FSV-011 pointer-capable timeline splitter", () => {
  let container: HTMLDivElement;
  let root: Root;

  beforeEach(async () => {
    localStorage.clear();
    container = document.createElement("div");
    document.body.appendChild(container);
    root = createRoot(container);
    await act(async () => root.render(createElement(SplitterProbe)));
  });

  afterEach(async () => {
    await act(async () => root.unmount());
    container.remove();
    document.body.style.userSelect = "";
    document.body.style.cursor = "";
    vi.restoreAllMocks();
  });

  function separator(): HTMLElement {
    return container.querySelector('[role="separator"]') as HTMLElement;
  }

  it.each(["mouse", "touch", "pen"])("resizes with primary %s pointer capture", async (pointerType) => {
    const target = separator() as HTMLElement & {
      setPointerCapture?: (pointerId: number) => void;
      releasePointerCapture?: (pointerId: number) => void;
    };
    const setPointerCapture = vi.fn();
    const releasePointerCapture = vi.fn();
    target.setPointerCapture = setPointerCapture;
    target.releasePointerCapture = releasePointerCapture;

    await act(async () => {
      target.dispatchEvent(pointerEvent("pointerdown", { pointerId: 7, pointerType, clientX: 500 }));
      target.dispatchEvent(pointerEvent("pointermove", { pointerId: 7, pointerType, clientX: 452 }));
    });

    expect(setPointerCapture).toHaveBeenCalledWith(7);
    expect(target.getAttribute("aria-valuenow")).toBe(String(DEFAULT_TIMELINE_SIDEBAR_WIDTH + 48));
    expect(target.getAttribute("aria-valuetext")).toContain(`${DEFAULT_TIMELINE_SIDEBAR_WIDTH + 48} pixels`);
    expect(document.body.style.userSelect).toBe("none");
    expect(document.body.style.cursor).toBe("col-resize");

    await act(async () => {
      target.dispatchEvent(pointerEvent("pointerup", { pointerId: 7, pointerType, clientX: 452 }));
    });
    expect(releasePointerCapture).toHaveBeenCalledWith(7);
    expect(document.body.style.userSelect).toBe("");
    expect(document.body.style.cursor).toBe("");
  });

  it("cancels an active drag, ignores later movement, and releases capture", async () => {
    const target = separator() as HTMLElement & {
      setPointerCapture?: (pointerId: number) => void;
      releasePointerCapture?: (pointerId: number) => void;
    };
    target.setPointerCapture = vi.fn();
    const releasePointerCapture = vi.fn();
    target.releasePointerCapture = releasePointerCapture;

    await act(async () => {
      target.dispatchEvent(pointerEvent("pointerdown", { pointerId: 11, pointerType: "touch", clientX: 500 }));
      target.dispatchEvent(pointerEvent("pointermove", { pointerId: 11, pointerType: "touch", clientX: 470 }));
      target.dispatchEvent(pointerEvent("pointercancel", { pointerId: 11, pointerType: "touch", clientX: 470 }));
    });
    const widthAfterCancel = target.getAttribute("aria-valuenow");

    await act(async () => {
      target.dispatchEvent(pointerEvent("pointermove", { pointerId: 11, pointerType: "touch", clientX: 420 }));
    });
    expect(target.getAttribute("aria-valuenow")).toBe(widthAfterCancel);
    expect(releasePointerCapture).toHaveBeenCalledWith(11);
    expect(document.body.style.userSelect).toBe("");
  });

  it("supports Arrow keys, Home, End, and reset without leaking global listeners", async () => {
    const target = separator();
    await act(async () => target.dispatchEvent(new KeyboardEvent("keydown", { key: "Home", bubbles: true })));
    expect(target.getAttribute("aria-valuenow")).toBe(String(MIN_TIMELINE_SIDEBAR_WIDTH));
    await act(async () => target.dispatchEvent(new KeyboardEvent("keydown", { key: "End", bubbles: true })));
    expect(target.getAttribute("aria-valuenow")).toBe(String(MAX_TIMELINE_SIDEBAR_WIDTH));
    await act(async () => target.dispatchEvent(new KeyboardEvent("keydown", { key: " ", bubbles: true })));
    expect(target.getAttribute("aria-valuenow")).toBe(String(DEFAULT_TIMELINE_SIDEBAR_WIDTH));
  });

  it("releases capture and body drag styles when unmounted mid-drag", async () => {
    const target = separator() as HTMLElement & {
      setPointerCapture?: (pointerId: number) => void;
      releasePointerCapture?: (pointerId: number) => void;
    };
    target.setPointerCapture = vi.fn();
    const releasePointerCapture = vi.fn();
    target.releasePointerCapture = releasePointerCapture;

    await act(async () => {
      target.dispatchEvent(pointerEvent("pointerdown", { pointerId: 19, pointerType: "pen", clientX: 500 }));
    });
    expect(document.body.style.cursor).toBe("col-resize");

    await act(async () => root.unmount());
    expect(releasePointerCapture).toHaveBeenCalledWith(19);
    expect(document.body.style.userSelect).toBe("");
    expect(document.body.style.cursor).toBe("");
    root = createRoot(container);
  });
});
