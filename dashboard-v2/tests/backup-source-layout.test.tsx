// @vitest-environment happy-dom
import { fireEvent, render, screen } from "@testing-library/react";
import { MotionGlobalConfig } from "framer-motion";
import { afterEach, describe, expect, it, vi } from "vitest";

import { BackupSourceMap } from "../src/components/dashboard/BackupSourceMap";

vi.mock("../src/components/dashboard/HardwareBackupStatus", () => ({
  HardwareBackupStatus: () => <div data-testid="hardware-detail">Hardware detail loaded</div>,
}));

MotionGlobalConfig.skipAnimations = true;

afterEach(() => {
  vi.unstubAllGlobals();
  document.body.innerHTML = "";
});

describe("backup source layout", () => {
  it("keeps hardware actions and operational detail collapsed until requested", () => {
    vi.stubGlobal("fetch", vi.fn(() => new Promise(() => {})));
    render(<BackupSourceMap />);

    const hardwareButton = screen.getByRole("button", { name: /Hardware actions & history/ });
    const operationsButton = screen.getByRole("button", { name: /Activity, recovery & policy/ });
    expect(hardwareButton.getAttribute("aria-expanded")).toBe("false");
    expect(operationsButton.getAttribute("aria-expanded")).toBe("false");
    expect(screen.queryByTestId("hardware-detail")).toBeNull();

    fireEvent.click(hardwareButton);
    expect(hardwareButton.getAttribute("aria-expanded")).toBe("true");
    expect(screen.getByTestId("hardware-detail")).toBeTruthy();

    fireEvent.click(hardwareButton);
    expect(hardwareButton.getAttribute("aria-expanded")).toBe("false");
    fireEvent.click(operationsButton);
    expect(operationsButton.getAttribute("aria-expanded")).toBe("true");
    expect(screen.getByLabelText("Loading backup details")).toBeTruthy();
  });
});
