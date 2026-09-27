// @vitest-environment happy-dom
import { MotionGlobalConfig } from "framer-motion";
import { fireEvent, render, screen } from "@testing-library/react";
import { afterEach, describe, expect, it, vi } from "vitest";

import { ScheduleRangePicker } from "../src/components/dashboard/BackupSchedulePickers";

MotionGlobalConfig.skipAnimations = true;

afterEach(() => {
  document.body.innerHTML = "";
});

describe("temporary backup range picker", () => {
  it("counts both boundary dates when the range crosses a month", () => {
    const onChange = vi.fn();
    render(<ScheduleRangePicker startDate="2026-09-27" durationDays={7} today="2026-09-27" onChange={onChange} disabled={false} />);

    fireEvent.click(screen.getByRole("button", { name: /Backup date range:/ }));
    fireEvent.click(screen.getByRole("button", { name: "27 Sept 2026" }));
    fireEvent.click(screen.getByRole("button", { name: "3 Oct 2026" }));

    expect(onChange).toHaveBeenCalledWith("2026-09-27", 7);
  });

  it("limits the last selected date to 90 inclusive days", async () => {
    render(<ScheduleRangePicker startDate="2026-09-27" durationDays={7} today="2026-09-27" onChange={vi.fn()} disabled={false} />);

    fireEvent.click(screen.getByRole("button", { name: /Backup date range:/ }));
    fireEvent.click(screen.getByRole("button", { name: "27 Sept 2026" }));
    fireEvent.click(screen.getByRole("button", { name: "Next five weeks" }));
    fireEvent.click(screen.getByRole("button", { name: "Next five weeks" }));

    expect((await screen.findByRole("button", { name: "25 Dec 2026" })).hasAttribute("disabled")).toBe(false);
    expect(screen.getByRole("button", { name: "26 Dec 2026" }).hasAttribute("disabled")).toBe(true);
  });
});
