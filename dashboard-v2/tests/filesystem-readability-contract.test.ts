import { readdirSync, readFileSync } from "node:fs";
import { join } from "node:path";
import { describe, expect, it } from "vitest";

const filesystemComponentDirectory = join(process.cwd(), "src/components/filesystem");
const globalStyles = readFileSync(join(process.cwd(), "src/app/globals.css"), "utf8");

function hexToLuminance(hex: string): number {
  const channels = hex.slice(1).match(/.{2}/g)?.map((value) => Number.parseInt(value, 16) / 255) ?? [];
  const linear = channels.map((value) => value <= 0.04045 ? value / 12.92 : ((value + 0.055) / 1.055) ** 2.4);
  return 0.2126 * (linear[0] ?? 0) + 0.7152 * (linear[1] ?? 0) + 0.0722 * (linear[2] ?? 0);
}

function contrastRatio(left: string, right: string): number {
  const light = Math.max(hexToLuminance(left), hexToLuminance(right));
  const dark = Math.min(hexToLuminance(left), hexToLuminance(right));
  return (light + 0.05) / (dark + 0.05);
}

function themeTokens(selector: string): Record<string, string> {
  const block = globalStyles.match(new RegExp(`${selector}\\s*\\{([^}]+)\\}`))?.[1] ?? "";
  return Object.fromEntries(
    [...block.matchAll(/(--[\w-]+):\s*(#[0-9A-Fa-f]{6})/g)].map((match) => [match[1], match[2]]),
  );
}

describe("FSV-012B readability contract", () => {
  it("does not render filesystem presentation text below the 12px text-xs floor", () => {
    const violations = readdirSync(filesystemComponentDirectory)
      .filter((file) => file.endsWith(".tsx"))
      .flatMap((file) => {
        const source = readFileSync(join(filesystemComponentDirectory, file), "utf8");
        return [...source.matchAll(/text-\[(?:9|10|11)px\]/g)].map((match) => `${file}:${match[0]}`);
      });

    expect(violations).toEqual([]);
  });

  it.each([
    [":root, :root\\[data-theme=\"light\"\\]", "light"],
    [":root\\[data-theme=\"dark\"\\]", "dark"],
  ])("keeps core %s text tokens at WCAG AA contrast on filesystem surfaces", (selector, theme) => {
    const tokens = themeTokens(selector);
    const failures = ["--text", "--text-muted", "--text-subtle"].flatMap((foreground) =>
      ["--surface", "--canvas"].flatMap((background) => {
        const ratio = contrastRatio(tokens[foreground] ?? "#000000", tokens[background] ?? "#000000");
        return ratio < 4.5 ? [`${theme}:${foreground}/${background}:${ratio.toFixed(2)}`] : [];
      }),
    );
    expect(failures).toEqual([]);
  });
});
