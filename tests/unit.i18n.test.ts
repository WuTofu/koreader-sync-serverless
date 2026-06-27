import { describe, expect, it } from "vitest";
import { pickLocale } from "../src/i18n";

describe("pickLocale", () => {
  it("picks English when it has the highest q even though zh appears later", () => {
    expect(pickLocale("en-US,en;q=0.9,zh-TW;q=0.8,zh;q=0.7")).toBe("en");
  });

  it("picks Chinese when it is genuinely the top preference", () => {
    expect(pickLocale("zh-TW,zh;q=0.9,en;q=0.8")).toBe("zh");
  });

  it("picks Japanese when it is listed first", () => {
    expect(pickLocale("ja,en;q=0.5")).toBe("ja");
  });

  it("falls back to English for an empty header", () => {
    expect(pickLocale("")).toBe("en");
  });

  it("falls back to English when the header is absent", () => {
    expect(pickLocale(undefined)).toBe("en");
    expect(pickLocale(null)).toBe("en");
  });

  it("falls back to English for unsupported language tags only", () => {
    expect(pickLocale("fr-FR,de;q=0.8")).toBe("en");
  });
});
