import { describe, expect, it } from "vitest";
import { formatDate, passphraseScore, timeAgo } from "./utils";
import { errorMessage, isCoreError } from "./api";

describe("utils", () => {
  it("score de phrase secrète", () => {
    expect(passphraseScore("abc")).toBe(0);
    expect(passphraseScore("correct horse battery staple")).toBeGreaterThanOrEqual(3);
  });
  it("durées relatives", () => {
    const now = Date.parse("2026-01-01T12:00:00Z");
    expect(timeAgo(null)).toBe("jamais");
    expect(timeAgo("2026-01-01T11:59:30Z", now)).toBe("à l'instant");
    expect(timeAgo("2026-01-01T11:00:00Z", now)).toBe("il y a 1 h");
    expect(timeAgo("2025-12-30T12:00:00Z", now)).toBe("il y a 2 j");
    expect(formatDate(null)).toBe("—");
  });
  it("erreurs du cœur", () => {
    expect(isCoreError({ code: "locked", message: "verrouillé" })).toBe(true);
    expect(errorMessage({ code: "x", message: "m" })).toBe("m");
    expect(errorMessage(new Error("e"))).toBe("e");
    expect(errorMessage("s")).toBe("s");
  });
});
