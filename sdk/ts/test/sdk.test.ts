import { describe, expect, it } from "vitest";
import { readFileSync } from "node:fs";
import { importPublicKey, LicenseChecker, LicenseError, LicenseVerifier, pae, b64urlDecode } from "../dist/index.js";

const fx = JSON.parse(readFileSync(new URL("../../fixtures.json", import.meta.url), "utf8"));
const at = (s: string) => new Date(s);

async function code(p: Promise<unknown>): Promise<string> {
  try {
    await p;
    return "ok";
  } catch (e) {
    return e instanceof LicenseError ? e.code : String(e);
  }
}

describe("compatibilité avec l'implémentation Rust", () => {
  it("kid PASERK identique", () => {
    expect(importPublicKey(fx.public_keys[0]).kid).toBe(fx.kid);
  });

  it("licence valide", async () => {
    const v = new LicenseVerifier(fx.public_keys);
    const c = await v.verify(fx.valid, at(fx.t_valid));
    expect(c.id).toBe(fx.license_id);
    expect(c.productName).toBe("Pro");
    expect(c.customerName).toBe("Awa Diallo");
    expect(c.features).toEqual(["export", "multi-postes"]);
    expect(c.options.seats).toBe(3);
    expect(c.kind).toBe("subscription");
    const p = await v.verify(fx.perpetual, at("2099-01-01T00:00:00Z"));
    expect(p.expiresAt).toBeNull();
  });

  it("falsifiée, autre clé, dates", async () => {
    const v = new LicenseVerifier(fx.public_keys);
    expect(await code(v.verify(fx.tampered, at(fx.t_valid)))).toBe("bad_signature");
    expect(await code(v.verify(fx.forged_other_key, at(fx.t_valid)))).toBe("unknown_key");
    expect(await code(v.verify(fx.valid, at(fx.t_after_expiry)))).toBe("expired");
    expect(await code(v.verify(fx.valid, at(fx.t_before_issue)))).toBe("not_yet_valid");
    expect(await code(v.verify("v2.public.xxx", at(fx.t_valid)))).toBe("unsupported_header");
    expect(await code(v.verify("v4.public.@@.x", at(fx.t_valid)))).toBe("malformed");
    expect(await code(v.verify(fx.revocation_list_seq1, at(fx.t_valid)))).toBe("wrong_type");
    // Chaque octet modifié est rejeté.
    for (let i = 10; i < fx.valid.length; i += 7) {
      const t = fx.valid.slice(0, i) + (fx.valid[i] === "A" ? "B" : "A") + fx.valid.slice(i + 1);
      expect(await code(v.verify(t, at(fx.t_valid)))).not.toBe("ok");
    }
  });

  it("révocation, anti-rollback, liste forgée, délai de grâce", async () => {
    const v = new LicenseVerifier(fx.public_keys);
    const mem = new Map<string, string>();
    const store = { get: (k: string) => mem.get(k) ?? null, set: (k: string, val: string) => void mem.set(k, val) };
    const ch = new LicenseChecker(v, { graceDays: 14, store });
    expect((await ch.check(fx.valid, at(fx.t_valid))).offlineDaysLeft).toBe(13);
    expect(await code(ch.check(fx.valid, at(fx.t_grace_exceeded)))).toBe("grace_expired");
    await ch.updateRevocations(fx.revocation_list_seq1, at(fx.t_valid));
    expect((await ch.check(fx.valid, at(fx.t_valid))).revocationSeq).toBe(1);
    await ch.updateRevocations(fx.revocation_list_seq2_revokes_valid, at(fx.t_valid));
    expect(await code(ch.check(fx.valid, at(fx.t_valid)))).toBe("revoked");
    expect(await code(ch.updateRevocations(fx.revocation_list_seq1, at(fx.t_valid)))).toBe("rollback");
    expect(await code(ch.updateRevocations(fx.revocation_list_forged, at(fx.t_valid)))).toBe("unknown_key");
    // Cache persisté puis restauré.
    const ch2 = new LicenseChecker(v, { store });
    await ch2.restore();
    expect(await code(ch2.check(fx.valid, at(fx.t_valid)))).toBe("revoked");
  });

  it("téléchargement de la liste (fetch simulé)", async () => {
    const v = new LicenseVerifier(fx.public_keys);
    const fetchOk = (async () => new Response(fx.revocation_list_seq2_revokes_valid)) as unknown as typeof fetch;
    const ch = new LicenseChecker(v, { revocationUrl: "https://example.invalid/r", fetch: fetchOk });
    expect(await ch.refresh(at(fx.t_valid))).toBe(true);
    expect(await code(ch.check(fx.valid, at(fx.t_valid)))).toBe("revoked");
    const offline = (async () => { throw new TypeError("network"); }) as unknown as typeof fetch;
    const ch2 = new LicenseChecker(v, { revocationUrl: "https://example.invalid/r", fetch: offline });
    expect(await ch2.refresh(at(fx.t_valid))).toBe(false);
    expect(await code(ch2.check(fx.valid, at(fx.t_valid)))).toBe("ok");
  });

  it("utilitaires", () => {
    expect(pae([]).length).toBe(8);
    expect(() => b64urlDecode("a")).toThrow();
    expect(() => importPublicKey("k3.public.AAAA")).toThrow();
  });
});
