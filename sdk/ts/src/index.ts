/**
 * SDK de vérification des licences Control Center — hors ligne.
 *
 * - Jetons PASETO v4.public signés Ed25519 (vérification avec @noble/ed25519, audité).
 * - Identifiant de clé `kid` = PASERK k4.pid (BLAKE2b, @noble/hashes).
 * - Liste de révocation signée, numérotée (anti-rollback), délai de grâce hors ligne.
 *
 * Seul l'encodage PASETO (PAE) est implémenté ici : aucune primitive cryptographique maison.
 */
import * as ed from "@noble/ed25519";
import { blake2b } from "@noble/hashes/blake2b";

export type LicenseErrorCode =
  | "malformed"
  | "unsupported_header"
  | "unknown_key"
  | "bad_signature"
  | "wrong_type"
  | "not_yet_valid"
  | "expired"
  | "revoked"
  | "rollback"
  | "grace_expired"
  | "invalid_key";

export class LicenseError extends Error {
  constructor(public readonly code: LicenseErrorCode, message?: string) {
    super(message ?? code);
    this.name = "LicenseError";
  }
}

export type LicenseKind = "perpetual" | "subscription" | "trial";

export interface LicenseClaims {
  id: string;
  productId: string;
  productName: string;
  customerId: string;
  customerName: string;
  kind: LicenseKind;
  issuedAt: Date;
  notBefore: Date | null;
  expiresAt: Date | null;
  features: string[];
  options: Record<string, unknown>;
}

export interface RevocationList {
  seq: number;
  issuedAt: Date;
  revoked: Set<string>;
}

export const ISSUER = "control-center";
const HEADER = "v4.public.";
const TYP_LICENSE = "cc.license.v1";
const TYP_REVOCATION = "cc.revocations.v1";

// ---------- Encodages ----------

export function b64urlDecode(s: string): Uint8Array {
  if (!/^[A-Za-z0-9_-]*$/.test(s)) throw new LicenseError("malformed");
  const pad = s.length % 4 === 2 ? "==" : s.length % 4 === 3 ? "=" : s.length % 4 === 0 ? "" : null;
  if (pad === null) throw new LicenseError("malformed");
  const bin = atob(s.replace(/-/g, "+").replace(/_/g, "/") + pad);
  const out = new Uint8Array(bin.length);
  for (let i = 0; i < bin.length; i++) out[i] = bin.charCodeAt(i);
  return out;
}

export function b64urlEncode(b: Uint8Array): string {
  let bin = "";
  for (const x of b) bin += String.fromCharCode(x);
  return btoa(bin).replace(/\+/g, "-").replace(/\//g, "_").replace(/=+$/, "");
}

const enc = new TextEncoder();
const dec = new TextDecoder("utf-8", { fatal: true });

function le64(n: number): Uint8Array {
  const out = new Uint8Array(8);
  let v = BigInt(n);
  for (let i = 0; i < 8; i++) {
    out[i] = Number(v & 0xffn);
    v >>= 8n;
  }
  out[7]! &= 0x7f;
  return out;
}

/** Pre-Authentication Encoding (spécification PASETO). */
export function pae(pieces: Uint8Array[]): Uint8Array {
  const parts = [le64(pieces.length)];
  for (const p of pieces) parts.push(le64(p.length), p);
  const total = parts.reduce((n, p) => n + p.length, 0);
  const out = new Uint8Array(total);
  let off = 0;
  for (const p of parts) {
    out.set(p, off);
    off += p.length;
  }
  return out;
}

// ---------- Clés ----------

export interface PublicKey {
  bytes: Uint8Array;
  paserk: string;
  kid: string;
}

/** Importe une clé `k4.public.…` et calcule son identifiant `k4.pid.…`. */
export function importPublicKey(paserk: string): PublicKey {
  const p = paserk.trim();
  if (!p.startsWith("k4.public.")) throw new LicenseError("invalid_key");
  const bytes = b64urlDecode(p.slice("k4.public.".length));
  if (bytes.length !== 32) throw new LicenseError("invalid_key");
  const h = blake2b(enc.encode("k4.pid." + p), { dkLen: 33 });
  return { bytes, paserk: p, kid: "k4.pid." + b64urlEncode(h) };
}

// ---------- Vérification ----------

interface RawToken {
  claims: Record<string, unknown>;
}

function parseDate(v: unknown): Date | null {
  if (v === undefined || v === null) return null;
  if (typeof v !== "string") throw new LicenseError("malformed");
  const d = new Date(v);
  if (Number.isNaN(d.getTime())) throw new LicenseError("malformed");
  return d;
}

function str(c: Record<string, unknown>, k: string): string {
  const v = c[k];
  if (typeof v !== "string") throw new LicenseError("malformed");
  return v;
}

export class LicenseVerifier {
  private readonly keys = new Map<string, PublicKey>();

  constructor(publicKeys: string[]) {
    for (const k of publicKeys) {
      const pk = importPublicKey(k);
      this.keys.set(pk.kid, pk);
    }
  }

  private async verifyRaw(token: string, typ: string, maxLen: number): Promise<RawToken> {
    if (typeof token !== "string" || token.length > maxLen) throw new LicenseError("malformed");
    if (!token.startsWith(HEADER)) throw new LicenseError("unsupported_header");
    const parts = token.split(".");
    if (parts.length !== 4) throw new LicenseError("unknown_key");
    const body = b64urlDecode(parts[2]!);
    const footer = b64urlDecode(parts[3]!);
    if (body.length < 64) throw new LicenseError("malformed");
    let kid: unknown;
    try {
      kid = (JSON.parse(dec.decode(footer)) as Record<string, unknown>).kid;
    } catch {
      throw new LicenseError("unknown_key");
    }
    const key = typeof kid === "string" ? this.keys.get(kid) : undefined;
    if (!key) throw new LicenseError("unknown_key");
    const m = body.slice(0, body.length - 64);
    const sig = body.slice(body.length - 64);
    const m2 = pae([enc.encode(HEADER), m, footer, new Uint8Array(0)]);
    let ok = false;
    try {
      ok = await ed.verifyAsync(sig, m2, key.bytes);
    } catch {
      ok = false;
    }
    if (!ok) throw new LicenseError("bad_signature");
    let claims: Record<string, unknown>;
    try {
      claims = JSON.parse(dec.decode(m)) as Record<string, unknown>;
    } catch {
      throw new LicenseError("malformed");
    }
    if (claims.iss !== ISSUER || claims.typ !== typ) throw new LicenseError("wrong_type");
    return { claims };
  }

  /** Vérifie une licence (signature, type, kid, dates) à l'instant `now`. */
  async verify(token: string, now: Date = new Date()): Promise<LicenseClaims> {
    const { claims: c } = await this.verifyRaw(token, TYP_LICENSE, 16 * 1024);
    const kind = c.kind;
    if (kind !== "perpetual" && kind !== "subscription" && kind !== "trial") throw new LicenseError("malformed");
    const features = Array.isArray(c.features) ? c.features.filter((f): f is string => typeof f === "string") : [];
    const lic: LicenseClaims = {
      id: str(c, "jti"),
      productId: str(c, "aud"),
      productName: str(c, "pname"),
      customerId: str(c, "sub"),
      customerName: str(c, "cname"),
      kind,
      issuedAt: parseDate(c.iat) ?? (() => { throw new LicenseError("malformed"); })(),
      notBefore: parseDate(c.nbf),
      expiresAt: parseDate(c.exp),
      features,
      options: typeof c.opt === "object" && c.opt !== null && !Array.isArray(c.opt) ? (c.opt as Record<string, unknown>) : {},
    };
    if (lic.notBefore && now < lic.notBefore) throw new LicenseError("not_yet_valid");
    if (lic.expiresAt && now >= lic.expiresAt) throw new LicenseError("expired");
    return lic;
  }

  /** Vérifie et décode une liste de révocation signée. */
  async verifyRevocationList(token: string): Promise<RevocationList> {
    const { claims: c } = await this.verifyRaw(token, TYP_REVOCATION, 4 * 1024 * 1024);
    if (typeof c.seq !== "number" || !Number.isInteger(c.seq) || c.seq < 0) throw new LicenseError("malformed");
    if (!Array.isArray(c.revoked) || !c.revoked.every((x) => typeof x === "string")) throw new LicenseError("malformed");
    return { seq: c.seq, issuedAt: parseDate(c.iat) ?? new Date(0), revoked: new Set(c.revoked as string[]) };
  }
}

// ---------- Vérification complète côté appli cliente ----------

/** Stockage persistant minimal (localStorage, fichier, Keychain…). */
export interface KeyValueStore {
  get(key: string): string | null | Promise<string | null>;
  set(key: string, value: string): void | Promise<void>;
}

export interface CheckerOptions {
  /** Jours maximum sans liste de révocation fraîche (défaut 14). */
  graceDays?: number;
  /** URL brute de la liste (ex. https://raw.githubusercontent.com/<owner>/<repo>/HEAD/revocations.paseto). */
  revocationUrl?: string;
  store?: KeyValueStore;
  fetch?: typeof fetch;
}

export interface CheckResult {
  claims: LicenseClaims;
  offlineDaysLeft: number;
  revocationSeq: number | null;
}

const CACHE_KEY = "cc-license.revocations";
const DAY = 86_400_000;

export class LicenseChecker {
  private cache: { list: RevocationList; token: string; fetchedAt: Date } | null = null;
  private readonly grace: number;

  constructor(private readonly verifier: LicenseVerifier, private readonly opts: CheckerOptions = {}) {
    this.grace = (opts.graceDays ?? 14) * DAY;
  }

  /** Recharge le cache persisté (re-vérifié). */
  async restore(): Promise<void> {
    const raw = await this.opts.store?.get(CACHE_KEY);
    if (!raw) return;
    try {
      const { token, fetchedAt } = JSON.parse(raw) as { token: string; fetchedAt: string };
      const list = await this.verifier.verifyRevocationList(token);
      this.cache = { list, token, fetchedAt: new Date(fetchedAt) };
    } catch {
      this.cache = null;
    }
  }

  /** Intègre une liste ; refuse un numéro inférieur à celui déjà connu. */
  async updateRevocations(token: string, now: Date = new Date()): Promise<number> {
    const list = await this.verifier.verifyRevocationList(token);
    if (this.cache && list.seq < this.cache.list.seq) throw new LicenseError("rollback");
    this.cache = { list, token, fetchedAt: now };
    await this.opts.store?.set(CACHE_KEY, JSON.stringify({ token, fetchedAt: now.toISOString() }));
    return list.seq;
  }

  /** Télécharge la liste publiée ; en cas d'échec réseau, le cache (et le délai de grâce) s'applique. */
  async refresh(now: Date = new Date()): Promise<boolean> {
    if (!this.opts.revocationUrl) return false;
    const f = this.opts.fetch ?? fetch;
    try {
      const r = await f(this.opts.revocationUrl, { cache: "no-store" });
      if (!r.ok) return false;
      await this.updateRevocations((await r.text()).trim(), now);
      return true;
    } catch (e) {
      if (e instanceof LicenseError && (e.code === "rollback" || e.code === "bad_signature" || e.code === "unknown_key")) throw e;
      return false;
    }
  }

  /** Vérification complète : signature, dates, révocation, délai de grâce hors ligne. */
  async check(token: string, now: Date = new Date()): Promise<CheckResult> {
    const claims = await this.verifier.verify(token, now);
    let reference = claims.issuedAt;
    if (this.cache) {
      if (this.cache.list.revoked.has(claims.id)) throw new LicenseError("revoked");
      reference = this.cache.fetchedAt;
    }
    const deadline = reference.getTime() + this.grace;
    if (now.getTime() > deadline) throw new LicenseError("grace_expired");
    return {
      claims,
      offlineDaysLeft: Math.floor((deadline - now.getTime()) / DAY),
      revocationSeq: this.cache?.list.seq ?? null,
    };
  }
}
