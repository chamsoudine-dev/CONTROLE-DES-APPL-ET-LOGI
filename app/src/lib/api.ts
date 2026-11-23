// Couche d'accès au cœur Rust. L'interface n'a AUCUNE logique sensible : elle affiche.
import { invoke } from "@tauri-apps/api/core";

export interface CoreError {
  code: string;
  message: string;
}

export function isCoreError(e: unknown): e is CoreError {
  return typeof e === "object" && e !== null && "code" in e && "message" in e;
}

export function errorMessage(e: unknown): string {
  if (isCoreError(e)) return e.message;
  if (e instanceof Error) return e.message;
  return String(e);
}

export async function call<T>(cmd: string, args?: Record<string, unknown>): Promise<T> {
  return invoke<T>(cmd, args);
}

// ---------- Types partagés ----------
export interface VaultStatus {
  state: "uninitialized" | "locked" | "totp_required" | "unlocked";
  pin_available: boolean;
  secret_backend: string;
  autolock_secs: number | null;
}
export interface Profile {
  id: string;
  display_name: string;
  totp_enabled: boolean;
  autolock_secs: number;
  github_login: string | null;
  sync_repo: string | null;
  revocation_repo: string | null;
  license_kid: string | null;
}
export interface TotpSetup {
  secret_base32: string;
  otpauth_url: string;
  qr_png_base64: string;
}
export interface PermissionSpec {
  scope: string;
  access: "read" | "write";
  reason: string;
  required_for_read_only: boolean;
}
export interface DetectedPermission {
  scope: string;
  access: "read" | "write";
  granted: boolean;
}
export interface TestReport {
  ok: boolean;
  identity: string | null;
  permissions: DetectedPermission[];
  warnings: string[];
  too_powerful: boolean;
  expires_at: string | null;
  can_read: boolean;
  can_write: boolean;
}
export interface Repo {
  full_name: string;
  private: boolean;
  html_url: string;
  default_branch: string | null;
  pushed_at: string | null;
  description: string | null;
}
export interface DeviceCode {
  device_code: string;
  user_code: string;
  verification_uri: string;
  expires_in: number;
  interval: number;
}
export interface AuditEntry {
  seq: number;
  ts: string;
  actor: string;
  action: string;
  target: string;
  details: string;
  outcome: string;
  hash: string;
}
export interface Device {
  id: string;
  name: string;
  platform: string;
  is_current: boolean;
  revoked_at: string | null;
  last_seen: string | null;
}
