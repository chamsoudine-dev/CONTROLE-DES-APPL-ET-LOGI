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

// ---------- Phase 2 ----------
export type AccessMode = "read_only" | "read_write" | "disabled";
export type PolicyAction = "view" | "redeploy" | "rollback" | "release" | "edit_env" | "media" | "licenses" | "delete";
export const ACTION_LABELS: Record<PolicyAction, string> = {
  view: "Voir",
  redeploy: "Redéployer",
  rollback: "Rollback",
  release: "Tag / release / workflow",
  edit_env: "Modifier les variables",
  media: "Médias",
  licenses: "Licences",
  delete: "Supprimer",
};
export type ProviderId = "github" | "vercel" | "supabase" | "firebase" | "netlify" | "cloudflare" | "cloudinary" | "custom";
export interface App {
  id: string;
  name: string;
  description: string;
  icon: string | null;
  urls: string[];
  repo: string | null;
  access_mode: AccessMode;
  licensing_enabled: boolean;
  created_at: string;
  updated_at: string;
}
export interface NewApp {
  name: string;
  description: string;
  icon: string | null;
  urls: string[];
  repo: string | null;
  access_mode: AccessMode | null;
  licensing_enabled: boolean;
}
export interface ConnectorRow {
  id: string;
  app_id: string;
  provider: ProviderId;
  category: string;
  config: Record<string, unknown>;
  secret_id: string | null;
  last_test_at: string | null;
  last_test_ok: boolean | null;
  detected_permissions: DetectedPermission[];
}
export interface SecretMeta {
  id: string;
  app_id: string | null;
  environment: string;
  provider: string;
  name: string;
  masked: string;
  fingerprint: string;
  created_at: string;
  updated_at: string;
  last_used_at: string | null;
  expires_at: string | null;
  detected_permissions: DetectedPermission[] | null;
  too_powerful: boolean;
}
export interface AppDetail {
  app: App;
  matrix: Partial<Record<PolicyAction, boolean>>;
  connectors: ConnectorRow[];
  secrets: SecretMeta[];
}
export interface FieldSpec {
  key: string;
  label: string;
  required: boolean;
  help: string;
  options: string[];
}
export interface ProviderInfo {
  provider: ProviderId;
  label: string;
  category: string;
  fields: FieldSpec[];
  secret_label: string;
  secret_help: string;
  permissions: PermissionSpec[];
  media: boolean;
}
export interface Resource {
  id: string;
  kind: string;
  name: string;
  url: string | null;
  status: string | null;
  created_at: string | null;
  extra: Record<string, unknown> | null;
}
export interface ActionSpec {
  id: string;
  label: string;
  policy_action: PolicyAction;
  description: string;
}
export interface Prepared {
  token: string;
  preview: string;
  policy_action: PolicyAction;
  destructive: boolean;
}
export interface EnvVar {
  id: string;
  app_id: string;
  environment: string;
  key: string;
  value: string;
  secret_id: string | null;
  updated_at: string;
  pushed: boolean;
}
export interface DiffLine {
  key: string;
  change: "added" | "changed" | "removed" | "unchanged";
}
export interface ImportReportT {
  apps_created: number;
  apps_skipped: string[];
  secrets: number;
  env_vars: number;
}
