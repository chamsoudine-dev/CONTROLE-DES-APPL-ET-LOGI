// Mode d'accès par appli + matrice des actions autorisées.
import * as React from "react";
import { ACTION_LABELS, call, errorMessage, type AccessMode, type PolicyAction } from "@/lib/api";
import { Alert, Badge, Button } from "./ui";
import { useReauth } from "./Reauth";

const MODES: { id: AccessMode; label: string; help: string }[] = [
  { id: "read_only", label: "Lecture seule", help: "Aucune écriture possible chez les fournisseurs." },
  { id: "read_write", label: "Lecture-écriture", help: "Écritures autorisées selon la matrice, avec confirmation." },
  { id: "disabled", label: "Désactivé", help: "Aucun accès, même en lecture." },
];

export function PermissionMatrix({
  appId,
  mode,
  matrix,
  onChanged,
}: {
  appId: string;
  mode: AccessMode;
  matrix: Partial<Record<PolicyAction, boolean>>;
  onChanged: () => void;
}) {
  const [err, setErr] = React.useState("");
  const reauth = useReauth();
  async function run(fn: () => Promise<unknown>) {
    setErr("");
    try {
      await reauth(fn);
      onChanged();
    } catch (e) {
      setErr(errorMessage(e));
    }
  }
  return (
    <div className="space-y-4">
      <div className="flex flex-wrap gap-2">
        {MODES.map((m) => (
          <Button key={m.id} size="sm" variant={mode === m.id ? "default" : "outline"} title={m.help} onClick={() => run(() => call("app_set_mode", { id: appId, mode: m.id }))}>
            {m.label}
          </Button>
        ))}
      </div>
      <p className="text-xs text-muted-foreground">{MODES.find((m) => m.id === mode)?.help}</p>
      <div className="grid grid-cols-1 gap-2 sm:grid-cols-2">
        {(Object.keys(ACTION_LABELS) as PolicyAction[]).map((a) => {
          const allowed = matrix[a] ?? false;
          const effective = mode !== "disabled" && allowed && (a === "view" || mode === "read_write");
          return (
            <label key={a} className="flex items-center justify-between rounded border px-3 py-2 text-sm">
              <span>
                {ACTION_LABELS[a]} {a === "delete" || a === "rollback" ? <Badge tone="warning">ré-auth</Badge> : null}
              </span>
              <span className="flex items-center gap-2">
                {!effective && allowed && <Badge tone="muted">bloqué par le mode</Badge>}
                <input type="checkbox" checked={allowed} onChange={(e) => run(() => call("app_set_permission", { id: appId, action: a, allowed: e.target.checked }))} />
              </span>
            </label>
          );
        })}
      </div>
      {err && <Alert tone="destructive">{err}</Alert>}
    </div>
  );
}
