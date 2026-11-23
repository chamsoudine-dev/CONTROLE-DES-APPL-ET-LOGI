// Fiche appli : services, déploiements et actions, droits (complétée en phase 3 : dépôt, médias, licences).
import * as React from "react";
import {
  call,
  errorMessage,
  type ActionSpec,
  type AppDetail,
  type ConnectorRow,
  type Resource,
  type TestReport,
} from "@/lib/api";
import { formatDate } from "@/lib/utils";
import { Alert, Badge, Button, Card, CardTitle, Empty, Input, Modal } from "@/components/ui";
import { PermissionMatrix } from "@/components/PermissionMatrix";
import { useAction } from "@/components/ActionDialog";
import { useReauth } from "@/components/Reauth";
import { appSections } from "./appSections";
import type { PageProps } from "./registry";

export function AppDetailPage({ nav, appId }: PageProps) {
  const [d, setD] = React.useState<AppDetail | null>(null);
  const [err, setErr] = React.useState("");
  const reauth = useReauth();
  const load = React.useCallback(async () => {
    if (!appId) return;
    try {
      setD(await call<AppDetail>("app_get", { id: appId }));
    } catch (e) {
      setErr(errorMessage(e));
    }
  }, [appId]);
  React.useEffect(() => {
    load();
  }, [load]);

  if (!appId) return <Empty>Choisissez une application dans le tableau de bord.</Empty>;
  if (err && !d) return <Alert tone="destructive">{err}</Alert>;
  if (!d) return null;
  const { app } = d;
  const modeTone = app.access_mode === "read_write" ? "warning" : app.access_mode === "disabled" ? "destructive" : "muted";

  return (
    <div className="space-y-6">
      <div className="flex flex-wrap items-center gap-3">
        <span className="text-3xl">{app.icon?.startsWith("data:") ? <img src={app.icon} alt="" className="h-10 w-10 rounded" /> : app.icon}</span>
        <div className="flex-1">
          <h1 className="text-2xl font-bold">{app.name}</h1>
          <p className="text-sm text-muted-foreground">{app.description}</p>
        </div>
        <Badge tone={modeTone}>{app.access_mode === "read_only" ? "Lecture seule" : app.access_mode === "read_write" ? "Lecture-écriture" : "Désactivé"}</Badge>
        <Button variant="outline" size="sm" onClick={() => nav.go("keys", app.id)}>Clés & variables</Button>
        <Button
          variant="destructive"
          size="sm"
          onClick={async () => {
            if (!confirm(`Supprimer « ${app.name} » et ses secrets ?`)) return;
            try {
              await reauth(() => call("app_delete", { id: app.id }));
              nav.go("dashboard");
            } catch (e) {
              setErr(errorMessage(e));
            }
          }}
        >
          Supprimer
        </Button>
      </div>
      {err && <Alert tone="destructive">{err}</Alert>}
      {app.urls.length > 0 && (
        <p className="text-sm">{app.urls.map((u) => <code key={u} className="mr-3">{u}</code>)}</p>
      )}
      <div className="grid gap-6 xl:grid-cols-2">
        {appSections.map((Section, i) => <Section key={i} detail={d} reload={load} />)}
        {d.connectors.filter((c) => c.provider !== "github").map((c) => (
          <ConnectorCard key={c.id} c={c} onChanged={load} />
        ))}
      </div>
      <Card>
        <CardTitle>Droits</CardTitle>
        <PermissionMatrix appId={app.id} mode={app.access_mode} matrix={d.matrix} onChanged={load} />
      </Card>
    </div>
  );
}

export function ConnectorCard({ c, onChanged }: { c: ConnectorRow; onChanged: () => void }) {
  const [resources, setResources] = React.useState<Resource[] | null>(null);
  const [actions, setActions] = React.useState<ActionSpec[]>([]);
  const [report, setReport] = React.useState<TestReport | null>(null);
  const [custom, setCustom] = React.useState<ActionSpec | null>(null);
  const [param, setParam] = React.useState("");
  const [err, setErr] = React.useState("");
  const action = useAction();

  const load = React.useCallback(async () => {
    setErr("");
    try {
      setResources(await call<Resource[]>("connector_resources", { connectorId: c.id }));
      setActions(await call<ActionSpec[]>("connector_actions", { connectorId: c.id }));
    } catch (e) {
      setErr(errorMessage(e));
      setResources([]);
    }
  }, [c.id]);
  React.useEffect(() => {
    load();
  }, [load]);

  const run = (a: ActionSpec, params: Record<string, unknown>) =>
    action.start(() => call("action_prepare", { connectorId: c.id, action: a.id, params }), () => { load(); onChanged(); }).catch(() => undefined);

  const deploymentActions = actions.filter((a) => a.id === "redeploy" || a.id === "rollback");
  const otherActions = actions.filter((a) => !deploymentActions.includes(a) && a.id !== "env_push" && a.id !== "env_delete");

  return (
    <Card>
      <CardTitle
        actions={
          <>
            <Button size="sm" variant="outline" onClick={async () => { try { setReport(await call<TestReport>("connector_test", { connectorId: c.id })); } catch (e) { setErr(errorMessage(e)); } }}>Tester</Button>
            {otherActions.map((a) => (
              <Button key={a.id} size="sm" variant="outline" onClick={() => { setCustom(a); setParam(""); }}>{a.label}</Button>
            ))}
          </>
        }
      >
        {c.provider} <span className="text-xs font-normal text-muted-foreground">({c.category})</span>
      </CardTitle>
      {report && <Alert tone={report.ok ? "success" : "destructive"}>{report.ok ? "Connexion OK." : "Échec."} {report.warnings.join(" ")}</Alert>}
      {err && <Alert tone="destructive">{err}</Alert>}
      {action.error && <Alert tone="destructive">{action.error}</Alert>}
      {action.result && <Alert tone="success">{action.result}</Alert>}
      {resources === null ? (
        <p className="text-sm text-muted-foreground">Chargement…</p>
      ) : resources.length === 0 ? (
        <Empty>Aucune ressource.</Empty>
      ) : (
        <ul className="max-h-72 divide-y overflow-auto text-sm">
          {resources.map((r) => (
            <li key={r.id} className="flex flex-wrap items-center gap-2 py-2">
              <Badge tone={/ready|success|active|deploy/i.test(r.status ?? "") ? "success" : /error|fail/i.test(r.status ?? "") ? "destructive" : "muted"}>{r.status ?? r.kind}</Badge>
              <span className="min-w-0 flex-1 truncate">{r.name || r.id}</span>
              <span className="text-xs text-muted-foreground">{formatDate(r.created_at)}</span>
              {deploymentActions.map((a) => (
                <Button key={a.id} size="sm" variant={a.id === "rollback" ? "outline" : "ghost"} onClick={() => run(a, { deployment_id: r.id })}>{a.label}</Button>
              ))}
            </li>
          ))}
        </ul>
      )}
      <Modal open={custom !== null} title={custom?.label ?? ""} onClose={() => setCustom(null)}>
        {custom && (
          <div className="space-y-3">
            <p className="text-sm text-muted-foreground">{custom.description}</p>
            <Input placeholder='Paramètres JSON, ex. {"tag":"v1.2.0"}' value={param} onChange={(e) => setParam(e.target.value)} />
            <Button onClick={() => { let p: Record<string, unknown> = {}; try { p = param ? JSON.parse(param) : {}; } catch { setErr("JSON invalide"); return; } setCustom(null); run(custom, p); }}>Prévisualiser</Button>
          </div>
        )}
      </Modal>
      {action.dialog}
    </Card>
  );
}
