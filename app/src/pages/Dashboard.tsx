// Tableau de bord : toutes les applis, en ligne / hors ligne, dernier déploiement, alertes, quota.
import * as React from "react";
import { RefreshCw } from "lucide-react";
import { call, errorMessage, type AlertItem, type App, type AppStatus, type PollSummary, type RateState, type RepoEvent } from "@/lib/api";
import { timeAgo } from "@/lib/utils";
import { Alert, Badge, Button, Card, CardTitle, Empty, Spinner } from "@/components/ui";
import type { PageProps } from "./registry";

export function DashboardPage({ nav }: PageProps) {
  const [apps, setApps] = React.useState<App[]>([]);
  const [alerts, setAlerts] = React.useState<AlertItem[]>([]);
  const [events, setEvents] = React.useState<RepoEvent[]>([]);
  const [rate, setRate] = React.useState<RateState | null>(null);
  const [polling, setPolling] = React.useState(false);
  const [msg, setMsg] = React.useState("");

  const load = React.useCallback(async () => {
    setApps(await call<App[]>("apps_list"));
    setAlerts(await call<AlertItem[]>("alerts_list"));
    setEvents(await call<RepoEvent[]>("repo_events", { appId: null, limit: 15 }));
    setRate(await call<RateState | null>("github_rate"));
  }, []);
  React.useEffect(() => {
    load().catch((e) => setMsg(errorMessage(e)));
    const t = setInterval(() => load().catch(() => undefined), 60_000);
    return () => clearInterval(t);
  }, [load]);

  async function pollNow() {
    setPolling(true);
    setMsg("");
    try {
      const s = await call<PollSummary>("tracking_poll_now");
      setMsg(`${s.repos} dépôt(s), ${s.requests} requête(s) dont ${s.not_modified} non modifiée(s) (304, sans quota), ${s.new_events} nouvel(s) événement(s).${s.errors.length ? " Erreurs : " + s.errors.join(" ; ") : ""}`);
      await load();
    } catch (e) {
      setMsg(errorMessage(e));
    } finally {
      setPolling(false);
    }
  }

  return (
    <div className="space-y-6">
      <div className="flex flex-wrap items-center justify-between gap-2">
        <h1 className="text-2xl font-bold">Tableau de bord</h1>
        <div className="flex items-center gap-2">
          {rate && <Badge tone={rate.remaining < 500 ? "warning" : "muted"}>Quota GitHub {rate.remaining}/{rate.limit}</Badge>}
          <Button variant="outline" size="sm" onClick={pollNow} disabled={polling}>{polling ? <Spinner /> : <RefreshCw className="h-4 w-4" />} Actualiser</Button>
          <Button size="sm" onClick={() => nav.go("add-app")}>＋ Ajouter une appli</Button>
        </div>
      </div>
      {msg && <Alert tone="muted">{msg}</Alert>}
      {alerts.length > 0 && (
        <Card>
          <CardTitle>Alertes ({alerts.length})</CardTitle>
          <ul className="space-y-1">
            {alerts.map((a, i) => (
              <li key={i} className="text-sm"><Badge tone={a.level === "error" ? "destructive" : "warning"}>{a.level === "error" ? "erreur" : "attention"}</Badge> {a.message}</li>
            ))}
          </ul>
        </Card>
      )}
      {apps.length === 0 ? (
        <Card><Empty>Aucune application. Commencez par en ajouter une.</Empty></Card>
      ) : (
        <div className="grid gap-4 sm:grid-cols-2 xl:grid-cols-3">
          {apps.map((a) => <AppCard key={a.id} app={a} onOpen={() => nav.go("app", a.id)} />)}
        </div>
      )}
      <Card>
        <CardTitle>Activité récente</CardTitle>
        {events.length === 0 ? <Empty>Aucun événement de dépôt pour l'instant.</Empty> : <EventList events={events} />}
      </Card>
    </div>
  );
}

function AppCard({ app, onOpen }: { app: App; onOpen: () => void }) {
  const [st, setSt] = React.useState<AppStatus | null>(null);
  const [err, setErr] = React.useState(false);
  React.useEffect(() => {
    if (app.access_mode === "disabled") return;
    call<AppStatus>("app_status", { appId: app.id }).then(setSt).catch(() => setErr(true));
  }, [app.id, app.access_mode]);
  const dep = st?.latest_deployment?.[1];
  return (
    <button onClick={onOpen} className="text-left">
      <Card className="h-full transition hover:border-primary">
        <div className="flex items-center gap-3">
          <span className="text-2xl">{app.icon?.startsWith("data:") ? <img src={app.icon} alt="" className="h-8 w-8 rounded" /> : app.icon}</span>
          <div className="min-w-0 flex-1">
            <div className="truncate font-semibold">{app.name}</div>
            <div className="truncate text-xs text-muted-foreground">{app.repo ?? "pas de dépôt"}</div>
          </div>
          {app.access_mode === "disabled" ? (
            <Badge tone="muted">désactivée</Badge>
          ) : st?.online === true ? (
            <Badge tone="success">● en ligne</Badge>
          ) : st?.online === false ? (
            <Badge tone="destructive">○ hors ligne</Badge>
          ) : err ? (
            <Badge tone="warning">?</Badge>
          ) : (
            <Badge tone="muted">…</Badge>
          )}
        </div>
        {dep && (
          <p className="mt-3 text-xs">
            {st?.latest_deployment?.[0]} · <Badge tone={/ready|success/i.test(dep.status ?? "") ? "success" : /error|fail/i.test(dep.status ?? "") ? "destructive" : "muted"}>{dep.status}</Badge> {timeAgo(dep.created_at)}
          </p>
        )}
        {st?.urls.map(([u, h]) => (
          <p key={u} className="truncate text-xs text-muted-foreground">{u} · {h.detail} · {h.latency_ms} ms</p>
        ))}
      </Card>
    </button>
  );
}

export function EventList({ events }: { events: RepoEvent[] }) {
  const icon: Record<string, string> = { commit: "⬆", branch: "⎇", pull_request: "⇄", workflow_run: "⚙", release: "🏷" };
  return (
    <ul className="divide-y text-sm">
      {events.map((e) => (
        <li key={e.id} className="flex flex-wrap items-center gap-2 py-2">
          <span aria-hidden>{icon[e.kind] ?? "•"}</span>
          <span className="min-w-0 flex-1 truncate">{e.title}</span>
          {e.status && <Badge tone={e.status === "success" || e.status === "published" ? "success" : /fail|timed_out/.test(e.status) ? "destructive" : "muted"}>{e.status}</Badge>}
          <span className="text-xs text-muted-foreground">{e.repo}{e.author ? ` · ${e.author}` : ""} · {timeAgo(e.occurred_at)}</span>
        </li>
      ))}
    </ul>
  );
}
