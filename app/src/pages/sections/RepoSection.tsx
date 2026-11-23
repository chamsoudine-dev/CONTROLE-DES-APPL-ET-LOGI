// Section « Dépôt » de la fiche appli : événements GitHub + actions (release, workflow, relance).
import * as React from "react";
import { call, errorMessage, type ActionSpec, type RepoEvent } from "@/lib/api";
import { Alert, Button, Card, CardTitle, Empty, Input, Modal } from "@/components/ui";
import { useAction } from "@/components/ActionDialog";
import { EventList } from "../Dashboard";
import type { SectionProps } from "../appSections";

export function RepoSection({ detail }: SectionProps) {
  const gh = detail.connectors.find((c) => c.provider === "github");
  const [events, setEvents] = React.useState<RepoEvent[]>([]);
  const [actions, setActions] = React.useState<ActionSpec[]>([]);
  const [open, setOpen] = React.useState<ActionSpec | null>(null);
  const [form, setForm] = React.useState<Record<string, string>>({});
  const [err, setErr] = React.useState("");
  const action = useAction();
  const load = React.useCallback(async () => {
    setEvents(await call<RepoEvent[]>("repo_events", { appId: detail.app.id, limit: 30 }));
    if (gh) setActions(await call<ActionSpec[]>("connector_actions", { connectorId: gh.id }));
  }, [detail.app.id, gh]);
  React.useEffect(() => {
    load().catch((e) => setErr(errorMessage(e)));
  }, [load]);
  if (!detail.app.repo) return null;
  const fields: Record<string, string[]> = { workflow_dispatch: ["workflow", "ref"], create_release: ["tag", "target", "name", "body"], rerun_workflow: ["run_id"] };
  return (
    <Card>
      <CardTitle actions={gh && actions.map((a) => <Button key={a.id} size="sm" variant="outline" onClick={() => { setOpen(a); setForm({}); }}>{a.label}</Button>)}>
        Dépôt <code className="text-sm font-normal">{detail.app.repo}</code>
      </CardTitle>
      {err && <Alert tone="destructive">{err}</Alert>}
      {action.error && <Alert tone="destructive">{action.error}</Alert>}
      {action.result && <Alert tone="success">{action.result}</Alert>}
      <div className="max-h-80 overflow-auto">{events.length === 0 ? <Empty>En attente du premier suivi (Tableau de bord → Actualiser).</Empty> : <EventList events={events} />}</div>
      <Modal open={open !== null} title={open?.label ?? ""} onClose={() => setOpen(null)}>
        {open && gh && (
          <div className="space-y-2">
            {(fields[open.id] ?? []).map((f) => <Input key={f} placeholder={f} value={form[f] ?? ""} onChange={(e) => setForm({ ...form, [f]: e.target.value })} />)}
            <Button onClick={() => { const params = { ...form }; setOpen(null); action.start(() => call("action_prepare", { connectorId: gh.id, action: open.id, params }), () => load()).catch(() => undefined); }}>Prévisualiser</Button>
          </div>
        )}
      </Modal>
      {action.dialog}
    </Card>
  );
}
