// Mises à jour : détection, notes de version, installation. La signature est vérifiée par le
// plugin updater avec la clé publique embarquée : une mise à jour non signée est refusée.
import * as React from "react";
import { call, errorMessage } from "@/lib/api";
import { Alert, Button, Card, CardTitle, Spinner } from "./ui";

type Update = { version: string; body?: string; date?: string; downloadAndInstall: (cb?: (e: { event: string; data?: { contentLength?: number; chunkLength?: number } }) => void) => Promise<void> };

export function UpdateCard() {
  const [version, setVersion] = React.useState("");
  const [update, setUpdate] = React.useState<Update | null>(null);
  const [state, setState] = React.useState<"idle" | "checking" | "none" | "downloading" | "ready">("idle");
  const [progress, setProgress] = React.useState(0);
  const [err, setErr] = React.useState("");

  React.useEffect(() => {
    call<string>("app_version").then(setVersion).catch(() => undefined);
  }, []);

  async function check() {
    setErr("");
    setState("checking");
    try {
      const { check } = await import("@tauri-apps/plugin-updater");
      const u = (await check()) as Update | null;
      setUpdate(u);
      setState(u ? "idle" : "none");
    } catch (e) {
      setErr(errorMessage(e));
      setState("idle");
    }
  }

  async function install() {
    if (!update) return;
    setState("downloading");
    let total = 0;
    let done = 0;
    try {
      await update.downloadAndInstall((ev) => {
        if (ev.event === "Started") total = ev.data?.contentLength ?? 0;
        if (ev.event === "Progress") {
          done += ev.data?.chunkLength ?? 0;
          if (total) setProgress(Math.round((done / total) * 100));
        }
      });
      setState("ready");
      const { relaunch } = await import("@tauri-apps/plugin-process");
      await relaunch();
    } catch (e) {
      setErr(`Mise à jour refusée ou échouée : ${errorMessage(e)}`);
      setState("idle");
    }
  }

  return (
    <Card className="space-y-3">
      <CardTitle actions={<Button size="sm" variant="outline" onClick={check} disabled={state === "checking" || state === "downloading"}>{state === "checking" && <Spinner />} Vérifier</Button>}>Mises à jour</CardTitle>
      <p className="text-sm">Version installée : <b>{version || "?"}</b></p>
      {state === "none" && <Alert tone="success">Vous avez la dernière version.</Alert>}
      {update && (
        <div className="space-y-2">
          <Alert>Version {update.version} disponible{update.date ? ` (${update.date.slice(0, 10)})` : ""}.</Alert>
          {update.body && <pre className="max-h-48 overflow-auto whitespace-pre-wrap rounded bg-muted p-3 text-xs">{update.body}</pre>}
          <Button onClick={install} disabled={state === "downloading"}>{state === "downloading" ? `Téléchargement… ${progress} %` : "Mettre à jour"}</Button>
        </div>
      )}
      {err && <Alert tone="destructive">{err}</Alert>}
      <p className="text-xs text-muted-foreground">Chaque mise à jour est signée (minisign) ; la signature et la version signée sont vérifiées avant installation (protection contre les mises à jour piégées et les retours en arrière).</p>
    </Card>
  );
}
