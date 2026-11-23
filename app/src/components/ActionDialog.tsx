// Toute écriture : aperçu de l'effet → confirmation explicite → (ré-auth si destructive) → exécution.
import * as React from "react";
import { call, errorMessage, type Prepared } from "@/lib/api";
import { Alert, Button, Modal, Spinner } from "./ui";
import { useReauth } from "./Reauth";

export function useAction() {
  const [state, setState] = React.useState<{ prepared: Prepared; onDone?: (r: unknown) => void } | null>(null);
  const [busy, setBusy] = React.useState(false);
  const [err, setErr] = React.useState("");
  const [result, setResult] = React.useState<string>("");
  const reauth = useReauth();

  const start = React.useCallback(async (prepare: () => Promise<Prepared>, onDone?: (r: unknown) => void) => {
    setErr("");
    setResult("");
    try {
      setState({ prepared: await prepare(), onDone });
    } catch (e) {
      setErr(errorMessage(e));
      setState(null);
      throw e;
    }
  }, []);

  async function confirm() {
    if (!state) return;
    setBusy(true);
    setErr("");
    try {
      const r = await reauth(() => call<unknown>("action_execute", { token: state.prepared.token }));
      setResult("Action effectuée.");
      state.onDone?.(r);
      setState(null);
    } catch (e) {
      setErr(errorMessage(e));
    } finally {
      setBusy(false);
    }
  }

  const dialog = (
    <Modal open={state !== null} title="Confirmer l'écriture" onClose={() => setState(null)}>
      {state && (
        <div className="space-y-3">
          <p className="text-sm text-muted-foreground">Effet prévu :</p>
          <pre className="whitespace-pre-wrap rounded bg-muted p-3 text-xs">{state.prepared.preview}</pre>
          {state.prepared.destructive && <Alert tone="warning">Action destructrice : votre phrase secrète sera demandée.</Alert>}
          {err && <Alert tone="destructive">{err}</Alert>}
          <div className="flex justify-end gap-2">
            <Button variant="ghost" onClick={() => setState(null)}>Annuler</Button>
            <Button variant={state.prepared.destructive ? "destructive" : "default"} onClick={confirm} disabled={busy}>
              {busy && <Spinner />} Confirmer
            </Button>
          </div>
        </div>
      )}
    </Modal>
  );
  return { start, dialog, error: err, result };
}
