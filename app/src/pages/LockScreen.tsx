// Écran de verrouillage : phrase secrète, PIN, puis code TOTP si la 2FA est active.
import * as React from "react";
import { call, errorMessage, type VaultStatus } from "@/lib/api";
import { Alert, Button, Card, Field, Input, Spinner } from "@/components/ui";

export function LockScreen({ status, onUnlocked }: { status: VaultStatus; onUnlocked: () => void }) {
  const [mode, setMode] = React.useState<"pass" | "pin">(status.pin_available ? "pin" : "pass");
  const [secret, setSecret] = React.useState("");
  const [code, setCode] = React.useState("");
  const [err, setErr] = React.useState("");
  const [busy, setBusy] = React.useState(false);
  const needTotp = status.state === "totp_required";

  async function submit(e: React.FormEvent) {
    e.preventDefault();
    setBusy(true);
    setErr("");
    try {
      if (needTotp) {
        await call("vault_complete_totp", { code });
      } else if (mode === "pin") {
        await call("vault_unlock_pin", { pin: secret });
      } else {
        await call("vault_unlock", { passphrase: secret });
      }
      setSecret("");
      setCode("");
      onUnlocked();
    } catch (e) {
      setErr(errorMessage(e));
      setSecret("");
      onUnlocked(); // rafraîchit l'état (ex. passage en attente TOTP, PIN désactivé)
    } finally {
      setBusy(false);
    }
  }

  return (
    <div className="flex min-h-screen items-center justify-center p-4">
      <Card className="w-full max-w-sm">
        <form onSubmit={submit} className="space-y-4">
          <div className="text-center">
            <div className="mb-2 text-4xl" aria-hidden>🔒</div>
            <h1 className="text-xl font-semibold">Control Center verrouillé</h1>
          </div>
          {needTotp ? (
            <Field label="Code de double authentification">
              <Input inputMode="numeric" maxLength={6} value={code} onChange={(e) => setCode(e.target.value)} autoFocus />
            </Field>
          ) : (
            <Field label={mode === "pin" ? "PIN" : "Phrase secrète"}>
              <Input
                type="password"
                inputMode={mode === "pin" ? "numeric" : undefined}
                value={secret}
                onChange={(e) => setSecret(e.target.value)}
                autoFocus
              />
            </Field>
          )}
          {err && <Alert tone="destructive">{err}</Alert>}
          <Button type="submit" className="w-full" disabled={busy}>{busy && <Spinner />} Déverrouiller</Button>
          {!needTotp && status.pin_available && (
            <button type="button" className="w-full text-sm text-muted-foreground underline" onClick={() => setMode(mode === "pin" ? "pass" : "pin")}>
              {mode === "pin" ? "Utiliser la phrase secrète" : "Utiliser le PIN"}
            </button>
          )}
        </form>
      </Card>
    </div>
  );
}
