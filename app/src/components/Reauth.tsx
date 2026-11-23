// Ré-authentification avant les actions sensibles (révéler, supprimer, rollback…).
import * as React from "react";
import { call, errorMessage, isCoreError } from "@/lib/api";
import { Alert, Button, Field, Input, Modal } from "./ui";

type Runner = <T>(fn: () => Promise<T>) => Promise<T>;
const Ctx = React.createContext<Runner>((fn) => fn());

export function useReauth(): Runner {
  return React.useContext(Ctx);
}

export function ReauthProvider({ children, totpEnabled }: { children: React.ReactNode; totpEnabled: boolean }) {
  const [pending, setPending] = React.useState<{ resolve: () => void; reject: (e: unknown) => void } | null>(null);
  const [pass, setPass] = React.useState("");
  const [totp, setTotp] = React.useState("");
  const [err, setErr] = React.useState("");

  const ask = React.useCallback(
    () =>
      new Promise<void>((resolve, reject) => {
        setPass("");
        setTotp("");
        setErr("");
        setPending({ resolve, reject });
      }),
    [],
  );

  const run: Runner = React.useCallback(
    async (fn) => {
      try {
        return await fn();
      } catch (e) {
        if (isCoreError(e) && e.code === "reauth_required") {
          await ask();
          return fn();
        }
        throw e;
      }
    },
    [ask],
  );

  async function submit(ev: React.FormEvent) {
    ev.preventDefault();
    try {
      await call("vault_reauth", { passphrase: pass, totp: totpEnabled ? totp : null });
      setPass("");
      pending?.resolve();
      setPending(null);
    } catch (e) {
      setErr(errorMessage(e));
    }
  }

  return (
    <Ctx.Provider value={run}>
      {children}
      <Modal
        open={pending !== null}
        title="Confirmez votre identité"
        onClose={() => {
          pending?.reject({ code: "cancelled", message: "Action annulée" });
          setPending(null);
        }}
      >
        <form onSubmit={submit} className="space-y-3">
          <p className="text-sm text-muted-foreground">Cette action est sensible : saisissez votre phrase secrète.</p>
          <Field label="Phrase secrète">
            <Input type="password" value={pass} onChange={(e) => setPass(e.target.value)} autoFocus />
          </Field>
          {totpEnabled && (
            <Field label="Code 2FA">
              <Input inputMode="numeric" maxLength={6} value={totp} onChange={(e) => setTotp(e.target.value)} />
            </Field>
          )}
          {err && <Alert tone="destructive">{err}</Alert>}
          <Button type="submit" className="w-full">Confirmer</Button>
        </form>
      </Modal>
    </Ctx.Provider>
  );
}
