// Synchronisation chiffrée : état, conflits, appareils (ajout par QR, révocation), rotation de clé.
import * as React from "react";
import { call, errorMessage, type SyncConflict, type SyncReport, type SyncStatus } from "@/lib/api";
import { formatDate, timeAgo } from "@/lib/utils";
import { Alert, Badge, Button, Card, CardTitle, Empty, Field, Input, Spinner } from "@/components/ui";
import { useReauth } from "@/components/Reauth";
import type { PageProps } from "./registry";

export function SyncPage({ nav }: PageProps) {
  const [st, setSt] = React.useState<SyncStatus | null>(null);
  const [conflicts, setConflicts] = React.useState<SyncConflict[]>([]);
  const [pass, setPass] = React.useState("");
  const [busy, setBusy] = React.useState(false);
  const [msg, setMsg] = React.useState<{ tone: "success" | "destructive" | "muted"; text: string } | null>(null);
  const [pairing, setPairing] = React.useState<{ payload: string; qr_png_base64: string } | null>(null);
  const [newPass, setNewPass] = React.useState("");
  const reauth = useReauth();

  const load = React.useCallback(async () => {
    setSt(await call<SyncStatus>("sync_status"));
    setConflicts(await call<SyncConflict[]>("sync_conflicts"));
  }, []);
  React.useEffect(() => {
    load().catch((e) => setMsg({ tone: "destructive", text: errorMessage(e) }));
  }, [load]);

  async function run<T>(fn: () => Promise<T>, ok: (r: T) => string) {
    setBusy(true);
    setMsg(null);
    try {
      const r = await reauth(fn);
      setMsg({ tone: "success", text: ok(r) });
      await load();
    } catch (e) {
      setMsg({ tone: "destructive", text: errorMessage(e) });
    } finally {
      setBusy(false);
    }
  }

  if (!st) return null;
  return (
    <div className="space-y-6">
      <h1 className="text-2xl font-bold">Synchronisation</h1>
      {msg && <Alert tone={msg.tone}>{msg.text}</Alert>}
      <Card className="space-y-3">
        <CardTitle actions={st.configured && <Button size="sm" onClick={() => run(() => call<SyncReport>("sync_now"), (r) => `${r.captured} changement(s) local(aux), ${r.pulled.applied} appliqué(s), ${r.pulled.conflicts} conflit(s), ${r.pushed_batches} lot(s) envoyé(s).`)} disabled={busy}>{busy && <Spinner />} Synchroniser maintenant</Button>}>
          Dépôt chiffré
        </CardTitle>
        {!st.repo ? (
          <Alert tone="warning">Aucun dépôt de synchronisation. <button className="underline" onClick={() => nav.go("settings")}>Configurer GitHub</button></Alert>
        ) : (
          <p className="text-sm">Dépôt <code>{st.repo}</code> · époque {st.epoch ?? "—"} · dernière synchro {timeAgo(st.last_sync)}</p>
        )}
        {st.repo && !st.configured && (
          <div className="space-y-2">
            <p className="text-sm text-muted-foreground">
              Saisissez la phrase secrète de synchronisation (identique sur tous vos appareils). Sur le premier appareil, elle crée la clé ; sur les suivants, elle la retrouve.
            </p>
            <div className="flex gap-2">
              <Input type="password" value={pass} onChange={(e) => setPass(e.target.value)} placeholder="Phrase secrète" />
              <Button onClick={() => run(() => call<number>("sync_setup", { passphrase: pass }), (e) => { setPass(""); return `Synchronisation activée (époque ${e}).`; })} disabled={!pass || busy}>Activer</Button>
            </div>
          </div>
        )}
        <p className="text-xs text-muted-foreground">GitHub ne stocke que des lots chiffrés (XChaCha20-Poly1305, clé Argon2id dérivée de la phrase secrète). Sans elle, le contenu est illisible.</p>
      </Card>

      <Card>
        <CardTitle>Conflits à résoudre ({conflicts.length})</CardTitle>
        {conflicts.length === 0 ? <Empty>Aucun conflit.</Empty> : conflicts.map((c) => (
          <div key={c.id} className="mb-3 rounded border p-3 text-sm">
            <p className="mb-2"><Badge tone="warning">{c.entity}</Badge> modifié sur deux appareils en même temps ({formatDate(c.created_at)}).</p>
            <div className="grid gap-2 md:grid-cols-2">
              <div><p className="text-xs font-medium">Version retenue (la plus récente)</p><pre className="max-h-40 overflow-auto rounded bg-muted p-2 text-xs">{JSON.stringify(c.current, null, 2)}</pre></div>
              <div><p className="text-xs font-medium">Version écartée</p><pre className="max-h-40 overflow-auto rounded bg-muted p-2 text-xs">{JSON.stringify(c.discarded, null, 2)}</pre></div>
            </div>
            <div className="mt-2 flex gap-2">
              <Button size="sm" variant="outline" onClick={() => run(() => call("sync_resolve", { id: c.id, restoreDiscarded: false }), () => "Version retenue conservée.")}>Garder la version retenue</Button>
              <Button size="sm" onClick={() => run(() => call("sync_resolve", { id: c.id, restoreDiscarded: true }), () => "Version écartée restaurée (sera propagée).")}>Restaurer la version écartée</Button>
            </div>
          </div>
        ))}
      </Card>

      <Card className="space-y-3">
        <CardTitle actions={st.configured && <Button size="sm" variant="outline" onClick={async () => setPairing(await call("sync_pairing"))}>Ajouter un appareil (QR)</Button>}>Appareils</CardTitle>
        {pairing && (
          <div className="flex flex-wrap items-center gap-4 rounded border p-3">
            <img src={`data:image/png;base64,${pairing.qr_png_base64}`} alt="QR d'appairage" className="h-40 w-40 rounded bg-white p-2" />
            <div className="max-w-md text-sm">
              <ol className="list-decimal space-y-1 pl-5">
                <li>Installez Control Center sur le nouvel appareil et créez son profil.</li>
                <li>Connectez GitHub puis choisissez le dépôt indiqué par ce QR code.</li>
                <li>Saisissez la phrase secrète de synchronisation : tout est récupéré et déchiffré localement.</li>
              </ol>
              <code className="mt-2 block break-all text-xs">{pairing.payload}</code>
            </div>
          </div>
        )}
        <ul className="divide-y text-sm">
          {st.devices.map((d) => (
            <li key={d.id} className="flex flex-wrap items-center gap-2 py-2">
              <span className="flex-1">{d.name} <span className="text-xs text-muted-foreground">({d.platform})</span></span>
              {d.is_current && <Badge>cet appareil</Badge>}
              {d.revoked_at ? <Badge tone="destructive">révoqué {formatDate(d.revoked_at)}</Badge> : !d.is_current && (
                <Button size="sm" variant="destructive" onClick={() => { if (confirm(`Révoquer « ${d.name} » ? Ses futures modifications seront ignorées.`)) run(() => call("device_revoke", { id: d.id }), () => "Appareil révoqué. Faites maintenant une rotation de la clé avec une nouvelle phrase secrète."); }}>Révoquer (perdu)</Button>
              )}
            </li>
          ))}
        </ul>
      </Card>

      {st.configured && (
        <Card className="space-y-2">
          <CardTitle>Rotation de la clé (après perte d'un appareil)</CardTitle>
          <p className="text-sm text-muted-foreground">Crée une nouvelle époque chiffrée avec une NOUVELLE phrase secrète et ré-envoie toutes les données. L'appareil perdu, qui ne la connaît pas, ne peut plus rien lire. Les autres appareils devront saisir la nouvelle phrase.</p>
          <Field label="Nouvelle phrase secrète de synchronisation"><Input type="password" value={newPass} onChange={(e) => setNewPass(e.target.value)} /></Field>
          <Button variant="destructive" disabled={newPass.length < 12 || busy} onClick={() => run(() => call<number>("sync_rotate_epoch", { newPassphrase: newPass }), (e) => { setNewPass(""); return `Nouvelle époque ${e} : synchronisez pour ré-envoyer les données.`; })}>Faire la rotation</Button>
        </Card>
      )}
      <Card>
        <CardTitle>Synchronisation directe en réseau local</CardTitle>
        <p className="text-sm text-muted-foreground">Option prévue (voir docs/sync.md) : non activée dans cette version, la synchronisation passe par le dépôt GitHub chiffré.</p>
      </Card>
    </div>
  );
}
