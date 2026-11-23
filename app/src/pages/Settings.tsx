// Paramètres : sécurité, GitHub, licences, journal d'audit.
import * as React from "react";
import { call, errorMessage, type AuditEntry, type Profile, type TotpSetup, type VaultStatus } from "@/lib/api";
import { formatDate } from "@/lib/utils";
import { Alert, Badge, Button, Card, CardTitle, Field, Input, Select, Textarea } from "@/components/ui";
import { useReauth } from "@/components/Reauth";
import { GithubStep } from "./Onboarding";

export function Settings({ onChanged }: { onChanged: () => void }) {
  const [profile, setProfile] = React.useState<Profile | null>(null);
  const [status, setStatus] = React.useState<VaultStatus | null>(null);
  const [msg, setMsg] = React.useState<{ tone: "success" | "destructive"; text: string } | null>(null);
  const reauth = useReauth();

  const load = React.useCallback(async () => {
    setProfile(await call<Profile>("profile_get"));
    setStatus(await call<VaultStatus>("vault_status"));
  }, []);
  React.useEffect(() => {
    load().catch(() => undefined);
  }, [load]);

  async function act(fn: () => Promise<unknown>, ok: string) {
    setMsg(null);
    try {
      await reauth(fn);
      setMsg({ tone: "success", text: ok });
      await load();
      onChanged();
    } catch (e) {
      setMsg({ tone: "destructive", text: errorMessage(e) });
    }
  }

  if (!profile || !status) return null;
  return (
    <div className="space-y-6">
      <h1 className="text-2xl font-bold">Paramètres</h1>
      {msg && <Alert tone={msg.tone}>{msg.text}</Alert>}
      <SecurityCard profile={profile} status={status} act={act} />
      <PassphraseCard act={act} />
      <Card>
        <CardTitle>GitHub</CardTitle>
        <p className="mb-3 text-sm">
          {profile.github_login ? <>Connecté en tant que <b>@{profile.github_login}</b></> : "Non connecté"} · dépôt de sync :{" "}
          <code>{profile.sync_repo ?? "—"}</code>
        </p>
        <details>
          <summary className="cursor-pointer text-sm text-primary">Reconnecter / changer de jeton</summary>
          <div className="mt-3">
            <GithubStep onNext={() => load()} />
          </div>
        </details>
      </Card>
      <LicenseKeyCard act={act} />
      <AuditCard />
    </div>
  );
}

type Act = (fn: () => Promise<unknown>, ok: string) => Promise<void>;

function SecurityCard({ profile, status, act }: { profile: Profile; status: VaultStatus; act: Act }) {
  const [setup, setSetup] = React.useState<TotpSetup | null>(null);
  const [code, setCode] = React.useState("");
  const [pin, setPin] = React.useState("");
  return (
    <Card className="space-y-4">
      <CardTitle>Sécurité</CardTitle>
      <p className="text-sm text-muted-foreground">Stockage des secrets : {status.secret_backend}</p>
      <Field label="Verrouillage automatique après inactivité">
        <Select value={profile.autolock_secs} onChange={(e) => act(() => call("autolock_set", { secs: Number(e.target.value) }), "Délai enregistré.")}>
          {[60, 300, 900, 1800, 3600, 0].map((s) => (
            <option key={s} value={s}>{s === 0 ? "Jamais (déconseillé)" : `${s / 60} min`}</option>
          ))}
        </Select>
      </Field>
      <div className="flex flex-wrap items-center gap-2">
        <span className="text-sm">2FA TOTP :</span>
        {profile.totp_enabled ? <Badge tone="success">activée</Badge> : <Badge tone="warning">désactivée</Badge>}
        {profile.totp_enabled ? (
          <Button size="sm" variant="outline" onClick={() => act(() => call("totp_disable"), "2FA désactivée.")}>Désactiver</Button>
        ) : (
          <Button size="sm" variant="outline" onClick={async () => setSetup(await call<TotpSetup>("totp_begin"))}>Activer</Button>
        )}
      </div>
      {setup && (
        <div className="flex flex-wrap items-end gap-3">
          <img src={`data:image/png;base64,${setup.qr_png_base64}`} alt="QR code TOTP" className="h-40 w-40 rounded bg-white p-2" />
          <Input className="w-32" inputMode="numeric" maxLength={6} value={code} onChange={(e) => setCode(e.target.value)} />
          <Button size="sm" onClick={() => act(async () => { await call("totp_confirm", { code }); setSetup(null); }, "2FA activée.")}>Vérifier</Button>
        </div>
      )}
      <div className="flex flex-wrap items-center gap-2">
        <span className="text-sm">PIN :</span>
        {status.pin_available ? <Badge tone="success">configuré</Badge> : <Badge tone="muted">aucun</Badge>}
        <Input className="w-40" type="password" inputMode="numeric" maxLength={12} placeholder="nouveau PIN" value={pin} onChange={(e) => setPin(e.target.value)} />
        <Button size="sm" variant="outline" disabled={pin.length < 6} onClick={() => act(async () => { await call("pin_set", { pin }); setPin(""); }, "PIN enregistré.")}>Définir</Button>
        {status.pin_available && <Button size="sm" variant="ghost" onClick={() => act(() => call("pin_remove"), "PIN supprimé.")}>Supprimer</Button>}
      </div>
    </Card>
  );
}

function PassphraseCard({ act }: { act: Act }) {
  const [oldP, setOld] = React.useState("");
  const [newP, setNew] = React.useState("");
  return (
    <Card className="space-y-3">
      <CardTitle>Changer la phrase secrète</CardTitle>
      <p className="text-xs text-muted-foreground">La base est entièrement re-chiffrée ; le PIN devra être redéfini.</p>
      <Input type="password" placeholder="Phrase actuelle" value={oldP} onChange={(e) => setOld(e.target.value)} />
      <Input type="password" placeholder="Nouvelle phrase (12+ caractères)" value={newP} onChange={(e) => setNew(e.target.value)} />
      <Button variant="outline" onClick={() => act(async () => { await call("passphrase_change", { old: oldP, new: newP }); setOld(""); setNew(""); }, "Phrase secrète changée.")}>Changer</Button>
    </Card>
  );
}

function download(name: string, content: string) {
  const url = URL.createObjectURL(new Blob([content], { type: "application/json" }));
  const a = document.createElement("a");
  a.href = url;
  a.download = name;
  a.click();
  URL.revokeObjectURL(url);
}

function LicenseKeyCard({ act }: { act: Act }) {
  const [status, setStatus] = React.useState<{ kid: string | null; public_keys: string[] } | null>(null);
  const [pass, setPass] = React.useState("");
  const [restore, setRestore] = React.useState("");
  const load = () => call<{ kid: string | null; public_keys: string[] }>("license_key_status").then(setStatus);
  React.useEffect(() => {
    load().catch(() => undefined);
  }, []);
  return (
    <Card className="space-y-3">
      <CardTitle actions={<Button size="sm" variant="outline" onClick={() => act(async () => { await call("license_key_generate"); await load(); }, "Nouvelle clé active (rotation).")}>{status?.kid ? "Rotation de clé" : "Générer"}</Button>}>
        Clé de signature des licences
      </CardTitle>
      <p className="text-sm">kid actif : <code className="break-all">{status?.kid ?? "aucun"}</code></p>
      {status && status.public_keys.length > 0 && (
        <Field label="Clés publiques à embarquer dans vos applis (PASERK)">
          <Textarea readOnly rows={Math.min(4, status.public_keys.length + 1)} value={status.public_keys.join("\n")} />
        </Field>
      )}
      <div className="flex flex-wrap gap-2">
        <Input type="password" className="max-w-xs" placeholder="Phrase de la sauvegarde (12+)" value={pass} onChange={(e) => setPass(e.target.value)} />
        <Button size="sm" variant="outline" onClick={() => act(async () => download("control-center-license-key.json", await call<string>("license_key_backup", { backupPassphrase: pass })), "Sauvegarde chiffrée exportée.")}>Exporter une sauvegarde chiffrée</Button>
      </div>
      <details>
        <summary className="cursor-pointer text-sm text-primary">Restaurer une sauvegarde</summary>
        <Textarea rows={4} className="mt-2" placeholder="Contenu du fichier de sauvegarde" value={restore} onChange={(e) => setRestore(e.target.value)} />
        <Button size="sm" className="mt-2" onClick={() => act(async () => { await call("license_key_restore", { backup: restore, backupPassphrase: pass }); setRestore(""); await load(); }, "Clé restaurée.")}>Restaurer</Button>
      </details>
    </Card>
  );
}

export function AuditCard() {
  const [entries, setEntries] = React.useState<AuditEntry[]>([]);
  const [chain, setChain] = React.useState<string>("");
  const load = React.useCallback(async () => {
    setEntries(await call<AuditEntry[]>("audit_list", { limit: 100, offset: 0 }));
    try {
      const r = await call<{ entries: number }>("audit_verify");
      setChain(`✓ chaîne intègre (${r.entries} entrées)`);
    } catch (e) {
      setChain(`✗ ${errorMessage(e)}`);
    }
  }, []);
  React.useEffect(() => {
    load().catch(() => undefined);
  }, [load]);
  return (
    <Card>
      <CardTitle actions={<Button size="sm" variant="outline" onClick={load}>Vérifier</Button>}>Journal d'audit</CardTitle>
      <p className="mb-3 text-sm">{chain}</p>
      <div className="max-h-96 overflow-auto">
        <table className="w-full text-xs">
          <tbody>
            {entries.map((e) => (
              <tr key={e.seq} className="border-t">
                <td className="py-1 pr-2 text-muted-foreground">#{e.seq}</td>
                <td className="pr-2">{formatDate(e.ts)}</td>
                <td className="pr-2 font-mono">{e.action}</td>
                <td className="max-w-[12rem] truncate pr-2">{e.target}</td>
                <td>
                  <Badge tone={e.outcome === "ok" ? "success" : "destructive"}>{e.outcome}</Badge>
                </td>
              </tr>
            ))}
          </tbody>
        </table>
      </div>
    </Card>
  );
}
