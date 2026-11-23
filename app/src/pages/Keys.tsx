// Onglet « Environnements & Clés » : secrets par appli et par environnement, variables, export/import.
import * as React from "react";
import { Eye, FlaskConical, Pencil, RotateCw, Trash2 } from "lucide-react";
import {
  call,
  errorMessage,
  type App,
  type AppDetail,
  type DiffLine,
  type EnvVar,
  type ImportReportT,
  type SecretMeta,
  type TestReport,
} from "@/lib/api";
import { formatDate, timeAgo } from "@/lib/utils";
import { Alert, Badge, Button, Card, CardTitle, Empty, Field, Input, Modal, Select } from "@/components/ui";
import { useReauth } from "@/components/Reauth";
import { useAction } from "@/components/ActionDialog";
import type { PageProps } from "./registry";

const ENVS = ["development", "preview", "production"] as const;
const ENV_LABEL: Record<string, string> = { development: "Développement", preview: "Preview", production: "Production", global: "Global" };

export function KeysPage({ appId: initialApp }: PageProps) {
  const [apps, setApps] = React.useState<App[]>([]);
  const [appId, setAppId] = React.useState<string>(initialApp ?? "");
  const [env, setEnv] = React.useState<string>("production");
  const [secrets, setSecrets] = React.useState<SecretMeta[]>([]);
  const [msg, setMsg] = React.useState<{ tone: "success" | "destructive" | "warning"; text: string } | null>(null);
  const [adding, setAdding] = React.useState(false);
  const reauth = useReauth();

  const load = React.useCallback(async () => {
    const a = await call<App[]>("apps_list");
    setApps(a);
    setSecrets(await call<SecretMeta[]>("secrets_list", { appId: appId === "" ? "" : appId }));
  }, [appId]);
  React.useEffect(() => {
    load().catch((e) => setMsg({ tone: "destructive", text: errorMessage(e) }));
  }, [load]);

  const visible = secrets.filter((s) => appId === "" || s.environment === env);

  async function act(fn: () => Promise<unknown>, ok?: string) {
    setMsg(null);
    try {
      await reauth(fn);
      if (ok) setMsg({ tone: "success", text: ok });
      await load();
    } catch (e) {
      setMsg({ tone: "destructive", text: errorMessage(e) });
    }
  }

  return (
    <div className="space-y-6">
      <h1 className="text-2xl font-bold">Environnements & Clés</h1>
      <div className="flex flex-wrap items-end gap-3">
        <Field label="Application">
          <Select value={appId} onChange={(e) => setAppId(e.target.value)} className="w-56">
            <option value="">Secrets globaux</option>
            {apps.map((a) => (
              <option key={a.id} value={a.id}>{a.name}</option>
            ))}
          </Select>
        </Field>
        {appId !== "" && (
          <div className="flex gap-1" role="tablist">
            {ENVS.map((e) => (
              <Button key={e} size="sm" variant={env === e ? "default" : "outline"} onClick={() => setEnv(e)}>{ENV_LABEL[e]}</Button>
            ))}
          </div>
        )}
        <Button onClick={() => setAdding(true)}>＋ Ajouter un secret</Button>
      </div>
      {msg && <Alert tone={msg.tone}>{msg.text}</Alert>}
      <Card className="overflow-x-auto p-0">
        {visible.length === 0 ? (
          <Empty>Aucun secret ici.</Empty>
        ) : (
          <table className="w-full text-sm">
            <thead className="bg-muted/50 text-left text-xs text-muted-foreground">
              <tr>
                <th className="p-3">Nom</th>
                <th>Fournisseur</th>
                <th>Env.</th>
                <th>Valeur</th>
                <th>Ajouté</th>
                <th>Utilisé</th>
                <th>Expire</th>
                <th>Permissions</th>
                <th className="pr-3 text-right">Actions</th>
              </tr>
            </thead>
            <tbody>
              {visible.map((s) => (
                <SecretRow key={s.id} s={s} act={act} onMsg={setMsg} />
              ))}
            </tbody>
          </table>
        )}
      </Card>
      {appId !== "" && <EnvVarsCard appId={appId} env={env} secrets={secrets.filter((s) => s.environment === env)} />}
      <VaultTransferCard onDone={load} />
      <AddSecretModal open={adding} appId={appId} env={appId === "" ? "global" : env} onClose={() => setAdding(false)} onSaved={() => { setAdding(false); load(); }} />
    </div>
  );
}

function SecretRow({ s, act, onMsg }: { s: SecretMeta; act: (fn: () => Promise<unknown>, ok?: string) => Promise<void>; onMsg: (m: { tone: "success" | "destructive" | "warning"; text: string }) => void }) {
  const [revealed, setRevealed] = React.useState<string | null>(null);
  const [rotating, setRotating] = React.useState(false);
  const [editing, setEditing] = React.useState(false);
  const reauth = useReauth();

  React.useEffect(() => {
    if (revealed === null) return;
    const t = setTimeout(() => setRevealed(null), 30_000); // masquage automatique après 30 s
    return () => clearTimeout(t);
  }, [revealed]);

  const perms = s.detected_permissions ?? [];
  return (
    <tr className="border-t align-top">
      <td className="p-3 font-mono text-xs">
        {s.name} {s.too_powerful && <span title="Clé trop puissante : réduisez ses droits"><Badge tone="warning">⚠ trop puissante</Badge></span>}
      </td>
      <td>{s.provider}</td>
      <td><Badge tone="muted">{ENV_LABEL[s.environment] ?? s.environment}</Badge></td>
      <td className="font-mono text-xs">{revealed ?? s.masked}</td>
      <td className="text-xs">{formatDate(s.created_at)}</td>
      <td className="text-xs">{timeAgo(s.last_used_at)}</td>
      <td className="text-xs">{s.expires_at ? formatDate(s.expires_at) : "—"}</td>
      <td className="text-xs">
        {perms.length === 0 ? "—" : perms.map((p, i) => (
          <span key={i} className="mr-1"><Badge tone={p.granted ? (p.access === "write" ? "warning" : "muted") : "destructive"}>{p.access === "write" ? "É" : "L"} {p.scope}</Badge></span>
        ))}
      </td>
      <td className="whitespace-nowrap pr-3 text-right">
        <IconBtn title="Révéler (ré-authentification)" onClick={async () => { try { setRevealed(await reauth(() => call<string>("secret_reveal", { id: s.id }))); } catch (e) { onMsg({ tone: "destructive", text: errorMessage(e) }); } }}><Eye className="h-4 w-4" /></IconBtn>
        <IconBtn title="Tester" onClick={async () => { try { const r = await call<TestReport>("secret_test", { id: s.id }); onMsg({ tone: r.ok ? "success" : "destructive", text: r.ok ? `Clé valide${r.identity ? ` (${r.identity})` : ""}. ${r.warnings.join(" ")}` : `Échec : ${r.warnings.join(" ")}` }); } catch (e) { onMsg({ tone: "destructive", text: errorMessage(e) }); } }}><FlaskConical className="h-4 w-4" /></IconBtn>
        <IconBtn title="Rotation" onClick={() => setRotating(true)}><RotateCw className="h-4 w-4" /></IconBtn>
        <IconBtn title="Modifier" onClick={() => setEditing(true)}><Pencil className="h-4 w-4" /></IconBtn>
        <IconBtn title="Supprimer" onClick={() => { if (confirm(`Supprimer définitivement « ${s.name} » ?`)) act(() => call("secret_delete", { id: s.id }), "Secret supprimé."); }}><Trash2 className="h-4 w-4 text-destructive" /></IconBtn>
        <RotateModal open={rotating} s={s} onClose={() => setRotating(false)} act={act} />
        <EditModal open={editing} s={s} onClose={() => setEditing(false)} act={act} />
      </td>
    </tr>
  );
}

function IconBtn({ children, title, onClick }: { children: React.ReactNode; title: string; onClick: () => void }) {
  return (
    <button title={title} aria-label={title} onClick={onClick} className="rounded p-1.5 hover:bg-muted">
      {children}
    </button>
  );
}

function RotateModal({ open, s, onClose, act }: { open: boolean; s: SecretMeta; onClose: () => void; act: (fn: () => Promise<unknown>, ok?: string) => Promise<void> }) {
  const [v, setV] = React.useState("");
  return (
    <Modal open={open} title={`Rotation de ${s.name}`} onClose={onClose}>
      <div className="space-y-3 text-left">
        <ol className="list-decimal pl-5 text-sm text-muted-foreground">
          <li>Créez une nouvelle clé chez {s.provider}.</li>
          <li>Collez-la ci-dessous (l'ancienne est remplacée dans le trousseau).</li>
          <li>Testez, puis révoquez l'ancienne clé chez le fournisseur.</li>
        </ol>
        <Input type="password" value={v} onChange={(e) => setV(e.target.value)} placeholder="Nouvelle valeur" />
        <Button onClick={async () => { await act(() => call("secret_rotate", { id: s.id, value: v }), "Clé remplacée : testez-la puis révoquez l'ancienne."); setV(""); onClose(); }} disabled={!v}>Remplacer</Button>
      </div>
    </Modal>
  );
}

function EditModal({ open, s, onClose, act }: { open: boolean; s: SecretMeta; onClose: () => void; act: (fn: () => Promise<unknown>, ok?: string) => Promise<void> }) {
  const [name, setName] = React.useState(s.name);
  const [exp, setExp] = React.useState(s.expires_at?.slice(0, 10) ?? "");
  return (
    <Modal open={open} title="Modifier le secret" onClose={onClose}>
      <div className="space-y-3 text-left">
        <Field label="Nom"><Input value={name} onChange={(e) => setName(e.target.value)} /></Field>
        <Field label="Expiration"><Input type="date" value={exp} onChange={(e) => setExp(e.target.value)} /></Field>
        <Button onClick={async () => { await act(() => call("secret_update", { id: s.id, name, expiresAt: exp ? `${exp}T00:00:00Z` : null }), "Secret modifié."); onClose(); }}>Enregistrer</Button>
      </div>
    </Modal>
  );
}

function AddSecretModal({ open, appId, env, onClose, onSaved }: { open: boolean; appId: string; env: string; onClose: () => void; onSaved: () => void }) {
  const [name, setName] = React.useState("");
  const [provider, setProvider] = React.useState("custom");
  const [value, setValue] = React.useState("");
  const [exp, setExp] = React.useState("");
  const [err, setErr] = React.useState("");
  async function save() {
    setErr("");
    try {
      await call("secret_add", { appId: appId || null, environment: env, provider, name, value, expiresAt: exp ? `${exp}T00:00:00Z` : null });
      setName("");
      setValue("");
      onSaved();
    } catch (e) {
      setErr(errorMessage(e));
    }
  }
  return (
    <Modal open={open} title={`Nouveau secret — ${ENV_LABEL[env] ?? env}`} onClose={onClose}>
      <div className="space-y-3">
        <Field label="Nom" hint="Ex. STRIPE_SECRET_KEY"><Input value={name} onChange={(e) => setName(e.target.value)} /></Field>
        <Field label="Fournisseur"><Input value={provider} onChange={(e) => setProvider(e.target.value)} /></Field>
        <Field label="Valeur" hint="Stockée dans le trousseau du système, jamais réaffichée sans ré-authentification."><Input type="password" value={value} onChange={(e) => setValue(e.target.value)} /></Field>
        <Field label="Expiration (optionnelle)"><Input type="date" value={exp} onChange={(e) => setExp(e.target.value)} /></Field>
        {err && <Alert tone="destructive">{err}</Alert>}
        <Button onClick={save} disabled={!name || !value}>Enregistrer</Button>
      </div>
    </Modal>
  );
}

function EnvVarsCard({ appId, env, secrets }: { appId: string; env: string; secrets: SecretMeta[] }) {
  const [vars, setVars] = React.useState<EnvVar[]>([]);
  const [detail, setDetail] = React.useState<AppDetail | null>(null);
  const [key, setKey] = React.useState("");
  const [value, setValue] = React.useState("");
  const [secretId, setSecretId] = React.useState("");
  const [diff, setDiff] = React.useState<DiffLine[] | null>(null);
  const [err, setErr] = React.useState("");
  const action = useAction();
  const hosting = detail?.connectors.filter((c) => ["vercel", "netlify", "cloudflare"].includes(c.provider)) ?? [];

  const load = React.useCallback(async () => {
    setVars(await call<EnvVar[]>("env_list", { appId, environment: env }));
    setDetail(await call<AppDetail>("app_get", { id: appId }));
    setDiff(null);
  }, [appId, env]);
  React.useEffect(() => {
    load().catch((e) => setErr(errorMessage(e)));
  }, [load]);

  async function add() {
    setErr("");
    try {
      await call("env_set", { appId, environment: env, key, value: secretId ? null : value, secretId: secretId || null });
      setKey("");
      setValue("");
      setSecretId("");
      await load();
    } catch (e) {
      setErr(errorMessage(e));
    }
  }

  const tone = { added: "success", changed: "warning", removed: "destructive", unchanged: "muted" } as const;
  return (
    <Card>
      <CardTitle
        actions={hosting.map((c) => (
          <React.Fragment key={c.id}>
            <Button size="sm" variant="outline" onClick={async () => { try { setDiff(await call<DiffLine[]>("env_diff", { appId, environment: env, connectorId: c.id })); } catch (e) { setErr(errorMessage(e)); } }}>Aperçu des différences ({c.provider})</Button>
            <Button size="sm" onClick={() => action.start(() => call("env_push_prepare", { appId, environment: env, connectorId: c.id }), () => load()).catch(() => undefined)}>Envoyer vers {c.provider}</Button>
          </React.Fragment>
        ))}
      >
        Variables d'environnement — {ENV_LABEL[env]}
      </CardTitle>
      {action.error && <Alert tone="destructive">{action.error}</Alert>}
      {action.result && <Alert tone="success">{action.result}</Alert>}
      <table className="mb-3 w-full text-sm">
        <tbody>
          {vars.map((v) => (
            <tr key={v.id} className="border-t">
              <td className="py-1 font-mono text-xs">{v.key}</td>
              <td className="max-w-xs truncate font-mono text-xs">{v.value}</td>
              <td>{v.pushed ? <Badge tone="success">envoyée</Badge> : <Badge tone="muted">locale</Badge>}</td>
              <td className="text-right"><button className="text-xs text-destructive" onClick={async () => { await call("env_remove", { appId, environment: env, key: v.key }); load(); }}>retirer</button></td>
            </tr>
          ))}
        </tbody>
      </table>
      <div className="flex flex-wrap gap-2">
        <Input className="w-48 font-mono" placeholder="CLÉ" value={key} onChange={(e) => setKey(e.target.value.toUpperCase())} />
        {secretId ? null : <Input className="w-64" placeholder="valeur (non secrète)" value={value} onChange={(e) => setValue(e.target.value)} />}
        <Select className="w-56" value={secretId} onChange={(e) => setSecretId(e.target.value)}>
          <option value="">— ou lier un secret —</option>
          {secrets.map((s) => <option key={s.id} value={s.id}>{s.name}</option>)}
        </Select>
        <Button variant="outline" onClick={add} disabled={!key}>Ajouter / modifier</Button>
      </div>
      {diff && (
        <div className="mt-4">
          <h3 className="mb-2 text-sm font-medium">Différences avec l'hébergeur</h3>
          {diff.length === 0 ? <p className="text-sm text-muted-foreground">Aucune variable.</p> : diff.map((d) => (
            <div key={d.key} className="flex items-center gap-2 text-sm"><Badge tone={tone[d.change]}>{d.change === "added" ? "+ ajout" : d.change === "changed" ? "~ modif" : d.change === "removed" ? "− absente localement" : "= identique"}</Badge><code>{d.key}</code></div>
          ))}
        </div>
      )}
      {err && <Alert tone="destructive">{err}</Alert>}
      {action.dialog}
    </Card>
  );
}

function download(name: string, content: string) {
  const url = URL.createObjectURL(new Blob([content], { type: "application/octet-stream" }));
  const a = document.createElement("a");
  a.href = url;
  a.download = name;
  a.click();
  URL.revokeObjectURL(url);
}

function VaultTransferCard({ onDone }: { onDone: () => void }) {
  const [pass, setPass] = React.useState("");
  const [msg, setMsg] = React.useState<{ tone: "success" | "destructive"; text: string } | null>(null);
  const reauth = useReauth();
  const fileRef = React.useRef<HTMLInputElement>(null);
  return (
    <Card className="space-y-3">
      <CardTitle>Export / import chiffré (.ccvault)</CardTitle>
      <p className="text-sm text-muted-foreground">Le fichier est chiffré (Argon2id + XChaCha20-Poly1305) avec la phrase ci-dessous, distincte de votre phrase maîtresse.</p>
      <Input type="password" className="max-w-sm" placeholder="Phrase du fichier (12+ caractères)" value={pass} onChange={(e) => setPass(e.target.value)} />
      <div className="flex flex-wrap gap-2">
        <Button variant="outline" disabled={pass.length < 12} onClick={async () => { try { const c = await reauth(() => call<string>("vault_export", { passphrase: pass })); download(`control-center-${new Date().toISOString().slice(0, 10)}.ccvault`, c); setMsg({ tone: "success", text: "Coffre exporté." }); } catch (e) { setMsg({ tone: "destructive", text: errorMessage(e) }); } }}>Exporter</Button>
        <Button variant="outline" disabled={pass.length < 12} onClick={() => fileRef.current?.click()}>Importer…</Button>
        <input ref={fileRef} type="file" accept=".ccvault" className="hidden" onChange={async (e) => {
          const f = e.target.files?.[0];
          if (!f) return;
          try {
            const content = await f.text();
            const r = await reauth(() => call<ImportReportT>("vault_import", { content, passphrase: pass }));
            setMsg({ tone: "success", text: `${r.apps_created} appli(s), ${r.secrets} secret(s), ${r.env_vars} variable(s) importés${r.apps_skipped.length ? ` ; ignorées (existantes) : ${r.apps_skipped.join(", ")}` : ""}.` });
            onDone();
          } catch (err) {
            setMsg({ tone: "destructive", text: errorMessage(err) });
          } finally {
            e.target.value = "";
          }
        }} />
      </div>
      {msg && <Alert tone={msg.tone}>{msg.text}</Alert>}
    </Card>
  );
}
