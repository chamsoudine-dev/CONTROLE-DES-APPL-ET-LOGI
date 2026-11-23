// Assistant « Ajouter une application ».
import * as React from "react";
import {
  call,
  errorMessage,
  type AccessMode,
  type App,
  type ProviderId,
  type ProviderInfo,
  type Repo,
  type TestReport,
} from "@/lib/api";
import { Alert, Badge, Button, Card, Field, Input, Select, Spinner, Textarea } from "@/components/ui";
import { useReauth } from "@/components/Reauth";
import type { PageProps } from "./registry";

interface ServiceDraft {
  provider: ProviderId;
  config: Record<string, string>;
  secret: string;
  report: TestReport | null;
}

const CATEGORIES: { id: string; label: string; providers: ProviderId[] }[] = [
  { id: "hosting", label: "Hébergement", providers: ["vercel", "netlify", "cloudflare"] },
  { id: "database", label: "Base de données", providers: ["supabase", "firebase"] },
  { id: "storage", label: "Stockage / médias", providers: ["cloudinary", "supabase", "firebase"] },
  { id: "payment", label: "Paiement", providers: ["custom"] },
  { id: "custom", label: "Personnalisé", providers: ["custom"] },
];

const STEPS = ["Identité", "Dépôt", "Services", "Droits", "Récapitulatif"];

export function AddAppPage({ nav }: PageProps) {
  const [step, setStep] = React.useState(0);
  const [name, setName] = React.useState("");
  const [description, setDescription] = React.useState("");
  const [icon, setIcon] = React.useState("🚀");
  const [urls, setUrls] = React.useState("");
  const [repo, setRepo] = React.useState("");
  const [repos, setRepos] = React.useState<Repo[]>([]);
  const [repoFilter, setRepoFilter] = React.useState("");
  const [catalog, setCatalog] = React.useState<ProviderInfo[]>([]);
  const [services, setServices] = React.useState<ServiceDraft[]>([]);
  const [mode, setMode] = React.useState<AccessMode>("read_only");
  const [licensing, setLicensing] = React.useState(false);
  const [err, setErr] = React.useState("");
  const [busy, setBusy] = React.useState(false);
  const reauth = useReauth();

  React.useEffect(() => {
    call<ProviderInfo[]>("providers_catalog").then(setCatalog).catch(() => undefined);
    call<Repo[]>("github_repos").then(setRepos).catch(() => undefined);
  }, []);

  const info = (p: ProviderId) => catalog.find((c) => c.provider === p);

  async function testService(i: number) {
    const s = services[i];
    if (!s) return;
    setErr("");
    try {
      const report = await call<TestReport>("connector_test_draft", { provider: s.provider, config: s.config, secret: s.secret || null });
      setServices((all) => all.map((x, j) => (j === i ? { ...x, report } : x)));
    } catch (e) {
      setErr(errorMessage(e));
    }
  }

  async function create() {
    setBusy(true);
    setErr("");
    try {
      const app = await reauth(() =>
        call<App>("app_create", {
          app: {
            name,
            description,
            icon: icon || null,
            urls: urls.split(/\s+/).filter(Boolean),
            repo: repo || null,
            access_mode: mode,
            licensing_enabled: licensing,
          },
        }),
      );
      if (repo) {
        await call("connector_add", { appId: app.id, provider: "github", config: { repo }, secret: null, environment: null });
      }
      for (const s of services) {
        await call("connector_add", { appId: app.id, provider: s.provider, config: s.config, secret: s.secret || null, environment: "production" });
      }
      nav.go("app", app.id);
    } catch (e) {
      setErr(errorMessage(e));
    } finally {
      setBusy(false);
    }
  }

  return (
    <div className="mx-auto max-w-3xl space-y-4">
      <h1 className="text-2xl font-bold">Ajouter une application</h1>
      <ol className="flex flex-wrap gap-3 text-sm">
        {STEPS.map((s, i) => (
          <li key={s} className={i === step ? "font-semibold text-primary" : i < step ? "text-success" : "text-muted-foreground"}>{i + 1}. {s}</li>
        ))}
      </ol>
      <Card className="space-y-4">
        {step === 0 && (
          <>
            <div className="grid grid-cols-[5rem_1fr] gap-3">
              <Field label="Icône"><Input value={icon} maxLength={4} onChange={(e) => setIcon(e.target.value)} className="text-center text-2xl" /></Field>
              <Field label="Nom"><Input value={name} onChange={(e) => setName(e.target.value)} maxLength={80} /></Field>
            </div>
            <Field label="Description"><Textarea rows={2} value={description} onChange={(e) => setDescription(e.target.value)} className="font-sans" /></Field>
            <Field label="URL(s)" hint="Une par ligne, HTTPS. Servent aux vérifications en ligne / hors ligne."><Textarea rows={2} value={urls} onChange={(e) => setUrls(e.target.value)} placeholder="https://monappli.com" /></Field>
          </>
        )}
        {step === 1 && (
          <>
            <Field label="Rechercher un dépôt GitHub"><Input value={repoFilter} onChange={(e) => setRepoFilter(e.target.value)} placeholder="filtrer…" /></Field>
            <Select value={repo} onChange={(e) => setRepo(e.target.value)} size={8} className="h-auto">
              <option value="">— aucun —</option>
              {repos.filter((r) => r.full_name.toLowerCase().includes(repoFilter.toLowerCase())).map((r) => (
                <option key={r.full_name} value={r.full_name}>{r.full_name}{r.private ? " 🔒" : ""}</option>
              ))}
            </Select>
          </>
        )}
        {step === 2 && (
          <ServicesStep catalog={catalog} services={services} setServices={setServices} info={info} onTest={testService} />
        )}
        {step === 3 && (
          <>
            <Field label="Mode d'accès">
              <Select value={mode} onChange={(e) => setMode(e.target.value as AccessMode)}>
                <option value="read_only">Lecture seule (recommandé pour commencer)</option>
                <option value="read_write">Lecture-écriture (ré-authentification)</option>
                <option value="disabled">Désactivé</option>
              </Select>
            </Field>
            <p className="text-xs text-muted-foreground">La matrice détaillée (redéployer, rollback, variables, médias, licences, supprimer) se règle ensuite dans la fiche de l'appli.</p>
            <label className="flex items-center gap-2 text-sm"><input type="checkbox" checked={licensing} onChange={(e) => setLicensing(e.target.checked)} /> Activer la gestion des licences pour cette appli</label>
          </>
        )}
        {step === 4 && (
          <div className="space-y-2 text-sm">
            <p><span className="text-2xl">{icon}</span> <b>{name}</b> — {description || "sans description"}</p>
            <p>Dépôt : <code>{repo || "—"}</code></p>
            <p>Services : {services.length === 0 ? "aucun" : services.map((s) => `${info(s.provider)?.label ?? s.provider}${s.report?.ok ? " ✓" : ""}`).join(", ")}</p>
            <p>Mode : <Badge>{mode}</Badge> · Licences : {licensing ? "oui" : "non"}</p>
          </div>
        )}
        {err && <Alert tone="destructive">{err}</Alert>}
        <div className="flex justify-between">
          <Button variant="ghost" onClick={() => setStep((s) => s - 1)} disabled={step === 0}>← Retour</Button>
          {step < STEPS.length - 1 ? (
            <Button onClick={() => setStep((s) => s + 1)} disabled={step === 0 && !name.trim()}>Continuer →</Button>
          ) : (
            <Button onClick={create} disabled={busy}>{busy && <Spinner />} Créer l'application</Button>
          )}
        </div>
      </Card>
    </div>
  );
}

function ServicesStep({
  catalog,
  services,
  setServices,
  info,
  onTest,
}: {
  catalog: ProviderInfo[];
  services: ServiceDraft[];
  setServices: React.Dispatch<React.SetStateAction<ServiceDraft[]>>;
  info: (p: ProviderId) => ProviderInfo | undefined;
  onTest: (i: number) => void;
}) {
  const [cat, setCat] = React.useState("hosting");
  const [prov, setProv] = React.useState<ProviderId>("vercel");
  const current = CATEGORIES.find((c) => c.id === cat);
  return (
    <div className="space-y-4">
      <div className="flex flex-wrap items-end gap-2">
        <Field label="Type de service">
          <Select value={cat} onChange={(e) => { setCat(e.target.value); setProv(CATEGORIES.find((c) => c.id === e.target.value)?.providers[0] ?? "custom"); }}>
            {CATEGORIES.map((c) => <option key={c.id} value={c.id}>{c.label}</option>)}
          </Select>
        </Field>
        <Field label="Fournisseur">
          <Select value={prov} onChange={(e) => setProv(e.target.value as ProviderId)}>
            {current?.providers.map((p) => <option key={p} value={p}>{catalog.find((c) => c.provider === p)?.label ?? p}</option>)}
          </Select>
        </Field>
        <Button variant="outline" onClick={() => setServices((s) => [...s, { provider: prov, config: {}, secret: "", report: null }])}>＋ Ajouter</Button>
      </div>
      {services.map((s, i) => {
        const pi = info(s.provider);
        if (!pi) return null;
        const set = (k: string, v: string) => setServices((all) => all.map((x, j) => (j === i ? { ...x, config: { ...x.config, [k]: v }, report: null } : x)));
        return (
          <div key={i} className="space-y-3 rounded-md border p-4">
            <div className="flex items-center justify-between">
              <h3 className="font-semibold">{pi.label}</h3>
              <button className="text-xs text-destructive" onClick={() => setServices((all) => all.filter((_, j) => j !== i))}>retirer</button>
            </div>
            <div className="grid gap-3 sm:grid-cols-2">
              {pi.fields.map((f) => (
                <Field key={f.key} label={`${f.label}${f.required ? " *" : ""}`} hint={f.help}>
                  {f.options.length > 0 ? (
                    <Select value={s.config[f.key] ?? ""} onChange={(e) => set(f.key, e.target.value)}>
                      <option value="">—</option>
                      {f.options.map((o) => <option key={o} value={o}>{o}</option>)}
                    </Select>
                  ) : (
                    <Input value={s.config[f.key] ?? ""} onChange={(e) => set(f.key, e.target.value)} />
                  )}
                </Field>
              ))}
            </div>
            <Field label={pi.secret_label} hint={pi.secret_help}>
              {s.provider === "firebase" ? (
                <Textarea rows={3} value={s.secret} onChange={(e) => setServices((all) => all.map((x, j) => (j === i ? { ...x, secret: e.target.value, report: null } : x)))} placeholder='{"type":"service_account",…}' />
              ) : (
                <Input type="password" value={s.secret} onChange={(e) => setServices((all) => all.map((x, j) => (j === i ? { ...x, secret: e.target.value, report: null } : x)))} />
              )}
            </Field>
            <details className="text-xs">
              <summary className="cursor-pointer text-muted-foreground">Permissions recommandées (minimales)</summary>
              <ul className="mt-2 space-y-1">
                {pi.permissions.map((p) => (
                  <li key={p.scope + p.access}><Badge tone={p.access === "read" ? "muted" : "warning"}>{p.access === "read" ? "Lecture" : "Écriture"}</Badge> <code>{p.scope}</code> — {p.reason}</li>
                ))}
              </ul>
            </details>
            <div className="flex items-center gap-3">
              <Button size="sm" variant="outline" onClick={() => onTest(i)}>Tester la clé et ses permissions</Button>
              {s.report && (s.report.ok ? <Badge tone="success">✓ valide{s.report.identity ? ` · ${s.report.identity}` : ""}</Badge> : <Badge tone="destructive">✗ échec</Badge>)}
              {s.report && <span className="text-xs">lecture {s.report.can_read ? "✓" : "✗"} · écriture {s.report.can_write ? "✓" : "✗"}</span>}
            </div>
            {s.report?.warnings.map((w) => <Alert key={w} tone={s.report?.too_powerful ? "warning" : "muted"}>{w}</Alert>)}
          </div>
        );
      })}
    </div>
  );
}
