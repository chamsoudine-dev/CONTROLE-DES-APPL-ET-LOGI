// Assistant de premier lancement : profil → sécurité (2FA, PIN) → GitHub → dépôt de sync → clé de licences.
import * as React from "react";
import {
  call,
  errorMessage,
  type DeviceCode,
  type PermissionSpec,
  type Repo,
  type TestReport,
  type TotpSetup,
  type VaultStatus,
} from "@/lib/api";
import { passphraseScore } from "@/lib/utils";
import { Alert, Badge, Button, Card, Field, Input, Select, Spinner } from "@/components/ui";

const STEPS = ["Profil", "Sécurité", "GitHub", "Dépôt de sync", "Clé de licences"];

export function Stepper({ step }: { step: number }) {
  return (
    <ol className="mb-6 flex flex-wrap gap-2 text-sm">
      {STEPS.map((s, i) => (
        <li key={s} className={i === step ? "font-semibold text-primary" : i < step ? "text-success" : "text-muted-foreground"}>
          {i < step ? "✓" : i === step ? "●" : "○"} {s}
        </li>
      ))}
    </ol>
  );
}

export function Onboarding({ initialStep, onDone }: { initialStep: number; onDone: () => void }) {
  const [step, setStep] = React.useState(initialStep);
  const next = () => setStep((s) => s + 1);
  return (
    <div className="mx-auto max-w-2xl p-4 sm:p-8">
      <h1 className="mb-2 text-2xl font-bold">Bienvenue dans Control Center</h1>
      <p className="mb-6 text-sm text-muted-foreground">
        Votre appareil est le serveur : tout est chiffré localement. GitHub est le seul service externe requis.
      </p>
      <Stepper step={step} />
      {step === 0 && <ProfileStep onNext={next} />}
      {step === 1 && <SecurityStep onNext={next} />}
      {step === 2 && <GithubStep onNext={next} />}
      {step === 3 && <SyncRepoStep onNext={next} />}
      {step === 4 && <LicenseKeyStep onNext={onDone} />}
    </div>
  );
}

function ProfileStep({ onNext }: { onNext: () => void }) {
  const [name, setName] = React.useState("");
  const [pass, setPass] = React.useState("");
  const [confirm, setConfirm] = React.useState("");
  const [err, setErr] = React.useState("");
  const [busy, setBusy] = React.useState(false);
  const score = passphraseScore(pass);
  const labels = ["très faible", "faible", "moyenne", "forte", "très forte"];

  async function submit(e: React.FormEvent) {
    e.preventDefault();
    if (pass !== confirm) return setErr("Les deux saisies diffèrent.");
    setBusy(true);
    setErr("");
    try {
      await call("vault_setup", { displayName: name, passphrase: pass });
      setPass("");
      setConfirm("");
      onNext();
    } catch (e) {
      setErr(errorMessage(e));
    } finally {
      setBusy(false);
    }
  }

  return (
    <Card>
      <form onSubmit={submit} className="space-y-4">
        <h2 className="text-lg font-semibold">Étape 1 — Votre profil local</h2>
        <Field label="Nom affiché">
          <Input value={name} onChange={(e) => setName(e.target.value)} maxLength={80} required />
        </Field>
        <Field label="Phrase secrète maîtresse" hint="12 caractères minimum ; une phrase de 4 à 6 mots est idéale.">
          <Input type="password" value={pass} onChange={(e) => setPass(e.target.value)} required />
        </Field>
        <div className="h-2 w-full overflow-hidden rounded bg-muted" aria-label={`Force : ${labels[score]}`}>
          <div className="h-full bg-primary transition-all" style={{ width: `${(score / 4) * 100}%` }} />
        </div>
        <p className="text-xs text-muted-foreground">Force : {labels[score]}</p>
        <Field label="Confirmer">
          <Input type="password" value={confirm} onChange={(e) => setConfirm(e.target.value)} required />
        </Field>
        <Alert tone="warning">
          Elle chiffre toute la base (Argon2id + SQLCipher). Elle n'est stockée nulle part : si vous l'oubliez, vos
          données sont irrécupérables.
        </Alert>
        {err && <Alert tone="destructive">{err}</Alert>}
        <Button type="submit" disabled={busy}>{busy ? <Spinner /> : null} Créer mon coffre</Button>
      </form>
    </Card>
  );
}

function SecurityStep({ onNext }: { onNext: () => void }) {
  const [setup, setSetup] = React.useState<TotpSetup | null>(null);
  const [code, setCode] = React.useState("");
  const [totpDone, setTotpDone] = React.useState(false);
  const [pin, setPin] = React.useState("");
  const [pinMsg, setPinMsg] = React.useState("");
  const [status, setStatus] = React.useState<VaultStatus | null>(null);
  const [err, setErr] = React.useState("");

  React.useEffect(() => {
    call<VaultStatus>("vault_status").then(setStatus).catch(() => undefined);
  }, []);

  async function begin() {
    setErr("");
    try {
      setSetup(await call<TotpSetup>("totp_begin"));
    } catch (e) {
      setErr(errorMessage(e));
    }
  }
  async function confirmTotp() {
    setErr("");
    try {
      await call("totp_confirm", { code });
      setTotpDone(true);
      setSetup(null);
    } catch (e) {
      setErr(errorMessage(e));
    }
  }
  async function savePin() {
    setPinMsg("");
    try {
      await call("pin_set", { pin });
      setPin("");
      setPinMsg("PIN enregistré.");
    } catch (e) {
      setPinMsg(errorMessage(e));
    }
  }

  return (
    <Card className="space-y-5">
      <h2 className="text-lg font-semibold">Étape 2 — Double authentification et PIN</h2>
      <section className="space-y-3">
        <h3 className="font-medium">2FA TOTP (recommandée)</h3>
        {totpDone ? (
          <Alert tone="success">2FA activée. Elle sera demandée au déverrouillage et pour les actions sensibles.</Alert>
        ) : setup ? (
          <div className="space-y-3">
            <img src={`data:image/png;base64,${setup.qr_png_base64}`} alt="QR code TOTP" className="h-48 w-48 rounded bg-white p-2" />
            <p className="text-xs text-muted-foreground">
              Scannez avec votre application d'authentification. Clé manuelle :{" "}
              <code className="break-all">{setup.secret_base32}</code>
            </p>
            <div className="flex gap-2">
              <Input inputMode="numeric" maxLength={6} placeholder="123456" value={code} onChange={(e) => setCode(e.target.value)} />
              <Button onClick={confirmTotp}>Vérifier</Button>
            </div>
          </div>
        ) : (
          <Button variant="outline" onClick={begin}>Activer la 2FA</Button>
        )}
      </section>
      <section className="space-y-2">
        <h3 className="font-medium">PIN de déverrouillage rapide (optionnel)</h3>
        {status && !status.pin_available && status.secret_backend.includes("fallback") ? (
          <p className="text-sm text-muted-foreground">Trousseau du système indisponible : PIN non proposé sur cet appareil.</p>
        ) : (
          <div className="flex gap-2">
            <Input type="password" inputMode="numeric" maxLength={12} placeholder="6 à 12 chiffres" value={pin} onChange={(e) => setPin(e.target.value)} />
            <Button variant="outline" onClick={savePin} disabled={pin.length < 6}>Définir</Button>
          </div>
        )}
        {pinMsg && <p className="text-sm">{pinMsg}</p>}
        <p className="text-xs text-muted-foreground">Après 5 erreurs, le PIN est désactivé et la phrase secrète devient obligatoire.</p>
      </section>
      {err && <Alert tone="destructive">{err}</Alert>}
      <Button onClick={onNext}>Continuer</Button>
    </Card>
  );
}

export function GithubStep({ onNext }: { onNext: () => void }) {
  const [mode, setMode] = React.useState<"token" | "device">("token");
  const [perms, setPerms] = React.useState<PermissionSpec[]>([]);
  const [token, setToken] = React.useState("");
  const [clientId, setClientId] = React.useState("");
  const [device, setDevice] = React.useState<DeviceCode | null>(null);
  const [report, setReport] = React.useState<TestReport | null>(null);
  const [err, setErr] = React.useState("");
  const [busy, setBusy] = React.useState(false);

  React.useEffect(() => {
    call<PermissionSpec[]>("github_permissions").then(setPerms).catch(() => undefined);
  }, []);

  async function connectToken() {
    setBusy(true);
    setErr("");
    try {
      const r = await call<TestReport>("github_connect_token", { token });
      setToken("");
      setReport(r);
    } catch (e) {
      setErr(errorMessage(e));
    } finally {
      setBusy(false);
    }
  }

  async function startDevice() {
    setErr("");
    try {
      const d = await call<DeviceCode>("github_device_start", { clientId });
      setDevice(d);
      let interval = d.interval * 1000;
      const deadline = Date.now() + d.expires_in * 1000;
      const tick = async () => {
        if (Date.now() > deadline) return setErr("Code expiré.");
        try {
          const r = await call<{ status: string; report?: TestReport }>("github_device_poll", { clientId, deviceCode: d.device_code });
          if (r.status === "connected" && r.report) {
            setReport(r.report);
            setDevice(null);
            return;
          }
          if (r.status === "slow_down") interval += 5000;
          setTimeout(tick, interval);
        } catch (e) {
          setErr(errorMessage(e));
        }
      };
      setTimeout(tick, interval);
    } catch (e) {
      setErr(errorMessage(e));
    }
  }

  return (
    <Card className="space-y-4">
      <h2 className="text-lg font-semibold">Étape 3 — Connexion GitHub (obligatoire)</h2>
      <p className="text-sm text-muted-foreground">GitHub sert à la distribution, aux mises à jour, à la synchronisation chiffrée et au suivi de vos dépôts.</p>
      <div className="overflow-x-auto">
        <table className="w-full text-sm">
          <thead>
            <tr className="text-left text-muted-foreground">
              <th className="py-1">Permission</th>
              <th>Accès</th>
              <th>Pourquoi</th>
            </tr>
          </thead>
          <tbody>
            {perms.map((p) => (
              <tr key={p.scope + p.access} className="border-t">
                <td className="py-1 font-mono text-xs">{p.scope}</td>
                <td>
                  <Badge tone={p.access === "read" ? "muted" : "warning"}>{p.access === "read" ? "Lecture" : "Écriture"}</Badge>
                </td>
                <td className="text-xs">{p.reason}</td>
              </tr>
            ))}
          </tbody>
        </table>
      </div>
      <div className="flex gap-2">
        <Button variant={mode === "token" ? "default" : "outline"} size="sm" onClick={() => setMode("token")}>Jeton fine-grained (recommandé)</Button>
        <Button variant={mode === "device" ? "default" : "outline"} size="sm" onClick={() => setMode("device")}>OAuth Device Flow</Button>
      </div>
      {mode === "token" ? (
        <div className="space-y-2">
          <p className="text-xs text-muted-foreground">
            GitHub → Settings → Developer settings → Fine-grained tokens. Limitez-le aux dépôts suivis + le dépôt de sync ;
            Contents : lecture/écriture, Metadata : lecture, Actions : lecture ; définissez une expiration.
          </p>
          <Field label="Jeton">
            <Input type="password" value={token} onChange={(e) => setToken(e.target.value)} placeholder="github_pat_…" />
          </Field>
          <Button onClick={connectToken} disabled={busy || !token}>{busy && <Spinner />} Tester et connecter</Button>
        </div>
      ) : (
        <div className="space-y-2">
          <p className="text-xs text-muted-foreground">Nécessite le Client ID (non secret) d'une OAuth App GitHub avec « Device flow » activé.</p>
          <Field label="Client ID">
            <Input value={clientId} onChange={(e) => setClientId(e.target.value)} placeholder="Iv1.…" />
          </Field>
          {device ? (
            <Alert>
              Ouvrez <b>{device.verification_uri}</b> et saisissez le code <b className="font-mono text-lg">{device.user_code}</b>. En attente…
            </Alert>
          ) : (
            <Button onClick={startDevice} disabled={!clientId}>Obtenir un code</Button>
          )}
        </div>
      )}
      {report && (
        <div className="space-y-2">
          {report.ok ? (
            <Alert tone="success">Connecté en tant que @{report.identity}.</Alert>
          ) : (
            <Alert tone="destructive">Échec de connexion.</Alert>
          )}
          {report.warnings.map((w) => (
            <Alert key={w} tone="warning">{w}</Alert>
          ))}
        </div>
      )}
      {err && <Alert tone="destructive">{err}</Alert>}
      <Button onClick={onNext} disabled={!report?.ok}>Continuer</Button>
    </Card>
  );
}

export function SyncRepoStep({ onNext }: { onNext: () => void }) {
  const [repos, setRepos] = React.useState<Repo[]>([]);
  const [choice, setChoice] = React.useState("__new__");
  const [name, setName] = React.useState("control-center-sync");
  const [done, setDone] = React.useState<Repo | null>(null);
  const [err, setErr] = React.useState("");

  React.useEffect(() => {
    call<Repo[]>("github_repos").then((r) => setRepos(r.filter((x) => x.private))).catch((e) => setErr(errorMessage(e)));
  }, []);

  async function submit() {
    setErr("");
    try {
      const r = await call<Repo>("github_setup_sync_repo", choice === "__new__" ? { name } : { existing: choice });
      setDone(r);
    } catch (e) {
      setErr(errorMessage(e));
    }
  }

  return (
    <Card className="space-y-4">
      <h2 className="text-lg font-semibold">Étape 4 — Dépôt privé de synchronisation</h2>
      <p className="text-sm text-muted-foreground">Il ne contiendra que des données chiffrées (XChaCha20-Poly1305) : GitHub ne peut pas les lire.</p>
      <Select value={choice} onChange={(e) => setChoice(e.target.value)}>
        <option value="__new__">Créer un nouveau dépôt privé</option>
        {repos.map((r) => (
          <option key={r.full_name} value={r.full_name}>{r.full_name}</option>
        ))}
      </Select>
      {choice === "__new__" && (
        <Field label="Nom du dépôt">
          <Input value={name} onChange={(e) => setName(e.target.value)} />
        </Field>
      )}
      {done ? <Alert tone="success">Dépôt {done.full_name} configuré.</Alert> : <Button onClick={submit}>Valider</Button>}
      {err && <Alert tone="destructive">{err}</Alert>}
      <Button variant={done ? "default" : "ghost"} onClick={onNext}>{done ? "Continuer" : "Passer (configurer plus tard)"}</Button>
    </Card>
  );
}

export function LicenseKeyStep({ onNext }: { onNext: () => void }) {
  const [kid, setKid] = React.useState<string | null>(null);
  const [err, setErr] = React.useState("");

  async function generate() {
    setErr("");
    try {
      setKid(await call<string>("license_key_generate"));
    } catch (e) {
      setErr(errorMessage(e));
    }
  }

  return (
    <Card className="space-y-4">
      <h2 className="text-lg font-semibold">Étape 5 — Clé de signature des licences</h2>
      <p className="text-sm text-muted-foreground">
        Paire Ed25519 : la clé privée reste dans le trousseau de cet appareil ; la clé publique sera intégrée à vos applis clientes.
        Une sauvegarde chiffrée est proposée dans Paramètres → Licences.
      </p>
      {kid ? <Alert tone="success">Clé créée : <code className="break-all">{kid}</code></Alert> : <Button onClick={generate}>Générer la paire Ed25519</Button>}
      {err && <Alert tone="destructive">{err}</Alert>}
      <Button variant={kid ? "default" : "ghost"} onClick={onNext}>{kid ? "Terminer" : "Passer"}</Button>
    </Card>
  );
}
