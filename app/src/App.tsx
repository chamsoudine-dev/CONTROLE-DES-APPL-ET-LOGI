import * as React from "react";
import { listen } from "@tauri-apps/api/event";
import { call, type Profile, type VaultStatus } from "@/lib/api";
import { Onboarding } from "@/pages/Onboarding";
import { LockScreen } from "@/pages/LockScreen";
import { Shell } from "@/pages/Shell";
import { ReauthProvider } from "@/components/Reauth";

/** Signale l'activité de l'utilisateur au cœur (verrouillage auto), au plus toutes les 20 s. */
function useActivityPing(enabled: boolean) {
  React.useEffect(() => {
    if (!enabled) return;
    let last = 0;
    const ping = () => {
      const now = Date.now();
      if (now - last > 20_000) {
        last = now;
        call("vault_touch").catch(() => undefined);
      }
    };
    const events = ["mousemove", "keydown", "pointerdown", "touchstart", "wheel"];
    events.forEach((e) => window.addEventListener(e, ping, { passive: true }));
    return () => events.forEach((e) => window.removeEventListener(e, ping));
  }, [enabled]);
}

export default function App() {
  const [status, setStatus] = React.useState<VaultStatus | null>(null);
  const [profile, setProfile] = React.useState<Profile | null>(null);
  const [onboardingStep, setOnboardingStep] = React.useState<number | null>(null);

  const refresh = React.useCallback(async () => {
    const s = await call<VaultStatus>("vault_status");
    setStatus(s);
    if (s.state === "unlocked") {
      const p = await call<Profile>("profile_get");
      setProfile(p);
      // Reprise de l'assistant si GitHub n'est pas encore connecté.
      setOnboardingStep((cur) => (cur === null && !p.github_login ? 2 : cur));
    } else {
      setProfile(null);
    }
  }, []);

  React.useEffect(() => {
    refresh().catch(() => undefined);
    const un = listen("vault-locked", () => refresh());
    return () => {
      un.then((f) => f());
    };
  }, [refresh]);

  useActivityPing(status?.state === "unlocked");

  if (!status) return <div className="p-8 text-muted-foreground">Chargement…</div>;
  if (status.state === "uninitialized")
    return <Onboarding initialStep={0} onDone={() => { setOnboardingStep(-1); refresh(); }} />;
  if (status.state !== "unlocked") return <LockScreen status={status} onUnlocked={refresh} />;
  if (onboardingStep !== null && onboardingStep >= 0)
    return (
      <Onboarding
        initialStep={onboardingStep}
        onDone={() => {
          setOnboardingStep(-1);
          refresh();
        }}
      />
    );
  return (
    <ReauthProvider totpEnabled={profile?.totp_enabled ?? false}>
      <Shell profile={profile} onLock={async () => { await call("vault_lock"); refresh(); }} onChanged={refresh} />
    </ReauthProvider>
  );
}
