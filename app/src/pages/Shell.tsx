// Coque de l'application : barre latérale (desktop) / barre inférieure (mobile) + page active.
import * as React from "react";
import { KeyRound, LayoutDashboard, Lock, Plus, RefreshCw, ScrollText, Settings as SettingsIcon, Ticket } from "lucide-react";
import type { Profile } from "@/lib/api";
import { cn } from "@/lib/utils";
import { Settings } from "./Settings";
import { pages, type PageId } from "./registry";

const NAV: { id: PageId; label: string; icon: React.ComponentType<{ className?: string }> }[] = [
  { id: "dashboard", label: "Tableau de bord", icon: LayoutDashboard },
  { id: "keys", label: "Environnements & Clés", icon: KeyRound },
  { id: "add-app", label: "Ajouter une appli", icon: Plus },
  { id: "licenses", label: "Licences", icon: Ticket },
  { id: "sync", label: "Synchronisation", icon: RefreshCw },
  { id: "audit", label: "Journal", icon: ScrollText },
  { id: "settings", label: "Paramètres", icon: SettingsIcon },
];

export interface Nav {
  go: (page: PageId, appId?: string) => void;
}

export function Shell({ profile, onLock, onChanged }: { profile: Profile | null; onLock: () => void; onChanged: () => void }) {
  const [page, setPage] = React.useState<PageId>("dashboard");
  const [appId, setAppId] = React.useState<string | undefined>();
  const nav: Nav = { go: (p, a) => { setPage(p); setAppId(a); } };
  const Page = pages[page];

  return (
    <div className="flex min-h-screen flex-col md:flex-row">
      <aside className="hidden w-60 shrink-0 flex-col border-r bg-card p-3 md:flex">
        <div className="mb-4 px-2">
          <div className="font-bold">Control Center</div>
          <div className="truncate text-xs text-muted-foreground">{profile?.display_name}{profile?.github_login ? ` · @${profile.github_login}` : ""}</div>
        </div>
        <nav className="flex-1 space-y-1">
          {NAV.map((n) => (
            <button
              key={n.id}
              onClick={() => nav.go(n.id)}
              className={cn(
                "flex w-full items-center gap-2 rounded-md px-2 py-2 text-left text-sm hover:bg-muted",
                page === n.id && "bg-muted font-medium",
              )}
            >
              <n.icon className="h-4 w-4" /> {n.label}
            </button>
          ))}
        </nav>
        <button onClick={onLock} className="flex items-center gap-2 rounded-md px-2 py-2 text-sm hover:bg-muted">
          <Lock className="h-4 w-4" /> Verrouiller
        </button>
      </aside>
      <main className="flex-1 overflow-auto p-4 pb-20 sm:p-6 md:pb-6">
        {page === "settings" ? <Settings onChanged={onChanged} /> : <Page nav={nav} appId={appId} />}
      </main>
      <nav className="fixed inset-x-0 bottom-0 z-40 flex justify-around border-t bg-card py-1 md:hidden">
        {NAV.filter((n) => ["dashboard", "keys", "licenses", "sync", "settings"].includes(n.id)).map((n) => (
          <button key={n.id} onClick={() => nav.go(n.id)} className={cn("flex flex-col items-center px-2 py-1 text-[10px]", page === n.id ? "text-primary" : "text-muted-foreground")}>
            <n.icon className="h-5 w-5" />
            {n.label.split(" ")[0]}
          </button>
        ))}
        <button onClick={onLock} className="flex flex-col items-center px-2 py-1 text-[10px] text-muted-foreground">
          <Lock className="h-5 w-5" /> Verrouiller
        </button>
      </nav>
    </div>
  );
}
