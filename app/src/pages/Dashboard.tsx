// Tableau de bord (version phase 2 : liste des applis ; enrichi en phase 3).
import * as React from "react";
import { call, type App } from "@/lib/api";
import { Badge, Button, Card, Empty } from "@/components/ui";
import type { PageProps } from "./registry";

export function DashboardPage({ nav }: PageProps) {
  const [apps, setApps] = React.useState<App[]>([]);
  React.useEffect(() => {
    call<App[]>("apps_list").then(setApps).catch(() => undefined);
  }, []);
  return (
    <div className="space-y-6">
      <div className="flex items-center justify-between">
        <h1 className="text-2xl font-bold">Tableau de bord</h1>
        <Button onClick={() => nav.go("add-app")}>＋ Ajouter une appli</Button>
      </div>
      {apps.length === 0 ? (
        <Card><Empty>Aucune application. Commencez par en ajouter une.</Empty></Card>
      ) : (
        <div className="grid gap-4 sm:grid-cols-2 xl:grid-cols-3">
          {apps.map((a) => (
            <button key={a.id} onClick={() => nav.go("app", a.id)} className="text-left">
              <Card className="transition hover:border-primary">
                <div className="flex items-center gap-3">
                  <span className="text-2xl">{a.icon}</span>
                  <div className="min-w-0 flex-1">
                    <div className="truncate font-semibold">{a.name}</div>
                    <div className="truncate text-xs text-muted-foreground">{a.repo ?? "pas de dépôt"}</div>
                  </div>
                  <Badge tone="muted">{a.access_mode}</Badge>
                </div>
              </Card>
            </button>
          ))}
        </div>
      )}
    </div>
  );
}
