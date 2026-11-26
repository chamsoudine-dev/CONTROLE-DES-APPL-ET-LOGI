// Registre des pages (complété au fil des phases).
import type * as React from "react";
import type { Nav } from "./Shell";
import { Empty, Card, CardTitle, Button } from "@/components/ui";
import { KeysPage } from "./Keys";
import { AddAppPage } from "./AddApp";
import { AppDetailPage } from "./AppDetail";
import { DashboardPage } from "./Dashboard";
import { SyncPage } from "./Sync";
import { LicensesPage } from "./Licenses";
import { NotificationsPage } from "./Notifications";
import { MediaPage } from "./Media";

export type PageId =
  | "dashboard"
  | "keys"
  | "add-app"
  | "app"
  | "licenses"
  | "sync"
  | "notifications"
  | "media"
  | "audit"
  | "settings";

export interface PageProps {
  nav: Nav;
  appId?: string;
}

function Soon() {
  return (
    <Card>
      <Empty>Disponible dans une prochaine phase.</Empty>
    </Card>
  );
}

export const pages: Record<PageId, React.ComponentType<PageProps>> = {
  dashboard: DashboardPage,
  keys: KeysPage,
  "add-app": AddAppPage,
  app: AppDetailPage,
  licenses: LicensesPage,
  sync: SyncPage,
  notifications: NotificationsPage,
  media: MediaPage,
  audit: () => <LicensingTab />,
  settings: Soon,
};

// Placeholder pour l'onglet Audit dans Settings
function LicensingTab() {
  return (
    <div className="space-y-6">
      <h1 className="text-2xl font-bold">Journal d'audit</h1>
      <p className="text-muted-foreground">Accédez au journal d'audit depuis les Paramètres → Sécurité.</p>
      <Card>
        <CardTitle>Accéder au journal</CardTitle>
        <p className="text-sm text-muted-foreground mb-4">
          Le journal d'audit est accessible depuis la page <strong>Paramètres</strong>, section <strong>Sécurité</strong>.
          Il enregistre toutes les actions critiques avec leur résultat (sha-256 chaîné).
        </p>
        <Button onClick={() => {
          const settingsBtn = document.querySelector('[data-page="settings"]') as HTMLElement;
          if (settingsBtn) settingsBtn.scrollIntoView({ behavior: "smooth" });
        }}>
          Aller aux Paramètres
        </Button>
      </Card>
    </div>
  );
}
