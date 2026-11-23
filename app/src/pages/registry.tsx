// Registre des pages (complété au fil des phases).
import type * as React from "react";
import type { Nav } from "./Shell";
import { AuditCard } from "./Settings";
import { Empty, Card } from "@/components/ui";

export type PageId = "dashboard" | "keys" | "add-app" | "app" | "licenses" | "sync" | "audit" | "settings";
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
  dashboard: Soon,
  keys: Soon,
  "add-app": Soon,
  app: Soon,
  licenses: Soon,
  sync: Soon,
  audit: () => <AuditCard />,
  settings: Soon,
};
