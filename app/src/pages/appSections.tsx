// Sections supplémentaires de la fiche appli (dépôt, médias, licences…) — enregistrées par phase.
import type * as React from "react";
import type { AppDetail } from "@/lib/api";

export interface SectionProps {
  detail: AppDetail;
  reload: () => void;
}

export const appSections: React.ComponentType<SectionProps>[] = [];
