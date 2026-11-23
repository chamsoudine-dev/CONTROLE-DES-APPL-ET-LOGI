// Sections supplémentaires de la fiche appli (dépôt, médias, licences…) — enregistrées par phase.
import type * as React from "react";
import type { AppDetail } from "@/lib/api";
import { RepoSection } from "./sections/RepoSection";
import { MediaSection } from "./sections/MediaSection";
import { LicensesSection } from "./sections/LicensesSection";

export interface SectionProps {
  detail: AppDetail;
  reload: () => void;
}

export const appSections: React.ComponentType<SectionProps>[] = [RepoSection, MediaSection, LicensesSection];
