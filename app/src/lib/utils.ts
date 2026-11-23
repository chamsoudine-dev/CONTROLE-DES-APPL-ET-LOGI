import { clsx, type ClassValue } from "clsx";
import { twMerge } from "tailwind-merge";

export function cn(...inputs: ClassValue[]) {
  return twMerge(clsx(inputs));
}

export function formatDate(iso: string | null | undefined): string {
  if (!iso) return "—";
  const d = new Date(iso);
  if (Number.isNaN(d.getTime())) return iso;
  return d.toLocaleString("fr-FR", { dateStyle: "short", timeStyle: "short" });
}

export function timeAgo(iso: string | null | undefined, now = Date.now()): string {
  if (!iso) return "jamais";
  const t = new Date(iso).getTime();
  if (Number.isNaN(t)) return iso;
  const s = Math.max(0, Math.round((now - t) / 1000));
  if (s < 60) return "à l'instant";
  if (s < 3600) return `il y a ${Math.floor(s / 60)} min`;
  if (s < 86400) return `il y a ${Math.floor(s / 3600)} h`;
  return `il y a ${Math.floor(s / 86400)} j`;
}

/** Estimation simple de la force d'une phrase secrète (0..4), purement indicative. */
export function passphraseScore(p: string): number {
  let score = 0;
  if (p.length >= 12) score++;
  if (p.length >= 20) score++;
  if (/[a-z]/.test(p) && /[A-Z0-9]/.test(p)) score++;
  if (/[^A-Za-z0-9]/.test(p) || p.split(" ").length >= 4) score++;
  return Math.min(4, score);
}
