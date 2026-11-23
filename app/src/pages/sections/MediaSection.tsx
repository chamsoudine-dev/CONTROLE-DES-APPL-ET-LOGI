// Section « Médias » : dépôt d'images, conversion WebP côté Rust, URL copiable.
import * as React from "react";
import { call, errorMessage, type MediaAsset } from "@/lib/api";
import { formatDate } from "@/lib/utils";
import { Alert, Button, Card, CardTitle, Empty, Select } from "@/components/ui";
import { useAction } from "@/components/ActionDialog";
import type { SectionProps } from "../appSections";

function toBase64(file: File): Promise<string> {
  return new Promise((resolve, reject) => {
    const r = new FileReader();
    r.onload = () => resolve(String(r.result).split(",")[1] ?? "");
    r.onerror = () => reject(r.error);
    r.readAsDataURL(file);
  });
}

export function MediaSection({ detail }: SectionProps) {
  const stores = detail.connectors.filter((c) => ["supabase", "firebase", "cloudinary"].includes(c.provider));
  const [store, setStore] = React.useState(stores[0]?.id ?? "");
  const [media, setMedia] = React.useState<MediaAsset[]>([]);
  const [err, setErr] = React.useState("");
  const [copied, setCopied] = React.useState("");
  const fileRef = React.useRef<HTMLInputElement>(null);
  const pending = React.useRef<File | null>(null);
  const action = useAction();
  const load = React.useCallback(() => call<MediaAsset[]>("media_list", { appId: detail.app.id }).then(setMedia), [detail.app.id]);
  React.useEffect(() => {
    load().catch(() => undefined);
  }, [load]);
  if (stores.length === 0) return null;

  async function onFile(f: File) {
    setErr("");
    pending.current = f;
    try {
      const prepared = await call<{ token: string; preview: string; policy_action: "media"; destructive: boolean }>("media_prepare", { appId: detail.app.id, connectorId: store, fileName: f.name, size: f.size });
      // Confirmation explicite avant l'envoi.
      if (!confirm(prepared.preview)) return;
      const data = await toBase64(f);
      await call("media_upload", { token: prepared.token, dataBase64: data });
      await load();
    } catch (e) {
      setErr(errorMessage(e));
    }
  }

  return (
    <Card>
      <CardTitle
        actions={
          <>
            <Select className="h-8 w-40" value={store} onChange={(e) => setStore(e.target.value)}>
              {stores.map((s) => <option key={s.id} value={s.id}>{s.provider}</option>)}
            </Select>
            <Button size="sm" onClick={() => fileRef.current?.click()}>Déposer une image</Button>
          </>
        }
      >
        Médias
      </CardTitle>
      <input ref={fileRef} type="file" accept="image/png,image/jpeg,image/webp,image/gif,image/bmp" className="hidden" onChange={(e) => { const f = e.target.files?.[0]; if (f) onFile(f); e.target.value = ""; }} />
      {err && <Alert tone="destructive">{err}</Alert>}
      {media.length === 0 ? <Empty>Aucun média envoyé.</Empty> : (
        <ul className="divide-y text-sm">
          {media.map((m) => (
            <li key={m.id} className="flex flex-wrap items-center gap-2 py-2">
              <img src={m.url} alt="" className="h-10 w-10 rounded object-cover" />
              <span className="min-w-0 flex-1 truncate">{m.path}</span>
              <span className="text-xs text-muted-foreground">{Math.round(m.bytes / 1024)} Ko · {m.width}×{m.height} · {formatDate(m.created_at)}</span>
              <Button size="sm" variant="outline" onClick={async () => { await navigator.clipboard.writeText(m.url); setCopied(m.id); setTimeout(() => setCopied(""), 1500); }}>{copied === m.id ? "Copiée ✓" : "Copier l'URL"}</Button>
            </li>
          ))}
        </ul>
      )}
      {action.dialog}
    </Card>
  );
}
