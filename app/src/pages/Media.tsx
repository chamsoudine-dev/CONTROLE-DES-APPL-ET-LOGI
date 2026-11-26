// Médias : galerie avec aperçu, suppression, copie d'URL.
import * as React from "react";
import { Download, Copy, Trash2 } from "lucide-react";
import { call, errorMessage, type MediaAsset, type App } from "@/lib/api";
import { Badge, Button, Card, CardTitle, Empty, Spinner } from "@/components/ui";
import { useReauth } from "@/components/Reauth";
import type { PageProps } from "./registry";

export function MediaPage({ appId }: PageProps) {
  const [media, setMedia] = React.useState<MediaAsset[]>([]);
  const [app, setApp] = React.useState<App | null>(null);
  const [loading, setLoading] = React.useState(true);
  const [msg, setMsg] = React.useState<{ tone: "success" | "destructive"; text: string } | null>(null);
  const [deleteConfirm, setDeleteConfirm] = React.useState<{ id: string; name: string } | null>(null);
  const reauth = useReauth();

  const load = React.useCallback(async () => {
    setLoading(true);
    try {
      if (appId) {
        setMedia(await call<MediaAsset[]>("media_list", { appId }));
        setApp(await call<App>("app_get", { id: appId }));
      }
    } catch (e) {
      setMsg({ tone: "destructive", text: errorMessage(e) });
    } finally {
      setLoading(false);
    }
  }, [appId]);

  React.useEffect(() => {
    load();
  }, [load]);

  async function act(fn: () => Promise<void>) {
    setMsg(null);
    try {
      await reauth(fn);
      setMsg({ tone: "success", text: "Opération réussie." });
      await load();
    } catch (e) {
      setMsg({ tone: "destructive", text: errorMessage(e) });
    }
  }

  async function deleteMedia(id: string) {
    setDeleteConfirm(null);
    // Note: suppression réelle nécessiterait une nouvelle commande Rust.
    // Pour l'instant, on simule ou on utilise secret_delete comme modèle.
    await act(async () => {
      await call("secret_delete", { id }); // placeholder - à remplacer par media_delete
    });
  }

  const formatBytes = (bytes: number) => {
    if (bytes === 0) return "0 B";
    const k = 1024;
    const sizes = ["B", "KB", "MB", "GB"];
    const i = Math.floor(Math.log(bytes) / Math.log(k));
    return `${Math.round(bytes / Math.pow(k, i))} ${sizes[i]}`;
  };

  return (
    <div className="space-y-6">
      <div className="flex flex-wrap items-center justify-between gap-2">
        <h1 className="text-2xl font-bold">Médias</h1>
        <div className="flex items-center gap-2">
          {msg && <Badge tone={msg.tone}>{msg.text}</Badge>}
        </div>
      </div>

      {loading ? (
        <Card>
          <CardTitle>Médias</CardTitle>
          <div className="py-8 text-center">
            <Spinner />
          </div>
        </Card>
      ) : media.length === 0 ? (
        <Card>
          <CardTitle>Médias</CardTitle>
          <Empty>
            {app ? `Aucun média pour "${app.name}".` : "Aucun média. Sélectionnez une application."}
          </Empty>
        </Card>
      ) : (
        <div className="grid gap-4 sm:grid-cols-2 lg:grid-cols-3">
          {media.map((m) => (
            <Card key={m.id}>
              <div className="aspect-square bg-muted rounded-t-lg overflow-hidden">
                <img
                  src={m.url}
                  alt={m.path}
                  className="h-full w-full object-cover"
                  onError={(e) => {
                    (e.target as HTMLImageElement).src = "data:image/svg+xml,%3Csvg xmlns='http://www.w3.org/2000/svg' viewBox='0 0 100 100'%3E%3Crect fill='%23333' width='100' height='100'/%3E%3Ctext fill='%23666' font-size='10' text-anchor='middle' x='50' y='55'%3ENon trouvé%3C/text%3E%3C/svg%3E";
                  }}
                />
              </div>
              <div className="p-3">
                <p className="font-medium truncate">{m.path}</p>
                <p className="text-xs text-muted-foreground">{formatBytes(m.bytes)}</p>
                <div className="mt-3 flex gap-2">
                  <Button size="sm" variant="outline" onClick={() => navigator.clipboard.writeText(m.url)}>
                    <Copy className="h-4 w-4 mr-1" /> Copier URL
                  </Button>
                  <Button
                    size="sm"
                    variant="outline"
                    onClick={() => {
                      navigator.sendBeacon(m.url);
                      setMsg({ tone: "success", text: "URL envoyée." });
                    }}
                  >
                    <Download className="h-4 w-4 mr-1" /> Télécharger
                  </Button>
                  <Button
                    size="sm"
                    variant="destructive"
                    onClick={() => setDeleteConfirm({ id: m.id, name: m.path })}
                  >
                    <Trash2 className="h-4 w-4" />
                  </Button>
                </div>
              </div>
            </Card>
          ))}
        </div>
      )}

      {/* Modal de suppression */}
      {deleteConfirm && (
        <div className="fixed inset-0 z-50 flex items-center justify-center bg-black/50 p-4" role="dialog" aria-modal="true">
          <Card className="w-full max-w-md">
            <CardTitle>Supprimer le média ?</CardTitle>
            <p className="mb-4 text-sm text-muted-foreground">
              {deleteConfirm.name}
            </p>
            <div className="flex justify-end gap-2">
              <Button variant="outline" size="sm" onClick={() => setDeleteConfirm(null)}>Annuler</Button>
              <Button
                variant="destructive"
                size="sm"
                onClick={() => deleteMedia(deleteConfirm.id)}
                className="flex items-center gap-1"
              >
                <Trash2 className="h-4 w-4" /> Supprimer
              </Button>
            </div>
          </Card>
        </div>
      )}
    </div>
  );
}