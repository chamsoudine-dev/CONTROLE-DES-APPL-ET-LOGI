// Centre de notifications : échecs CI, clés expirées, licences à échéance, alertes système.
import * as React from "react";
import { Bell, AlertCircle, Key, Calendar, Settings } from "lucide-react";
import { call, errorMessage, type AlertItem, type NotificationItem } from "@/lib/api";
import { Badge, Button, Card, CardTitle, Empty, Spinner, Alert } from "@/components/ui";

type FilterType = "all" | "ci_failure" | "key_expiring" | "license_expiring" | "app_offline" | "new_release";

export function NotificationsPage() {
  const [filter, setFilter] = React.useState<FilterType>("all");
  const [alerts, setAlerts] = React.useState<AlertItem[]>([]);
  const [loading, setLoading] = React.useState(true);
  const [msg, setMsg] = React.useState("");

  const load = React.useCallback(async () => {
    setLoading(true);
    try {
      const aler = await call<AlertItem[]>("alerts_list");
      setAlerts(aler);
    } catch (e) {
      setMsg(errorMessage(e));
    } finally {
      setLoading(false);
    }
  }, []);

  React.useEffect(() => {
    load();
  }, [load]);

  // Convertir les alertes en notifications
  const notifications: NotificationItem[] = React.useMemo(() => {
    return alerts.map((a) => ({
      id: `alert-${a.app_id ?? "global"}-${a.message.substring(0, 10)}`,
      type: a.app_id ? "app_offline" : "key_expiring",
      title: a.message,
      message: a.message,
      level: a.level,
      app_id: a.app_id ?? "global",
      timestamp: new Date().toISOString(),
    }));
  }, [alerts]);

  // Fusionner alertes et notifications
  const allItems = notifications;
  const filteredItems = React.useMemo(() => {
    if (filter === "all") return allItems;
    return allItems.filter((n) => n.type === filter);
  }, [allItems, filter]);

  const countByType: Record<FilterType, number> = {
    all: allItems.length,
    ci_failure: allItems.filter((n) => n.type === "ci_failure").length,
    key_expiring: allItems.filter((n) => n.type === "key_expiring").length,
    license_expiring: allItems.filter((n) => n.type === "license_expiring").length,
    app_offline: allItems.filter((n) => n.type === "app_offline").length,
    new_release: allItems.filter((n) => n.type === "new_release").length,
  };

  const iconByFilter: Record<FilterType, { icon: React.ElementType; label: string; color: "default" | "success" | "warning" | "destructive" | "muted" }> = {
    all: { icon: Bell, label: "Toutes", color: "muted" },
    ci_failure: { icon: AlertCircle, label: "Échecs CI", color: "destructive" },
    key_expiring: { icon: Key, label: "Clés expirées", color: "warning" },
    license_expiring: { icon: Calendar, label: "Licences", color: "warning" },
    app_offline: { icon: Settings, label: "App hors ligne", color: "muted" },
    new_release: { icon: Bell, label: "Nouvelle version", color: "success" },
  };

  return (
    <div className="space-y-6">
      <div className="flex flex-wrap items-center justify-between gap-2">
        <h1 className="text-2xl font-bold">Notifications</h1>
      </div>

      {msg && <Alert tone="destructive">{msg}</Alert>}

      {/* Filtres et comptes */}
      <div className="flex flex-wrap gap-2">
        {(Object.keys(iconByFilter) as FilterType[]).map((f) => {
          const Icon = iconByFilter[f].icon;
          return (
            <Button
              key={f}
              size="sm"
              variant={filter === f ? "default" : "outline"}
              onClick={() => setFilter(f)}
              className="gap-1"
            >
              <Icon className="h-4 w-4" />
              <span className="font-medium">{iconByFilter[f].label}</span>
              <Badge tone={iconByFilter[f].color}>{countByType[f]}</Badge>
            </Button>
          );
        })}
      </div>

      {/* Liste des notifications */}
      {loading ? (
        <Card>
          <CardTitle>Notifications</CardTitle>
          <div className="py-8 text-center">
            <Spinner />
          </div>
        </Card>
      ) : filteredItems.length === 0 ? (
        <Card>
          <CardTitle>Notifications</CardTitle>
          <Empty>
            {filter === "all" ? "Pas de notification." : `Aucune notification "${iconByFilter[filter].label}".`}
          </Empty>
        </Card>
      ) : (
        <div className="space-y-3">
          {filteredItems.map((n) => (
            <Card key={n.id} className="flex items-start gap-3">
              <div className="flex-1">
                <div className="flex items-center gap-2 mb-1">
                  <Badge tone={n.level === "error" ? "destructive" : "warning"}>{n.level === "error" ? "ERREUR" : "ALERTE"}</Badge>
                  <span className="text-xs text-muted-foreground">{new Date(n.timestamp).toLocaleString("fr-FR")}</span>
                </div>
                <p className="text-sm">{n.title}</p>
                {n.app_id !== "global" && <p className="text-xs text-muted-foreground mt-1">App ID: {n.app_id}</p>}
              </div>
            </Card>
          ))}
        </div>
      )}
    </div>
  );
}