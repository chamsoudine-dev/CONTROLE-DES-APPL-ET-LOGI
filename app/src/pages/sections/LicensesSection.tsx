// Section « Licences » de la fiche appli (produits liés à l'appli).
import * as React from "react";
import { call, type License, type Product } from "@/lib/api";
import { formatDate } from "@/lib/utils";
import { Badge, Card, CardTitle, Empty } from "@/components/ui";
import type { SectionProps } from "../appSections";

export function LicensesSection({ detail }: SectionProps) {
  const [rows, setRows] = React.useState<License[]>([]);
  React.useEffect(() => {
    (async () => {
      const products = await call<Product[]>("products_list");
      const ids = new Set(products.filter((p) => p.app_id === detail.app.id).map((p) => p.id));
      setRows((await call<License[]>("licenses_list")).filter((l) => ids.has(l.product_id)));
    })().catch(() => undefined);
  }, [detail.app.id]);
  if (!detail.app.licensing_enabled) return null;
  const active = rows.filter((r) => r.status === "active").length;
  return (
    <Card>
      <CardTitle>Licences <span className="text-sm font-normal text-muted-foreground">{active} active(s) · {rows.length - active} révoquée(s)</span></CardTitle>
      {rows.length === 0 ? <Empty>Aucune licence pour les produits de cette appli.</Empty> : (
        <ul className="max-h-64 divide-y overflow-auto text-sm">
          {rows.slice(0, 50).map((l) => (
            <li key={l.id} className="flex justify-between py-2"><span className="font-mono text-xs">{l.readable_key}</span><span>{l.customer_name}</span><span className="text-xs">{l.expires_at ? formatDate(l.expires_at) : "perpétuelle"}</span><Badge tone={l.status === "active" ? "success" : "destructive"}>{l.status}</Badge></li>
          ))}
        </ul>
      )}
    </Card>
  );
}
