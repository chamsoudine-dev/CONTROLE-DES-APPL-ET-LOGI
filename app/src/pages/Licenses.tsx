// Licences : produits, clients, ventes (saisie manuelle), licences signées, révocations publiées.
import * as React from "react";
import { call, errorMessage, type App, type Customer, type License, type LicenseKind, type Product, type RevocationInfo, type Sale } from "@/lib/api";
import { formatDate } from "@/lib/utils";
import { Alert, Badge, Button, Card, CardTitle, Empty, Field, Input, Select, Textarea } from "@/components/ui";
import { useReauth } from "@/components/Reauth";
import type { PageProps } from "./registry";

type Tab = "licenses" | "products" | "customers" | "sales" | "revocations";
const TABS: [Tab, string][] = [["licenses", "Licences"], ["products", "Produits"], ["customers", "Clients"], ["sales", "Ventes"], ["revocations", "Révocations"]];

function money(cents: number, cur: string) {
  return new Intl.NumberFormat("fr-FR", { style: "currency", currency: cur, maximumFractionDigits: 0 }).format(cents / 100);
}

function download(name: string, content: string, type: string) {
  const url = URL.createObjectURL(new Blob([content], { type }));
  const a = document.createElement("a");
  a.href = url;
  a.download = name;
  a.click();
  URL.revokeObjectURL(url);
}

export function LicensesPage(props: PageProps) {
  void props;
  const [tab, setTab] = React.useState<Tab>("licenses");
  const [products, setProducts] = React.useState<Product[]>([]);
  const [customers, setCustomers] = React.useState<Customer[]>([]);
  const [sales, setSales] = React.useState<Sale[]>([]);
  const [licenses, setLicenses] = React.useState<License[]>([]);
  const [rev, setRev] = React.useState<RevocationInfo | null>(null);
  const [msg, setMsg] = React.useState<{ tone: "success" | "destructive"; text: string } | null>(null);
  const reauth = useReauth();

  const load = React.useCallback(async () => {
    setProducts(await call<Product[]>("products_list"));
    setCustomers(await call<Customer[]>("customers_list"));
    setSales(await call<Sale[]>("sales_list"));
    setLicenses(await call<License[]>("licenses_list"));
    setRev(await call<RevocationInfo>("revocations_info"));
  }, []);
  React.useEffect(() => {
    load().catch((e) => setMsg({ tone: "destructive", text: errorMessage(e) }));
  }, [load]);

  async function act<T>(fn: () => Promise<T>, ok: (r: T) => string) {
    setMsg(null);
    try {
      const r = await reauth(fn);
      setMsg({ tone: "success", text: ok(r) });
      await load();
    } catch (e) {
      setMsg({ tone: "destructive", text: errorMessage(e) });
    }
  }

  return (
    <div className="space-y-6">
      <div className="flex flex-wrap items-center justify-between gap-2">
        <h1 className="text-2xl font-bold">Licences</h1>
        <div className="flex items-center gap-2 text-sm">
          {rev && <Badge tone={rev.status.unpublished > 0 ? "warning" : "muted"}>Révocations : liste n° {rev.status.last_seq ?? "—"}{rev.status.unpublished > 0 ? ` · ${rev.status.unpublished} à publier` : ""}</Badge>}
          <Button size="sm" variant="outline" onClick={async () => download("licences.csv", await call<string>("licenses_export_csv"), "text/csv")}>Exporter CSV</Button>
        </div>
      </div>
      <div className="flex flex-wrap gap-1">
        {TABS.map(([id, label]) => <Button key={id} size="sm" variant={tab === id ? "default" : "outline"} onClick={() => setTab(id)}>{label}</Button>)}
      </div>
      {msg && <Alert tone={msg.tone}>{msg.text}</Alert>}
      {tab === "licenses" && <LicensesTab products={products} customers={customers} sales={sales} licenses={licenses} act={act} />}
      {tab === "products" && <ProductsTab products={products} act={act} />}
      {tab === "customers" && <CustomersTab customers={customers} act={act} />}
      {tab === "sales" && <SalesTab products={products} customers={customers} sales={sales} act={act} />}
      {tab === "revocations" && rev && <RevocationsTab rev={rev} act={act} />}
    </div>
  );
}

type Act = <T>(fn: () => Promise<T>, ok: (r: T) => string) => Promise<void>;

function LicensesTab({ products, customers, sales, licenses, act }: { products: Product[]; customers: Customer[]; sales: Sale[]; licenses: License[]; act: Act }) {
  const [p, setP] = React.useState("");
  const [c, setC] = React.useState("");
  const [sale, setSale] = React.useState("");
  const [shown, setShown] = React.useState<License | null>(null);
  const [search, setSearch] = React.useState("");
  const filtered = licenses.filter((l) => !search || l.readable_key.includes(search.toUpperCase()) || l.customer_name.toLowerCase().includes(search.toLowerCase()));
  return (
    <>
      <Card className="space-y-3">
        <CardTitle>Nouvelle licence</CardTitle>
        <div className="grid gap-3 sm:grid-cols-3">
          <Field label="Produit"><Select value={p} onChange={(e) => setP(e.target.value)}><option value="">—</option>{products.map((x) => <option key={x.id} value={x.id}>{x.name} ({x.kind})</option>)}</Select></Field>
          <Field label="Client"><Select value={c} onChange={(e) => setC(e.target.value)}><option value="">—</option>{customers.map((x) => <option key={x.id} value={x.id}>{x.name}</option>)}</Select></Field>
          <Field label="Vente (optionnelle)"><Select value={sale} onChange={(e) => setSale(e.target.value)}><option value="">—</option>{sales.filter((s) => (!p || s.product_id === p) && (!c || s.customer_id === c)).map((s) => <option key={s.id} value={s.id}>{formatDate(s.created_at)} · {money(s.amount_cents, s.currency)}</option>)}</Select></Field>
        </div>
        <Button disabled={!p || !c} onClick={() => act(async () => { const l = await call<License>("license_create", { productId: p, customerId: c, saleId: sale || null, options: null }); setShown(l); return l; }, (l) => `Licence ${l.readable_key} créée.`)}>Créer et signer</Button>
        {shown && (
          <div className="space-y-2 rounded border p-3">
            <p className="text-sm">Clé lisible : <b className="font-mono text-lg">{shown.readable_key}</b></p>
            <Field label="Jeton à remettre au client (PASETO v4.public)"><Textarea readOnly rows={3} value={shown.token} /></Field>
            <Button size="sm" variant="outline" onClick={() => navigator.clipboard.writeText(shown.token)}>Copier le jeton</Button>
          </div>
        )}
      </Card>
      <Card className="overflow-x-auto p-0">
        <div className="p-3"><Input placeholder="Rechercher (clé lisible ou client)" value={search} onChange={(e) => setSearch(e.target.value)} /></div>
        {filtered.length === 0 ? <Empty>Aucune licence.</Empty> : (
          <table className="w-full text-sm">
            <thead className="bg-muted/50 text-left text-xs text-muted-foreground"><tr><th className="p-3">Clé lisible</th><th>Client</th><th>Produit</th><th>Expire</th><th>Statut</th><th className="pr-3 text-right">Actions</th></tr></thead>
            <tbody>
              {filtered.map((l) => (
                <tr key={l.id} className="border-t">
                  <td className="p-3 font-mono text-xs">{l.readable_key}</td>
                  <td>{l.customer_name}</td>
                  <td>{l.product_name}</td>
                  <td className="text-xs">{l.expires_at ? formatDate(l.expires_at) : "jamais"}</td>
                  <td><Badge tone={l.status === "active" ? "success" : "destructive"}>{l.status}</Badge></td>
                  <td className="space-x-1 whitespace-nowrap pr-3 text-right">
                    <Button size="sm" variant="ghost" onClick={() => navigator.clipboard.writeText(l.token)}>Copier jeton</Button>
                    {l.status === "active" && <Button size="sm" variant="ghost" onClick={() => { const d = Number(prompt("Prolonger de combien de jours ?", "30")); if (d > 0) act(() => call<License>("license_extend", { id: l.id, days: d }), (x) => `Prolongée jusqu'au ${formatDate(x.expires_at)} : remettez le nouveau jeton au client.`); }}>Prolonger</Button>}
                    {l.status === "active" && <Button size="sm" variant="destructive" onClick={() => { const r = prompt("Motif de la révocation ?"); if (r !== null) act(() => call("license_revoke", { id: l.id, reason: r }), () => "Licence révoquée. Publiez la liste (onglet Révocations)."); }}>Révoquer</Button>}
                  </td>
                </tr>
              ))}
            </tbody>
          </table>
        )}
      </Card>
    </>
  );
}

function ProductsTab({ products, act }: { products: Product[]; act: Act }) {
  const [apps, setApps] = React.useState<App[]>([]);
  const [f, setF] = React.useState({ name: "", kind: "perpetual" as LicenseKind, duration: "30", price: "0", currency: "XOF", features: "", app: "" });
  React.useEffect(() => {
    call<App[]>("apps_list").then(setApps).catch(() => undefined);
  }, []);
  return (
    <>
      <Card className="space-y-3">
        <CardTitle>Nouveau produit</CardTitle>
        <div className="grid gap-3 sm:grid-cols-3">
          <Field label="Nom"><Input value={f.name} onChange={(e) => setF({ ...f, name: e.target.value })} /></Field>
          <Field label="Type"><Select value={f.kind} onChange={(e) => setF({ ...f, kind: e.target.value as LicenseKind })}><option value="perpetual">Perpétuelle</option><option value="subscription">Abonnement</option><option value="trial">Essai</option></Select></Field>
          {f.kind !== "perpetual" && <Field label="Durée (jours)"><Input type="number" value={f.duration} onChange={(e) => setF({ ...f, duration: e.target.value })} /></Field>}
          <Field label="Prix"><Input type="number" value={f.price} onChange={(e) => setF({ ...f, price: e.target.value })} /></Field>
          <Field label="Devise"><Input value={f.currency} maxLength={3} onChange={(e) => setF({ ...f, currency: e.target.value.toUpperCase() })} /></Field>
          <Field label="Appli liée"><Select value={f.app} onChange={(e) => setF({ ...f, app: e.target.value })}><option value="">—</option>{apps.map((a) => <option key={a.id} value={a.id}>{a.name}</option>)}</Select></Field>
        </div>
        <Field label="Options (séparées par des virgules)" hint="Ex. export, multi-postes : lues par l'appli cliente dans le jeton."><Input value={f.features} onChange={(e) => setF({ ...f, features: e.target.value })} /></Field>
        <Button disabled={!f.name} onClick={() => act(() => call<Product>("product_create", { product: { app_id: f.app || null, name: f.name, kind: f.kind, duration_days: f.kind === "perpetual" ? null : Number(f.duration), price_cents: Math.round(Number(f.price) * 100), currency: f.currency, features: f.features.split(",").map((x) => x.trim()).filter(Boolean) } }), (p) => `Produit ${p.name} créé.`)}>Créer</Button>
      </Card>
      <Card>{products.length === 0 ? <Empty>Aucun produit.</Empty> : <ul className="divide-y text-sm">{products.map((p) => <li key={p.id} className="flex justify-between py-2"><span>{p.name} <Badge tone="muted">{p.kind}{p.duration_days ? ` · ${p.duration_days} j` : ""}</Badge></span><span>{money(p.price_cents, p.currency)}</span></li>)}</ul>}</Card>
    </>
  );
}

function CustomersTab({ customers, act }: { customers: Customer[]; act: Act }) {
  const [f, setF] = React.useState({ name: "", email: "", phone: "" });
  return (
    <>
      <Card className="space-y-3">
        <CardTitle>Nouveau client</CardTitle>
        <div className="grid gap-3 sm:grid-cols-3">
          <Field label="Nom"><Input value={f.name} onChange={(e) => setF({ ...f, name: e.target.value })} /></Field>
          <Field label="E-mail"><Input type="email" value={f.email} onChange={(e) => setF({ ...f, email: e.target.value })} /></Field>
          <Field label="Téléphone"><Input value={f.phone} onChange={(e) => setF({ ...f, phone: e.target.value })} /></Field>
        </div>
        <Button disabled={!f.name} onClick={() => act(async () => { const c = await call<Customer>("customer_create", { name: f.name, email: f.email, phone: f.phone, notes: "" }); setF({ name: "", email: "", phone: "" }); return c; }, (c) => `Client ${c.name} ajouté.`)}>Ajouter</Button>
      </Card>
      <Card>{customers.length === 0 ? <Empty>Aucun client.</Empty> : <ul className="divide-y text-sm">{customers.map((c) => <li key={c.id} className="py-2">{c.name} <span className="text-xs text-muted-foreground">{c.email} {c.phone}</span></li>)}</ul>}</Card>
    </>
  );
}

function SalesTab({ products, customers, sales, act }: { products: Product[]; customers: Customer[]; sales: Sale[]; act: Act }) {
  const [providers, setProviders] = React.useState<{ id: string; label: string }[]>([]);
  const [f, setF] = React.useState({ product: "", customer: "", provider: "manual", reference: "" });
  React.useEffect(() => {
    call<{ id: string; label: string }[]>("payment_providers").then(setProviders).catch(() => undefined);
  }, []);
  const name = (list: { id: string; name: string }[], id: string) => list.find((x) => x.id === id)?.name ?? id;
  return (
    <>
      <Card className="space-y-3">
        <CardTitle>Enregistrer une vente</CardTitle>
        <div className="grid gap-3 sm:grid-cols-2">
          <Field label="Produit"><Select value={f.product} onChange={(e) => setF({ ...f, product: e.target.value })}><option value="">—</option>{products.map((p) => <option key={p.id} value={p.id}>{p.name} · {money(p.price_cents, p.currency)}</option>)}</Select></Field>
          <Field label="Client"><Select value={f.customer} onChange={(e) => setF({ ...f, customer: e.target.value })}><option value="">—</option>{customers.map((c) => <option key={c.id} value={c.id}>{c.name}</option>)}</Select></Field>
          <Field label="Moyen de paiement"><Select value={f.provider} onChange={(e) => setF({ ...f, provider: e.target.value })}>{providers.map((p) => <option key={p.id} value={p.id}>{p.label}</option>)}</Select></Field>
          <Field label="Référence (ex. n° de transaction)"><Input value={f.reference} onChange={(e) => setF({ ...f, reference: e.target.value })} /></Field>
        </div>
        <Button disabled={!f.product || !f.customer} onClick={() => act(() => call<Sale>("sale_record", { productId: f.product, customerId: f.customer, provider: f.provider, reference: f.reference }), () => "Vente enregistrée.")}>Enregistrer</Button>
      </Card>
      <Card>{sales.length === 0 ? <Empty>Aucune vente.</Empty> : <ul className="divide-y text-sm">{sales.map((s) => <li key={s.id} className="flex justify-between py-2"><span>{formatDate(s.created_at)} · {name(products, s.product_id)} · {name(customers, s.customer_id)}</span><span>{money(s.amount_cents, s.currency)} <Badge tone="muted">{s.provider}</Badge></span></li>)}</ul>}</Card>
    </>
  );
}

function RevocationsTab({ rev, act }: { rev: RevocationInfo; act: Act }) {
  return (
    <Card className="space-y-3">
      <CardTitle actions={rev.repo && <Button onClick={() => act(() => call<number>("revocations_publish"), (n) => `Liste n° ${n} signée et publiée.`)}>Signer et publier la liste</Button>}>Liste de révocation</CardTitle>
      {!rev.repo ? (
        <div className="space-y-2">
          <p className="text-sm text-muted-foreground">Les applis clientes téléchargent une liste signée depuis un dépôt GitHub <b>public</b> (aucune donnée sensible : uniquement des identifiants de licence révoqués, signés).</p>
          <Button onClick={() => act(() => call<string>("revocations_setup_repo", { existing: null, name: "control-center-revocations" }), (r) => `Dépôt ${r} prêt.`)}>Créer le dépôt public des révocations</Button>
        </div>
      ) : (
        <>
          <p className="text-sm">Dépôt <code>{rev.repo}</code> · dernière liste n° {rev.status.last_seq ?? "—"} publiée {formatDate(rev.status.last_published_at)}</p>
          <Field label="URL à configurer dans vos applis (SDK)"><Input readOnly value={rev.list_url ?? ""} /></Field>
        </>
      )}
      <Field label="Clés publiques à embarquer (PASERK)"><Textarea readOnly rows={3} value={rev.public_keys.join("\n")} /></Field>
      <p className="text-xs text-muted-foreground">Intégration : voir docs/developer-guide.md (SDK TypeScript, Rust, Go).</p>
    </Card>
  );
}
