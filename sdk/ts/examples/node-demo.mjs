// Exemple d'intégration en quelques lignes (applis Node/Electron/Web).
// Usage : node examples/node-demo.mjs  (utilise les jeux de test ; remplacez par vos valeurs)
import { readFileSync } from "node:fs";
import { LicenseChecker, LicenseVerifier, LicenseError } from "../dist/index.js";

const fx = JSON.parse(readFileSync(new URL("../../fixtures.json", import.meta.url), "utf8"));

// 1. Clé(s) publique(s) affichées dans Control Center → Licences → Révocations.
const verifier = new LicenseVerifier(fx.public_keys);
// 2. Vérificateur avec liste de révocation (URL du dépôt public) et 14 jours de grâce hors ligne.
const checker = new LicenseChecker(verifier, {
  graceDays: 14,
  fetch: async () => new Response(fx.revocation_list_seq1), // en production : fetch réel
  revocationUrl: "https://raw.githubusercontent.com/<owner>/control-center-revocations/HEAD/revocations.paseto",
});
await checker.refresh(new Date(fx.t_valid));

// 3. Vérification de la licence saisie par l'utilisateur.
try {
  const r = await checker.check(fx.valid, new Date(fx.t_valid));
  console.log(`Licence valide : ${r.claims.productName} pour ${r.claims.customerName}, options ${r.claims.features.join(", ")}`);
} catch (e) {
  if (e instanceof LicenseError) console.error(`Licence refusée (${e.code})`);
  else throw e;
  process.exit(1);
}
