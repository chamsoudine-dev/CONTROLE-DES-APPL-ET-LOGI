# @control-center/license

Vérification **hors ligne** des licences émises par Control Center.

```ts
import { LicenseChecker, LicenseVerifier } from "@control-center/license";

const checker = new LicenseChecker(new LicenseVerifier(["k4.public.…"]), {
  revocationUrl: "https://raw.githubusercontent.com/<owner>/control-center-revocations/HEAD/revocations.paseto",
  graceDays: 14,
  store: { get: (k) => localStorage.getItem(k), set: (k, v) => localStorage.setItem(k, v) },
});
await checker.restore();
await checker.refresh();            // échec réseau toléré dans la limite du délai de grâce
const { claims } = await checker.check(userToken);  // lève LicenseError(code) sinon
```

Codes d'erreur : `malformed`, `unsupported_header`, `unknown_key`, `bad_signature`, `wrong_type`,
`not_yet_valid`, `expired`, `revoked`, `rollback`, `grace_expired`, `invalid_key`.

Dépendances : `@noble/ed25519`, `@noble/hashes` (audités). Seul l'encodage PASETO (PAE) est implémenté ici.
