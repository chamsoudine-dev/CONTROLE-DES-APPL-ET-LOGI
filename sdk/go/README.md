# SDK Go — licences Control Center

```go
import "github.com/chamsoudine-dev/Logiciel-/sdk/go/ccl"

v, _ := ccl.NewVerifier("k4.public.…")
checker := ccl.NewChecker(v, 14)
// Périodiquement : télécharger revocations.paseto depuis le dépôt public puis
checker.UpdateRevocations(listToken, time.Now())
claims, err := checker.Check(userToken, time.Now()) // errors.Is(err, ccl.ErrRevoked)…
```
