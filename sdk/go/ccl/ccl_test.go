package ccl

import (
	"encoding/json"
	"errors"
	"os"
	"testing"
	"time"
)

type fixtures struct {
	PublicKeys      []string `json:"public_keys"`
	Kid             string   `json:"kid"`
	LicenseID       string   `json:"license_id"`
	TValid          string   `json:"t_valid"`
	TAfterExpiry    string   `json:"t_after_expiry"`
	TBeforeIssue    string   `json:"t_before_issue"`
	TGraceExceeded  string   `json:"t_grace_exceeded"`
	Valid           string   `json:"valid"`
	Perpetual       string   `json:"perpetual"`
	Tampered        string   `json:"tampered"`
	Forged          string   `json:"forged_other_key"`
	List1           string   `json:"revocation_list_seq1"`
	List2           string   `json:"revocation_list_seq2_revokes_valid"`
	ListForged      string   `json:"revocation_list_forged"`
}

func load(t *testing.T) fixtures {
	raw, err := os.ReadFile("../../fixtures.json")
	if err != nil {
		t.Fatal(err)
	}
	var f fixtures
	if err := json.Unmarshal(raw, &f); err != nil {
		t.Fatal(err)
	}
	return f
}

func at(t *testing.T, s string) time.Time {
	v, err := time.Parse(time.RFC3339, s)
	if err != nil {
		t.Fatal(err)
	}
	return v
}

func TestCompatibility(t *testing.T) {
	f := load(t)
	k, err := ImportPublicKey(f.PublicKeys[0])
	if err != nil || k.Kid != f.Kid {
		t.Fatalf("kid %q != %q (%v)", k.Kid, f.Kid, err)
	}
	v, _ := NewVerifier(f.PublicKeys...)
	c, err := v.Verify(f.Valid, at(t, f.TValid))
	if err != nil || c.ID != f.LicenseID || c.ProductName != "Pro" || len(c.Features) != 2 || c.Options["seats"].(float64) != 3 {
		t.Fatalf("licence valide refusée : %v %+v", err, c)
	}
	if p, err := v.Verify(f.Perpetual, at(t, "2099-01-01T00:00:00Z")); err != nil || p.ExpiresAt != nil {
		t.Fatalf("perpétuelle : %v", err)
	}
	cases := map[string]error{f.Tampered: ErrBadSignature, f.Forged: ErrUnknownKey, "v3.public.x": ErrUnsupportedHeader, f.List1: ErrWrongType}
	for tok, want := range cases {
		if _, err := v.Verify(tok, at(t, f.TValid)); !errors.Is(err, want) {
			t.Fatalf("attendu %v, obtenu %v", want, err)
		}
	}
	if _, err := v.Verify(f.Valid, at(t, f.TAfterExpiry)); !errors.Is(err, ErrExpired) {
		t.Fatal(err)
	}
	if _, err := v.Verify(f.Valid, at(t, f.TBeforeIssue)); !errors.Is(err, ErrNotYetValid) {
		t.Fatal(err)
	}
	for i := 10; i < len(f.Valid); i += 5 {
		b := []byte(f.Valid)
		if b[i] == 'A' {
			b[i] = 'B'
		} else {
			b[i] = 'A'
		}
		if _, err := v.Verify(string(b), at(t, f.TValid)); err == nil {
			t.Fatalf("octet %d modifié accepté", i)
		}
	}
}

func TestRevocationAndGrace(t *testing.T) {
	f := load(t)
	v, _ := NewVerifier(f.PublicKeys...)
	c := NewChecker(v, 14)
	if _, err := c.Check(f.Valid, at(t, f.TValid)); err != nil {
		t.Fatal(err)
	}
	if _, err := c.Check(f.Valid, at(t, f.TGraceExceeded)); !errors.Is(err, ErrGraceExpired) {
		t.Fatal(err)
	}
	if _, err := c.UpdateRevocations(f.List1, at(t, f.TValid)); err != nil {
		t.Fatal(err)
	}
	if _, err := c.UpdateRevocations(f.List2, at(t, f.TValid)); err != nil {
		t.Fatal(err)
	}
	if _, err := c.Check(f.Valid, at(t, f.TValid)); !errors.Is(err, ErrRevoked) {
		t.Fatal(err)
	}
	if _, err := c.UpdateRevocations(f.List1, at(t, f.TValid)); !errors.Is(err, ErrRollback) {
		t.Fatal(err)
	}
	if _, err := c.UpdateRevocations(f.ListForged, at(t, f.TValid)); !errors.Is(err, ErrUnknownKey) {
		t.Fatal(err)
	}
}

func FuzzVerify(f *testing.F) {
	fx := struct{ Valid string `json:"valid"`; Keys []string `json:"public_keys"` }{}
	raw, _ := os.ReadFile("../../fixtures.json")
	_ = json.Unmarshal(raw, &fx)
	f.Add(fx.Valid)
	f.Add("v4.public.")
	v, _ := NewVerifier(fx.Keys...)
	f.Fuzz(func(t *testing.T, s string) {
		_, _ = v.Verify(s, time.Now())
		_, _ = v.VerifyRevocationList(s)
	})
}
