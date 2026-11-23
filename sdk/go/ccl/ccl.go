// Package ccl vérifie hors ligne les licences Control Center (PASETO v4.public / Ed25519)
// et applique la liste de révocation signée avec un délai de grâce.
//
// Primitives : crypto/ed25519 (bibliothèque standard) et golang.org/x/crypto/blake2b.
// Seul l'encodage PASETO (PAE) est implémenté ici.
package ccl

import (
	"crypto/ed25519"
	"encoding/base64"
	"encoding/binary"
	"encoding/json"
	"errors"
	"strings"
	"sync"
	"time"

	"golang.org/x/crypto/blake2b"
)

// Issuer est l'émetteur attendu dans chaque jeton.
const Issuer = "control-center"

const (
	header        = "v4.public."
	typLicense    = "cc.license.v1"
	typRevocation = "cc.revocations.v1"
)

// Erreurs (comparables avec errors.Is).
var (
	ErrMalformed         = errors.New("malformed")
	ErrUnsupportedHeader = errors.New("unsupported_header")
	ErrUnknownKey        = errors.New("unknown_key")
	ErrBadSignature      = errors.New("bad_signature")
	ErrWrongType         = errors.New("wrong_type")
	ErrNotYetValid       = errors.New("not_yet_valid")
	ErrExpired           = errors.New("expired")
	ErrRevoked           = errors.New("revoked")
	ErrRollback          = errors.New("rollback")
	ErrGraceExpired      = errors.New("grace_expired")
	ErrInvalidKey        = errors.New("invalid_key")
)

var b64 = base64.RawURLEncoding

// PublicKey est une clé de vérification et son identifiant PASERK k4.pid.
type PublicKey struct {
	Key ed25519.PublicKey
	Kid string
}

// ImportPublicKey importe une clé "k4.public.…".
func ImportPublicKey(paserk string) (PublicKey, error) {
	p := strings.TrimSpace(paserk)
	if !strings.HasPrefix(p, "k4.public.") {
		return PublicKey{}, ErrInvalidKey
	}
	raw, err := b64.DecodeString(strings.TrimPrefix(p, "k4.public."))
	if err != nil || len(raw) != ed25519.PublicKeySize {
		return PublicKey{}, ErrInvalidKey
	}
	h, _ := blake2b.New(33, nil)
	h.Write([]byte("k4.pid." + p))
	return PublicKey{Key: ed25519.PublicKey(raw), Kid: "k4.pid." + b64.EncodeToString(h.Sum(nil))}, nil
}

func le64(n int) []byte {
	b := make([]byte, 8)
	binary.LittleEndian.PutUint64(b, uint64(n)&0x7fffffffffffffff)
	return b
}

// PAE : Pre-Authentication Encoding (spécification PASETO).
func PAE(pieces ...[]byte) []byte {
	out := le64(len(pieces))
	for _, p := range pieces {
		out = append(out, le64(len(p))...)
		out = append(out, p...)
	}
	return out
}

// Claims décrit une licence.
type Claims struct {
	ID           string
	ProductID    string
	ProductName  string
	CustomerID   string
	CustomerName string
	Kind         string
	IssuedAt     time.Time
	NotBefore    *time.Time
	ExpiresAt    *time.Time
	Features     []string
	Options      map[string]any
}

// RevocationList est une liste de révocation vérifiée.
type RevocationList struct {
	Seq      uint64
	IssuedAt time.Time
	Revoked  map[string]struct{}
}

// Verifier vérifie jetons et listes avec une ou plusieurs clés (rotation).
type Verifier struct{ keys map[string]PublicKey }

// NewVerifier construit un vérificateur à partir de clés PASERK.
func NewVerifier(paserks ...string) (*Verifier, error) {
	v := &Verifier{keys: map[string]PublicKey{}}
	for _, p := range paserks {
		k, err := ImportPublicKey(p)
		if err != nil {
			return nil, err
		}
		v.keys[k.Kid] = k
	}
	return v, nil
}

func (v *Verifier) verifyRaw(token, typ string, maxLen int) (map[string]any, error) {
	if len(token) > maxLen {
		return nil, ErrMalformed
	}
	if !strings.HasPrefix(token, header) {
		return nil, ErrUnsupportedHeader
	}
	parts := strings.Split(token, ".")
	if len(parts) != 4 {
		return nil, ErrUnknownKey
	}
	body, err := b64.DecodeString(parts[2])
	if err != nil || len(body) < ed25519.SignatureSize {
		return nil, ErrMalformed
	}
	footer, err := b64.DecodeString(parts[3])
	if err != nil {
		return nil, ErrMalformed
	}
	var f struct {
		Kid string `json:"kid"`
	}
	if json.Unmarshal(footer, &f) != nil {
		return nil, ErrUnknownKey
	}
	key, ok := v.keys[f.Kid]
	if !ok {
		return nil, ErrUnknownKey
	}
	m, sig := body[:len(body)-64], body[len(body)-64:]
	if !ed25519.Verify(key.Key, PAE([]byte(header), m, footer, nil), sig) {
		return nil, ErrBadSignature
	}
	var c map[string]any
	if json.Unmarshal(m, &c) != nil {
		return nil, ErrMalformed
	}
	if c["iss"] != Issuer || c["typ"] != typ {
		return nil, ErrWrongType
	}
	return c, nil
}

func str(c map[string]any, k string) (string, error) {
	s, ok := c[k].(string)
	if !ok {
		return "", ErrMalformed
	}
	return s, nil
}

func optTime(c map[string]any, k string) (*time.Time, error) {
	v, ok := c[k]
	if !ok || v == nil {
		return nil, nil
	}
	s, ok := v.(string)
	if !ok {
		return nil, ErrMalformed
	}
	t, err := time.Parse(time.RFC3339, s)
	if err != nil {
		return nil, ErrMalformed
	}
	return &t, nil
}

// Verify vérifie une licence à l'instant now.
func (v *Verifier) Verify(token string, now time.Time) (*Claims, error) {
	c, err := v.verifyRaw(token, typLicense, 16*1024)
	if err != nil {
		return nil, err
	}
	out := &Claims{Options: map[string]any{}}
	for k, dst := range map[string]*string{"jti": &out.ID, "aud": &out.ProductID, "pname": &out.ProductName, "sub": &out.CustomerID, "cname": &out.CustomerName, "kind": &out.Kind} {
		if *dst, err = str(c, k); err != nil {
			return nil, err
		}
	}
	iat, err := optTime(c, "iat")
	if err != nil || iat == nil {
		return nil, ErrMalformed
	}
	out.IssuedAt = *iat
	if out.NotBefore, err = optTime(c, "nbf"); err != nil {
		return nil, err
	}
	if out.ExpiresAt, err = optTime(c, "exp"); err != nil {
		return nil, err
	}
	if fs, ok := c["features"].([]any); ok {
		for _, f := range fs {
			if s, ok := f.(string); ok {
				out.Features = append(out.Features, s)
			}
		}
	}
	if o, ok := c["opt"].(map[string]any); ok {
		out.Options = o
	}
	if out.NotBefore != nil && now.Before(*out.NotBefore) {
		return nil, ErrNotYetValid
	}
	if out.ExpiresAt != nil && !now.Before(*out.ExpiresAt) {
		return nil, ErrExpired
	}
	return out, nil
}

// VerifyRevocationList vérifie une liste de révocation signée.
func (v *Verifier) VerifyRevocationList(token string) (*RevocationList, error) {
	c, err := v.verifyRaw(token, typRevocation, 4*1024*1024)
	if err != nil {
		return nil, err
	}
	seq, ok := c["seq"].(float64)
	if !ok || seq < 0 || seq != float64(uint64(seq)) {
		return nil, ErrMalformed
	}
	iat, _ := optTime(c, "iat")
	l := &RevocationList{Seq: uint64(seq), Revoked: map[string]struct{}{}}
	if iat != nil {
		l.IssuedAt = *iat
	}
	arr, ok := c["revoked"].([]any)
	if !ok {
		return nil, ErrMalformed
	}
	for _, x := range arr {
		s, ok := x.(string)
		if !ok {
			return nil, ErrMalformed
		}
		l.Revoked[s] = struct{}{}
	}
	return l, nil
}

// Checker applique révocation et délai de grâce hors ligne.
type Checker struct {
	mu        sync.Mutex
	v         *Verifier
	grace     time.Duration
	list      *RevocationList
	fetchedAt time.Time
}

// NewChecker crée un vérificateur complet (graceDays : 14 recommandé).
func NewChecker(v *Verifier, graceDays int) *Checker {
	return &Checker{v: v, grace: time.Duration(graceDays) * 24 * time.Hour}
}

// UpdateRevocations intègre une liste fraîchement téléchargée (anti-rollback).
func (c *Checker) UpdateRevocations(token string, now time.Time) (uint64, error) {
	l, err := c.v.VerifyRevocationList(token)
	if err != nil {
		return 0, err
	}
	c.mu.Lock()
	defer c.mu.Unlock()
	if c.list != nil && l.Seq < c.list.Seq {
		return 0, ErrRollback
	}
	c.list, c.fetchedAt = l, now
	return l.Seq, nil
}

// Check vérifie la licence : signature, dates, révocation, délai de grâce.
func (c *Checker) Check(token string, now time.Time) (*Claims, error) {
	cl, err := c.v.Verify(token, now)
	if err != nil {
		return nil, err
	}
	c.mu.Lock()
	defer c.mu.Unlock()
	ref := cl.IssuedAt
	if c.list != nil {
		if _, revoked := c.list.Revoked[cl.ID]; revoked {
			return nil, ErrRevoked
		}
		ref = c.fetchedAt
	}
	if now.After(ref.Add(c.grace)) {
		return nil, ErrGraceExpired
	}
	return cl, nil
}
