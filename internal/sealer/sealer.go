// Package sealer encrypts the members' tokens and the other secrets the bridge keeps in its database (ADR-0001 D24).
// AES-256-GCM, one key per deployment from a Secret, several while one is rotated: the first key of the file seals, every
// key opens. A sealed value names the key it was sealed with, so a rotation needs no flag day: new rows and every refresh
// use the current key, old rows still open, and `idp-mcp-bridge reseal` rewrites the rest.
//
// The additional data of every seal is the owner of the value (tenant, member, connection) and the key id, so a sealed value
// copied to another member's row, or to another connection's, does not open, and neither does one whose key id was edited.
package sealer

import (
	"crypto/aes"
	"crypto/cipher"
	"crypto/rand"
	"encoding/base64"
	"errors"
	"fmt"
	"os"
	"regexp"
	"strings"

	"idp-mcp-bridge/internal/grants"
)

// ErrOpen: the value does not open. The reason is deliberately not told apart (wrong key, edited value, another owner).
var ErrOpen = errors.New("the sealed value does not open")

// ErrUnknownKey: the value was sealed with a key this file does not hold.
var ErrUnknownKey = errors.New("the sealed value names a key that is not in the key file")

const (
	version = 1
	keyLen  = 32
)

var idRE = regexp.MustCompile(`^[A-Za-z0-9_-]{1,32}$`)

// Keys is the key file: the current key and the older ones.
type Keys struct {
	current string
	aead    map[string]cipher.AEAD
}

// Parse reads a key file: one key a line, `<id>:<base64 of 32 bytes>`; the first line is the current key, the others only
// open. Blank lines and lines beginning with # are skipped. Ids are unique, [A-Za-z0-9_-] and at most 32 characters.
func Parse(data []byte) (*Keys, error) {
	k := &Keys{aead: map[string]cipher.AEAD{}}
	for i, line := range strings.Split(string(data), "\n") {
		line = strings.TrimSpace(line)
		if line == "" || strings.HasPrefix(line, "#") {
			continue
		}
		id, enc, ok := strings.Cut(line, ":")
		if !ok || !idRE.MatchString(id) {
			return nil, fmt.Errorf("line %d: want <key id>:<base64 key>, the id of letters, digits, _ and -, at most 32 characters", i+1)
		}
		raw, err := base64.StdEncoding.DecodeString(enc)
		if err != nil || len(raw) != keyLen {
			return nil, fmt.Errorf("line %d: the key must be %d bytes in standard base64 (openssl rand -base64 32)", i+1, keyLen)
		}
		if _, dup := k.aead[id]; dup {
			return nil, fmt.Errorf("line %d: key id %q is listed twice", i+1, id)
		}
		blk, err := aes.NewCipher(raw)
		if err != nil {
			return nil, err
		}
		g, err := cipher.NewGCM(blk)
		if err != nil {
			return nil, err
		}
		k.aead[id] = g
		if k.current == "" {
			k.current = id
		}
	}
	if k.current == "" {
		return nil, errors.New("no key in the file")
	}
	return k, nil
}

// Load reads the key file.
func Load(path string) (*Keys, error) {
	if path == "" {
		return nil, errors.New("no key file")
	}
	b, err := os.ReadFile(path)
	if err != nil {
		return nil, err
	}
	return Parse(b)
}

// Current is the id of the key that seals.
func (k *Keys) Current() string { return k.current }

// aad binds a ciphertext to its owner and its key: length-prefixed so that ("ab","c") and ("a","bc") differ.
func aad(o grants.Key, keyID string) []byte {
	var b []byte
	kind := "member"
	if o.Reviewer {
		kind = "reviewer" // a reviewer grant never opens as a member's, nor the other way round (ADR-0001 D33)
	}
	for _, s := range []string{"idp-mcp-bridge/v1", o.Tenant, o.Member, o.Connection, kind, keyID} {
		b = append(b, byte(len(s)>>8), byte(len(s)))
		b = append(b, s...)
	}
	return b
}

// Seal encrypts plaintext for owner with the current key. The result is version, key id length, key id, nonce, ciphertext.
func (k *Keys) Seal(plaintext []byte, owner grants.Key) ([]byte, error) {
	g := k.aead[k.current]
	nonce := make([]byte, g.NonceSize())
	if _, err := rand.Read(nonce); err != nil {
		return nil, err
	}
	out := []byte{version, byte(len(k.current))}
	out = append(out, k.current...)
	out = append(out, nonce...)
	return g.Seal(out, nonce, plaintext, aad(owner, k.current)), nil
}

// KeyID is the id of the key a sealed value names, without opening it.
func KeyID(sealed []byte) (string, error) {
	if len(sealed) < 2 || sealed[0] != version || len(sealed) < 2+int(sealed[1]) {
		return "", ErrOpen
	}
	return string(sealed[2 : 2+int(sealed[1])]), nil
}

// Open decrypts a sealed value of owner.
func (k *Keys) Open(sealed []byte, owner grants.Key) ([]byte, error) {
	id, err := KeyID(sealed)
	if err != nil {
		return nil, err
	}
	g, ok := k.aead[id]
	if !ok {
		return nil, ErrUnknownKey
	}
	rest := sealed[2+len(id):]
	if len(rest) < g.NonceSize()+g.Overhead() {
		return nil, ErrOpen
	}
	pt, err := g.Open(nil, rest[:g.NonceSize()], rest[g.NonceSize():], aad(owner, id))
	if err != nil {
		return nil, ErrOpen
	}
	return pt, nil
}

var _ grants.Sealer = (*Keys)(nil)
