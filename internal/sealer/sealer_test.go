package sealer

import (
	"bytes"
	"encoding/base64"
	"errors"
	"strings"
	"testing"

	"idp-mcp-bridge/internal/grants"
)

func key(b byte) string { return base64.StdEncoding.EncodeToString(bytes.Repeat([]byte{b}, 32)) }

var owner = grants.Key{Tenant: "acme", Member: "bob", Connection: "notes"}

func TestASealedValueOpensForItsOwnerAndNamesItsKeyAndDoesNotRepeat(t *testing.T) {
	k, err := Parse([]byte("# the current key first\nk2:" + key(2) + "\n\nk1:" + key(1) + "\n"))
	if err != nil || k.Current() != "k2" {
		t.Fatalf("%v", err)
	}
	a, _ := k.Seal([]byte("secret token"), owner)
	b, _ := k.Seal([]byte("secret token"), owner)
	if id, _ := KeyID(a); id != "k2" || bytes.Equal(a, b) || bytes.Contains(a, []byte("secret")) {
		t.Fatal("not sealed as it should be")
	}
	if pt, err := k.Open(a, owner); err != nil || string(pt) != "secret token" {
		t.Fatalf("%q %v", pt, err)
	}
	// an older key still opens what it sealed
	old, _ := Parse([]byte("k1:" + key(1)))
	o, _ := old.Seal([]byte("older"), owner)
	if pt, err := k.Open(o, owner); err != nil || string(pt) != "older" {
		t.Fatalf("%q %v", pt, err)
	}
}

// the plan's table: a sealed row copied to another member or connection does not open
func TestASealedValueDoesNotOpenForAnotherMemberTenantConnectionOrAnEditedKeyID(t *testing.T) {
	k, _ := Parse([]byte("k1:" + key(1) + "\nk2:" + key(1)))
	sealed, _ := k.Seal([]byte("x"), owner)
	for name, o := range map[string]grants.Key{
		"another member":     {Tenant: "acme", Member: "alice", Connection: "notes"},
		"another tenant":     {Tenant: "other", Member: "bob", Connection: "notes"},
		"another connection": {Tenant: "acme", Member: "bob", Connection: "crm"},
		"fields shifted":     {Tenant: "acmeb", Member: "ob", Connection: "notes"},
	} {
		if _, err := k.Open(sealed, o); !errors.Is(err, ErrOpen) {
			t.Errorf("%s: %v", name, err)
		}
	}
	// the same key bytes under another id: the id is part of what is authenticated
	edited := append([]byte(nil), sealed...)
	edited[3] = '2' // "k1" -> "k2"
	if _, err := k.Open(edited, owner); !errors.Is(err, ErrOpen) {
		t.Errorf("an edited key id: %v", err)
	}
	flipped := append([]byte(nil), sealed...)
	flipped[len(flipped)-1] ^= 1
	if _, err := k.Open(flipped, owner); !errors.Is(err, ErrOpen) {
		t.Errorf("an edited ciphertext: %v", err)
	}
	for _, junk := range [][]byte{nil, {1}, {2, 2, 'k'}, {1, 2, 'k', '1'}, bytes.Repeat([]byte{1}, 40)} {
		if _, err := k.Open(junk, owner); err == nil {
			t.Errorf("%v opened", junk)
		}
	}
	other, _ := Parse([]byte("k9:" + key(9)))
	if _, err := other.Open(sealed, owner); !errors.Is(err, ErrUnknownKey) {
		t.Errorf("%v", err)
	}
}

func TestTheKeyFileIsValidatedStrictly(t *testing.T) {
	for name, f := range map[string]string{
		"empty":           "",
		"only comments":   "# nothing\n",
		"no id":           key(1),
		"a key too short": "k1:" + base64.StdEncoding.EncodeToString([]byte("short")),
		"not base64":      "k1:!!!",
		"a bad id":        "k 1:" + key(1),
		"an id too long":  strings.Repeat("a", 33) + ":" + key(1),
		"a duplicate id":  "k1:" + key(1) + "\nk1:" + key(2),
		"a 16 byte key":   "k1:" + base64.StdEncoding.EncodeToString(bytes.Repeat([]byte{1}, 16)),
	} {
		if _, err := Parse([]byte(f)); err == nil {
			t.Errorf("%s: accepted", name)
		}
	}
	if _, err := Load(""); err == nil {
		t.Error("no path")
	}
}
