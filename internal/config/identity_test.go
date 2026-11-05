package config

import "testing"

func TestMismatchedPublicKeyRejected(t *testing.T) {
	first := &Channel{}
	second := &Channel{}
	if _, err := first.EnsureIdentity(); err != nil {
		t.Fatal(err)
	}
	if _, err := second.EnsureIdentity(); err != nil {
		t.Fatal(err)
	}
	first.PublicKey = second.PublicKey
	if _, err := first.Credentials(); err == nil {
		t.Fatal("accepted unrelated public key")
	}
}
