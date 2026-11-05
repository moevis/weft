package config

import (
	"os"
	"path/filepath"
	"testing"
)

func TestExportDoesNotSharePublisherIdentity(t *testing.T) {
	for _, mode := range []string{"shared", "public"} {
		t.Run(mode, func(t *testing.T) {
			publisher := &Channel{Endpoint: "localhost:8443:/phone", Mode: mode}
			client, err := publisher.ClientConfig()
			if err != nil {
				t.Fatal(err)
			}
			if client.PrivateKey == publisher.PrivateKey {
				t.Fatal("export contains publisher private key")
			}
			if client.ServerPublicKey != publisher.PublicKey {
				t.Fatal("client must pin publisher")
			}
			if len(client.Publish) != 0 {
				t.Fatal("local targets exported")
			}
			if mode == "public" {
				if client.Secret != "" || len(publisher.AllowedClients) != 1 || publisher.AllowedClients[0] != client.PublicKey {
					t.Fatal("client public identity not authorized")
				}
			} else if client.Secret != publisher.Secret || client.Secret == "" {
				t.Fatal("shared credential not exported")
			}
		})
	}
}
func TestSavedIdentitySurvivesRestart(t *testing.T) {
	path := filepath.Join(t.TempDir(), "weft.toml")
	c := &Channel{Endpoint: "localhost:/phone"}
	if _, err := c.EnsurePublisher(); err != nil {
		t.Fatal(err)
	}
	private, secret := c.PrivateKey, c.Secret
	if err := Save(path, &File{Channels: map[string]*Channel{"phone": c}}); err != nil {
		t.Fatal(err)
	}
	loaded, err := Load(path)
	if err != nil {
		t.Fatal(err)
	}
	changed, err := loaded.Channels["phone"].EnsurePublisher()
	if err != nil {
		t.Fatal(err)
	}
	if changed || loaded.Channels["phone"].PrivateKey != private || loaded.Channels["phone"].Secret != secret {
		t.Fatal("identity changed on reload")
	}
	info, err := os.Stat(path)
	if err != nil {
		t.Fatal(err)
	}
	if info.Mode().Perm() != 0600 {
		t.Fatal("unsafe credential permissions")
	}
}
func TestCorruptIdentityNotReplaced(t *testing.T) {
	c := &Channel{PrivateKey: "broken", PublicKey: "broken"}
	if _, err := c.EnsurePublisher(); err == nil {
		t.Fatal("accepted corrupt identity")
	}
	if c.PrivateKey != "broken" {
		t.Fatal("silently replaced key")
	}
}
func TestEndpointRejectsSecrets(t *testing.T) {
	if _, _, err := Endpoint("relay.example:/phone?secret=hidden"); err == nil {
		t.Fatal("URL credential accepted")
	}
	address, channel, err := Endpoint("relay.example:/phone")
	if err != nil || address != "relay.example:8443" || channel != "phone" {
		t.Fatalf("endpoint: %s %s %v", address, channel, err)
	}
}
