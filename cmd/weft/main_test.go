package main

import (
	"context"
	"path/filepath"
	"strings"
	"testing"

	"weft/internal/config"
)

func TestRejectMixedModes(t *testing.T) {
	path := filepath.Join(t.TempDir(), "weft.toml")
	cfg := &config.File{Channels: map[string]*config.Channel{"phone": {Endpoint: "localhost:8443:/phone"}}}
	if err := config.Save(path, cfg); err != nil {
		t.Fatal(err)
	}
	err := run(context.Background(), []string{"-conf", path, "-channel", "phone", "-list", "-bind", "adb:5555"})
	if err == nil || !strings.Contains(err.Error(), "choose one mode") {
		t.Fatalf("expected conflicting-mode error, got %v", err)
	}
}
func TestClientConfigCannotPublish(t *testing.T) {
	path := filepath.Join(t.TempDir(), "client.toml")
	pub := &config.Channel{Endpoint: "localhost:8443:/phone"}
	client, err := pub.ClientConfig()
	if err != nil {
		t.Fatal(err)
	}
	if err = config.Save(path, &config.File{Channels: map[string]*config.Channel{"phone": client}}); err != nil {
		t.Fatal(err)
	}
	err = run(context.Background(), []string{"-conf", path, "-channel", "phone"})
	if err == nil || !strings.Contains(err.Error(), "client channel") {
		t.Fatalf("expected client mode guidance, got %v", err)
	}
}
