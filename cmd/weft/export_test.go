package main

import (
	"os"
	"path/filepath"
	"testing"

	"weft/internal/config"
)

func TestExportFilePrivateAndNoOverwrite(t *testing.T) {
	path := filepath.Join(t.TempDir(), "client.toml")
	cfg := &config.File{Channels: map[string]*config.Channel{"phone": {Endpoint: "localhost:/phone"}}}
	if err := exportFile(path, cfg); err != nil {
		t.Fatal(err)
	}
	info, err := os.Stat(path)
	if err != nil {
		t.Fatal(err)
	}
	if info.Mode().Perm() != 0600 {
		t.Fatalf("permissions: %o", info.Mode().Perm())
	}
	before, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	if err = exportFile(path, &config.File{}); err == nil {
		t.Fatal("overwrote existing config")
	}
	after, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	if string(before) != string(after) {
		t.Fatal("existing file changed")
	}
}
