package main

import (
	"fmt"
	"os"

	"github.com/BurntSushi/toml"
	"weft/internal/config"
)

// Exclusive creation avoids overwriting an existing configuration or following a symlink.
func exportFile(path string, cfg *config.File) error {
	file, err := os.OpenFile(path, os.O_WRONLY|os.O_CREATE|os.O_EXCL, 0600)
	if err != nil {
		return fmt.Errorf("export client config: %w", err)
	}
	complete := false
	defer func() {
		file.Close()
		if !complete {
			os.Remove(path)
		}
	}()
	if err = toml.NewEncoder(file).Encode(cfg); err != nil {
		return err
	}
	if err = file.Sync(); err != nil {
		return err
	}
	if err = file.Close(); err != nil {
		return err
	}
	complete = true
	return nil
}
