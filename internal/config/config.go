package config

import (
	"bytes"
	"crypto/ecdh"
	"crypto/rand"
	"encoding/base64"
	"errors"
	"fmt"
	"net"
	"os"
	"path/filepath"
	"strings"

	"github.com/BurntSushi/toml"
	"weft/internal/tunnel"
)

type File struct {
	Channels map[string]*Channel `toml:"channels"`
}
type Channel struct {
	Endpoint        string            `toml:"endpoint"`
	PrivateKey      string            `toml:"private_key,omitempty"`
	PublicKey       string            `toml:"public_key,omitempty"`
	ServerPublicKey string            `toml:"server_public_key,omitempty"`
	Secret          string            `toml:"secret,omitempty"`
	Mode            string            `toml:"mode,omitempty"`
	AllowedClients  []string          `toml:"allowed_clients,omitempty"`
	Publish         map[string]string `toml:"publish,omitempty"`
}

func DefaultPath() (string, error) {
	home, err := os.UserHomeDir()
	if err != nil {
		return "", err
	}
	return filepath.Join(home, ".weft.toml"), nil
}
func Load(path string) (*File, error) {
	f := &File{Channels: make(map[string]*Channel)}
	info, err := os.Stat(path)
	if errors.Is(err, os.ErrNotExist) {
		return f, nil
	}
	if err != nil {
		return nil, err
	}
	if info.Mode().Perm()&0077 != 0 {
		return nil, fmt.Errorf("config %s contains credentials: run chmod 600 %s", path, path)
	}
	if _, err = toml.DecodeFile(path, f); err != nil {
		return nil, fmt.Errorf("read config: %w", err)
	}
	if f.Channels == nil {
		f.Channels = make(map[string]*Channel)
	}
	return f, nil
}
func Save(path string, f *File) error {
	dir := filepath.Dir(path)
	if err := os.MkdirAll(dir, 0700); err != nil {
		return err
	}
	tmp, err := os.CreateTemp(dir, ".weft-*")
	if err != nil {
		return err
	}
	defer os.Remove(tmp.Name())
	defer tmp.Close()
	if err = tmp.Chmod(0600); err != nil {
		return err
	}
	if err = toml.NewEncoder(tmp).Encode(f); err != nil {
		return err
	}
	if err = tmp.Sync(); err != nil {
		return err
	}
	if err = tmp.Close(); err != nil {
		return err
	}
	return os.Rename(tmp.Name(), path)
}
func EncodeKey(b []byte) string { return base64.StdEncoding.EncodeToString(b) }
func DecodeKey(s string) ([]byte, error) {
	b, err := base64.StdEncoding.DecodeString(s)
	if err != nil || len(b) != 32 {
		return nil, errors.New("key must be 32 bytes encoded as base64")
	}
	return b, nil
}
func (c *Channel) EnsureIdentity() (bool, error) {
	if c.PrivateKey != "" {
		_, err := c.Credentials()
		return false, err
	}
	if c.PublicKey != "" {
		return false, errors.New("public key exists without private key; refusing to replace identity")
	}
	id, err := tunnel.GenerateIdentity()
	if err != nil {
		return false, err
	}
	c.PrivateKey = EncodeKey(id.PrivateKey)
	c.PublicKey = EncodeKey(id.PublicKey)
	return true, nil
}
func (c *Channel) EnsurePublisher() (bool, error) {
	changed, err := c.EnsureIdentity()
	if err != nil {
		return false, err
	}
	if c.Mode == "" {
		c.Mode = "shared"
		changed = true
	}
	if c.Mode != "shared" && c.Mode != "public" {
		return false, errors.New("mode must be shared or public")
	}
	if c.Mode == "public" && c.Secret != "" {
		return false, errors.New("public mode must not contain a shared secret")
	}
	if c.Mode == "shared" && c.Secret == "" {
		b := make([]byte, 32)
		if _, err = rand.Read(b); err != nil {
			return false, err
		}
		c.Secret = EncodeKey(b)
		changed = true
	}
	_, err = c.Credentials()
	return changed, err
}
func (c *Channel) Credentials() (tunnel.Credentials, error) {
	var result tunnel.Credentials
	var err error
	if c.PrivateKey != "" {
		result.Identity.PrivateKey, err = DecodeKey(c.PrivateKey)
		if err != nil {
			return result, fmt.Errorf("private key: %w", err)
		}
		result.Identity.PublicKey, err = DecodeKey(c.PublicKey)
		if err != nil {
			return result, fmt.Errorf("public key: %w", err)
		}
	}
	if len(result.Identity.PrivateKey) > 0 {
		key, e := ecdh.X25519().NewPrivateKey(result.Identity.PrivateKey)
		if e != nil {
			return result, e
		}
		if !bytes.Equal(key.PublicKey().Bytes(), result.Identity.PublicKey) {
			return result, errors.New("public key does not match private key")
		}
	}
	if c.Secret != "" {
		result.Secret, err = DecodeKey(c.Secret)
		if err != nil {
			return result, fmt.Errorf("secret: %w", err)
		}
	}
	if c.ServerPublicKey != "" {
		result.PeerPublicKey, err = DecodeKey(c.ServerPublicKey)
		if err != nil {
			return result, fmt.Errorf("server public key: %w", err)
		}
	}
	for _, s := range c.AllowedClients {
		b, e := DecodeKey(s)
		if e != nil {
			return result, fmt.Errorf("allowed client: %w", e)
		}
		result.AllowedClients = append(result.AllowedClients, b)
	}
	return result, nil
}
func (c *Channel) ClientConfig() (*Channel, error) {
	if _, err := c.EnsurePublisher(); err != nil {
		return nil, err
	}
	id, err := tunnel.GenerateIdentity()
	if err != nil {
		return nil, err
	}
	client := &Channel{Endpoint: c.Endpoint, Mode: c.Mode, Secret: c.Secret, ServerPublicKey: c.PublicKey, PrivateKey: EncodeKey(id.PrivateKey), PublicKey: EncodeKey(id.PublicKey)}
	if c.Mode == "public" {
		c.AllowedClients = append(c.AllowedClients, client.PublicKey)
	}
	return client, nil
}
func Endpoint(s string) (address, channel string, err error) {
	host, id, ok := strings.Cut(s, ":/")
	if !ok || host == "" || id == "" || strings.ContainsAny(id, "/?#\\\r\n") {
		return "", "", errors.New("endpoint must be host[:port]:/channel (no secrets in URL)")
	}
	if strings.ContainsAny(host, "/?#@ \t\r\n") {
		return "", "", errors.New("invalid relay address")
	}
	if _, _, e := net.SplitHostPort(host); e != nil {
		if strings.Contains(host, ":") {
			return "", "", errors.New("relay address must be host:port or host")
		}
		host = net.JoinHostPort(host, "8443")
	}
	return host, id, nil
}
func Target(s string) (string, error) {
	if s == "" {
		return "", errors.New("empty target")
	}
	if !strings.Contains(s, ":") {
		s = net.JoinHostPort("127.0.0.1", s)
	}
	host, port, err := net.SplitHostPort(s)
	if err != nil || port == "" {
		return "", errors.New("address must be host:port or port")
	}
	if host == "" {
		host = "127.0.0.1"
	}
	return net.JoinHostPort(host, port), nil
}
