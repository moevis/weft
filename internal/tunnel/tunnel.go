// Package tunnel carries authenticated, encrypted streams through an untrusted hub.
package tunnel

import (
	"context"
	"crypto/ecdh"
	"crypto/subtle"
	"errors"
	"fmt"
	"io"
	"net"
	"sort"
	"time"

	"github.com/flynn/noise"
	"weft/internal/hub"
)

// Identity is a Curve25519 static keypair.
type Identity struct {
	PrivateKey []byte
	PublicKey  []byte
}

// Credentials authenticate both ends. Secret selects XXpsk3 instead of XX.
// Consumers must pin PeerPublicKey. Publishers without a Secret must authorize
// at least one AllowedClients key; a supplied allowlist also applies in PSK mode.
type Credentials struct {
	Identity       Identity
	Secret         []byte
	PeerPublicKey  []byte
	AllowedClients [][]byte
}

func GenerateIdentity() (Identity, error) {
	key, err := noise.DH25519.GenerateKeypair(nil)
	if err != nil {
		return Identity{}, err
	}
	return Identity{PrivateKey: key.Private, PublicKey: key.Public}, nil
}

func validateCredentials(c Credentials, initiator bool) error {
	if len(c.Identity.PrivateKey) != 32 || len(c.Identity.PublicKey) != 32 {
		return errors.New("tunnel: identity requires 32-byte private and public keys")
	}
	key, err := ecdh.X25519().NewPrivateKey(c.Identity.PrivateKey)
	if err != nil || subtle.ConstantTimeCompare(key.PublicKey().Bytes(), c.Identity.PublicKey) != 1 {
		return errors.New("tunnel: identity keypair does not match")
	}
	if len(c.Secret) != 0 && len(c.Secret) != 32 {
		return errors.New("tunnel: secret must be exactly 32 bytes")
	}
	if initiator && len(c.PeerPublicKey) != 32 {
		return errors.New("tunnel: publisher public key pin is required")
	}
	if !initiator && len(c.Secret) == 0 && len(c.AllowedClients) == 0 {
		return errors.New("tunnel: public-key mode requires allowed clients")
	}
	for _, key := range c.AllowedClients {
		if len(key) != 32 {
			return errors.New("tunnel: allowed client keys must be 32 bytes")
		}
	}
	return nil
}

const setupTimeout = 15 * time.Second
const maxServiceName = 4096

// Publish advertises names without opening their targets until a consumer asks.
// Each accepted connection has independent handshake and transport cipher states.
func Publish(ctx context.Context, address, channel string, services map[string]string, credentials Credentials) error {
	if err := validateCredentials(credentials, false); err != nil {
		return err
	}
	targets := make(map[string]string, len(services))
	names := make([]string, 0, len(services))
	for name, target := range services {
		if len(name) == 0 || len(name) > maxServiceName || target == "" {
			return errors.New("tunnel: service names and targets must be nonempty and names at most 4096 bytes")
		}
		targets[name] = target
		names = append(names, name)
	}
	sort.Strings(names)
	return hub.Publish(ctx, address, channel, names, func(raw net.Conn) {
		defer raw.Close()
		stop := context.AfterFunc(ctx, func() { raw.Close() })
		defer stop()
		if err := raw.SetDeadline(time.Now().Add(setupTimeout)); err != nil {
			return
		}
		secure, err := handshake(raw, credentials, false)
		if err != nil {
			return
		}
		request, err := secure.readRecord()
		if err != nil || len(request) < 2 || request[0] != recordRequest || len(request)-1 > maxServiceName {
			return
		}
		target, ok := targets[string(request[1:])]
		if !ok {
			secure.writeRecord(recordResponse, []byte("unknown service"))
			return
		}
		targetCtx, cancel := context.WithTimeout(ctx, setupTimeout)
		conn, err := (&net.Dialer{}).DialContext(targetCtx, "tcp", target)
		cancel()
		if err != nil {
			message := "target connection failed: " + err.Error()
			if len(message) > maxServiceName {
				message = message[:maxServiceName]
			}
			secure.writeRecord(recordResponse, []byte(message))
			return
		}
		defer conn.Close()
		stopTarget := context.AfterFunc(ctx, func() { conn.Close() })
		defer stopTarget()
		if err := secure.writeRecord(recordResponse, nil); err != nil {
			return
		}
		if err := raw.SetDeadline(time.Time{}); err != nil {
			return
		}
		bridge(secure, conn)
	})
}

// Dial authenticates the publisher and waits for an encrypted target-open result.
// Cancellation closes the returned stream as well as any pending setup work.
func Dial(ctx context.Context, address, channel, service string, credentials Credentials) (net.Conn, error) {
	if err := validateCredentials(credentials, true); err != nil {
		return nil, err
	}
	if len(service) == 0 || len(service) > maxServiceName {
		return nil, errors.New("tunnel: service name must be 1 to 4096 bytes")
	}
	raw, err := hub.Open(ctx, address, channel)
	if err != nil {
		return nil, err
	}
	stop := context.AfterFunc(ctx, func() { raw.Close() })
	fail := func(err error) (net.Conn, error) {
		stop()
		raw.Close()
		if ctx.Err() != nil {
			return nil, ctx.Err()
		}
		return nil, err
	}
	deadline := time.Now().Add(setupTimeout)
	if d, ok := ctx.Deadline(); ok && d.Before(deadline) {
		deadline = d
	}
	if err := raw.SetDeadline(deadline); err != nil {
		return fail(err)
	}
	secure, err := handshake(raw, credentials, true)
	if err != nil {
		return fail(fmt.Errorf("tunnel: authenticate publisher: %w", err))
	}
	secure.stop = stop
	if err := secure.writeRecord(recordRequest, []byte(service)); err != nil {
		return fail(err)
	}
	response, err := secure.readRecord()
	if err != nil {
		return fail(fmt.Errorf("tunnel: setup failed; check shared key, client authorization, and publisher availability: %w", err))
	}
	if len(response) == 0 || response[0] != recordResponse {
		return fail(errors.New("tunnel: invalid target response"))
	}
	if len(response) > 1 {
		return fail(fmt.Errorf("tunnel: %s", response[1:]))
	}
	if err := raw.SetDeadline(time.Time{}); err != nil {
		return fail(err)
	}
	if err := ctx.Err(); err != nil {
		return fail(err)
	}
	return secure, nil
}

func handshake(raw net.Conn, c Credentials, initiator bool) (*secureConn, error) {
	config := noise.Config{
		CipherSuite:   noise.NewCipherSuite(noise.DH25519, noise.CipherChaChaPoly, noise.HashSHA256),
		Pattern:       noise.HandshakeXX,
		Initiator:     initiator,
		Prologue:      []byte("weft/tunnel/1"),
		StaticKeypair: noise.DHKey{Private: c.Identity.PrivateKey, Public: c.Identity.PublicKey},
	}
	if len(c.Secret) > 0 {
		config.PresharedKey = c.Secret
		config.PresharedKeyPlacement = 3
	}
	hs, err := noise.NewHandshakeState(config)
	if err != nil {
		return nil, err
	}
	var first, second *noise.CipherState
	for step := range 3 {
		if (step%2 == 0) == initiator {
			var message []byte
			message, first, second, err = hs.WriteMessage(nil, nil)
			if err == nil {
				err = writeFrame(raw, message)
			}
		} else {
			var message []byte
			message, err = readFrame(raw, make([]byte, 128))
			if err == nil {
				var payload []byte
				payload, first, second, err = hs.ReadMessage(nil, message)
				if err == nil && len(payload) != 0 {
					err = errors.New("tunnel: unexpected handshake payload")
				}
			}
			// Check the responder pin before revealing the initiator static key.
			if err == nil && initiator && step == 1 && subtle.ConstantTimeCompare(hs.PeerStatic(), c.PeerPublicKey) != 1 {
				err = errors.New("tunnel: publisher public key does not match pin")
			}
		}
		if err != nil {
			return nil, err
		}
	}
	if !initiator && len(c.AllowedClients) > 0 {
		allowed := 0
		for _, key := range c.AllowedClients {
			allowed |= subtle.ConstantTimeCompare(hs.PeerStatic(), key)
		}
		if allowed != 1 {
			return nil, errors.New("tunnel: client is not authorized")
		}
	}
	// Split returns initiator-to-responder first, regardless of local role.
	if !initiator {
		first, second = second, first
	}
	return newSecureConn(raw, first, second), nil
}

func bridge(secure *secureConn, target net.Conn) {
	done := make(chan struct{})
	go func() {
		_, err := io.Copy(target, secure)
		if err != nil {
			target.Close()
			secure.Close()
		} else if half, ok := target.(interface{ CloseWrite() error }); ok {
			half.CloseWrite()
		} else {
			target.Close()
		}
		close(done)
	}()
	_, err := io.Copy(secure, target)
	if err != nil {
		secure.Close()
		target.Close()
	} else {
		secure.CloseWrite()
	}
	<-done
}
