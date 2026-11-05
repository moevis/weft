package tunnel

import (
	"bytes"
	"context"
	"encoding/binary"
	"io"
	"net"
	"strings"
	"testing"
	"time"

	"weft/internal/hub"
)

func testCredentials(t *testing.T) (Credentials, Credentials) {
	t.Helper()
	publisher, err := GenerateIdentity()
	if err != nil {
		t.Fatal(err)
	}
	client, err := GenerateIdentity()
	if err != nil {
		t.Fatal(err)
	}
	return Credentials{Identity: publisher, AllowedClients: [][]byte{client.PublicKey}}, Credentials{Identity: client, PeerPublicKey: publisher.PublicKey}
}

type handshakeResult struct {
	conn *secureConn
	err  error
}

func testHandshake(t *testing.T, publisher, consumer Credentials) (*secureConn, *secureConn, error, error) {
	t.Helper()
	left, right := net.Pipe()
	t.Cleanup(func() { left.Close(); right.Close() })
	left.SetDeadline(time.Now().Add(3 * time.Second))
	right.SetDeadline(time.Now().Add(3 * time.Second))
	result := make(chan handshakeResult, 1)
	go func() {
		conn, err := handshake(right, publisher, false)
		if err != nil {
			right.Close()
		}
		result <- handshakeResult{conn, err}
	}()
	client, clientErr := handshake(left, consumer, true)
	if clientErr != nil {
		left.Close()
	}
	server := <-result
	return client, server.conn, clientErr, server.err
}

func TestHandshakeAuthentication(t *testing.T) {
	for _, mode := range []string{"public", "psk"} {
		t.Run(mode, func(t *testing.T) {
			publisher, consumer := testCredentials(t)
			if mode == "psk" {
				publisher.Secret = bytes.Repeat([]byte{1}, 32)
				consumer.Secret = bytes.Repeat([]byte{1}, 32)
				publisher.AllowedClients = nil
			}
			_, _, clientErr, serverErr := testHandshake(t, publisher, consumer)
			if clientErr != nil || serverErr != nil {
				t.Fatalf("handshake: client=%v server=%v", clientErr, serverErr)
			}
		})
	}
	t.Run("wrong publisher pin", func(t *testing.T) {
		publisher, consumer := testCredentials(t)
		consumer.PeerPublicKey = bytes.Repeat([]byte{5}, 32)
		_, _, err, _ := testHandshake(t, publisher, consumer)
		if err == nil || !strings.Contains(err.Error(), "pin") {
			t.Fatalf("expected pin error, got %v", err)
		}
	})
	t.Run("wrong psk", func(t *testing.T) {
		publisher, consumer := testCredentials(t)
		publisher.Secret = bytes.Repeat([]byte{1}, 32)
		consumer.Secret = bytes.Repeat([]byte{2}, 32)
		_, _, clientErr, serverErr := testHandshake(t, publisher, consumer)
		if clientErr == nil && serverErr == nil {
			t.Fatal("different secrets authenticated")
		}
	})
	t.Run("unlisted client", func(t *testing.T) {
		publisher, consumer := testCredentials(t)
		publisher.AllowedClients = [][]byte{bytes.Repeat([]byte{3}, 32)}
		_, _, _, err := testHandshake(t, publisher, consumer)
		if err == nil || !strings.Contains(err.Error(), "authorized") {
			t.Fatalf("expected authorization error, got %v", err)
		}
	})
	t.Run("psk still enforces allowlist", func(t *testing.T) {
		publisher, consumer := testCredentials(t)
		publisher.Secret = bytes.Repeat([]byte{1}, 32)
		consumer.Secret = bytes.Repeat([]byte{1}, 32)
		publisher.AllowedClients = [][]byte{bytes.Repeat([]byte{3}, 32)}
		_, _, _, err := testHandshake(t, publisher, consumer)
		if err == nil {
			t.Fatal("PSK bypassed the configured client allowlist")
		}
	})
}

func TestSecureStreamAndHalfClose(t *testing.T) {
	publisher, consumer := testCredentials(t)
	client, server, clientErr, serverErr := testHandshake(t, publisher, consumer)
	if clientErr != nil || serverErr != nil {
		t.Fatalf("handshake: %v, %v", clientErr, serverErr)
	}
	payload := bytes.Repeat([]byte("independent authenticated stream"), 3000)
	result := make(chan error, 1)
	go func() {
		if _, err := client.Write(payload); err != nil {
			result <- err
			return
		}
		result <- client.CloseWrite()
	}()
	got, err := io.ReadAll(server)
	if err != nil || !bytes.Equal(got, payload) {
		t.Fatalf("stream: length=%d err=%v", len(got), err)
	}
	if err := <-result; err != nil {
		t.Fatal(err)
	}
	go func() {
		_, err := server.Write([]byte("reply after EOF"))
		if err == nil {
			err = server.CloseWrite()
		}
		result <- err
	}()
	got, err = io.ReadAll(client)
	if err != nil || string(got) != "reply after EOF" {
		t.Fatalf("half-close reply: %q, %v", got, err)
	}
	if err := <-result; err != nil {
		t.Fatal(err)
	}
	if _, err := client.Write([]byte("late write")); err != net.ErrClosed {
		t.Fatalf("write after half-close: %v", err)
	}
}

func TestSecureStreamRejectsTamperingAndTruncation(t *testing.T) {
	for _, attack := range []string{"tamper", "truncate"} {
		t.Run(attack, func(t *testing.T) {
			publisher, consumer := testCredentials(t)
			client, server, clientErr, serverErr := testHandshake(t, publisher, consumer)
			if clientErr != nil || serverErr != nil {
				t.Fatalf("handshake: %v, %v", clientErr, serverErr)
			}
			go func() {
				if attack == "tamper" {
					writeFrame(client.Conn, bytes.Repeat([]byte{7}, 32))
				}
				client.Close()
			}()
			var buf [1]byte
			if _, err := server.Read(buf[:]); err == nil || err == io.EOF {
				t.Fatalf("unauthenticated stream termination accepted: %v", err)
			}
		})
	}
}

type shortWriter struct{ bytes.Buffer }

func (w *shortWriter) Write(p []byte) (int, error) {
	return w.Buffer.Write(p[:min(1, len(p))])
}

type shortReader struct{ io.Reader }

func (r shortReader) Read(p []byte) (int, error) {
	return r.Reader.Read(p[:min(1, len(p))])
}

func TestFramesPartialIOAndBounds(t *testing.T) {
	var writer shortWriter
	want := []byte("framed message")
	if err := writeFrame(&writer, want); err != nil {
		t.Fatal(err)
	}
	got, err := readFrame(shortReader{&writer}, make([]byte, maxRecord))
	if err != nil || !bytes.Equal(got, want) {
		t.Fatalf("partial IO: %q %v", got, err)
	}
	var header [2]byte
	binary.BigEndian.PutUint16(header[:], maxRecord+1)
	if _, err := readFrame(bytes.NewReader(header[:]), make([]byte, maxRecord)); err == nil {
		t.Fatal("oversized frame accepted")
	}
}

func TestDialReportsTargetFailureAndKeepsStreamsIndependent(t *testing.T) {
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	listener, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	defer listener.Close()
	go hub.Serve(ctx, listener)
	target, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	defer target.Close()
	go func() {
		for {
			conn, err := target.Accept()
			if err != nil {
				return
			}
			go func() {
				defer conn.Close()
				io.Copy(conn, conn)
			}()
		}
	}()
	closed, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	offline := closed.Addr().String()
	closed.Close()
	publisher, consumer := testCredentials(t)
	publishResult := make(chan error, 1)
	go func() {
		publishResult <- Publish(ctx, listener.Addr().String(), "test", map[string]string{"echo": target.Addr().String(), "offline": offline}, publisher)
	}()
	deadline := time.Now().Add(3 * time.Second)
	for {
		services, err := hub.List(ctx, listener.Addr().String(), "test")
		if err == nil && len(services) == 2 {
			break
		}
		select {
		case err := <-publishResult:
			t.Fatalf("publisher stopped before registration: %v", err)
		default:
		}
		if time.Now().After(deadline) {
			t.Fatalf("publisher did not register: %v", err)
		}
		time.Sleep(5 * time.Millisecond)
	}
	dialCtx, stop := context.WithTimeout(ctx, 3*time.Second)
	defer stop()
	if conn, err := Dial(dialCtx, listener.Addr().String(), "test", "offline", consumer); err == nil {
		conn.Close()
		t.Fatal("offline target accepted")
	} else if !strings.Contains(err.Error(), "target connection failed") {
		t.Fatalf("missing encrypted target error: %v", err)
	}
	if conn, err := Dial(dialCtx, listener.Addr().String(), "test", "missing", consumer); err == nil {
		conn.Close()
		t.Fatal("unknown service accepted")
	} else if !strings.Contains(err.Error(), "unknown service") {
		t.Fatalf("missing encrypted unknown-service error: %v", err)
	}
	first, err := Dial(dialCtx, listener.Addr().String(), "test", "echo", consumer)
	if err != nil {
		t.Fatal(err)
	}
	defer first.Close()
	second, err := Dial(dialCtx, listener.Addr().String(), "test", "echo", consumer)
	if err != nil {
		t.Fatal(err)
	}
	defer second.Close()
	first.Close()
	if _, err := second.Write([]byte("still independent")); err != nil {
		t.Fatal(err)
	}
	got := make([]byte, len("still independent"))
	if _, err := io.ReadFull(second, got); err != nil || string(got) != "still independent" {
		t.Fatalf("independent stream: %q %v", got, err)
	}
}
