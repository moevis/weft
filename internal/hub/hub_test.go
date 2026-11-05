package hub

import (
	"bytes"
	"context"
	"encoding/binary"
	"io"
	"net"
	"strings"
	"testing"
	"time"
)

func startRelay(t *testing.T) (string, context.Context) {
	t.Helper()
	ctx, cancel := context.WithCancel(context.Background())
	listener, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	done := make(chan error, 1)
	go func() { done <- Serve(ctx, listener) }()
	t.Cleanup(func() {
		cancel()
		select {
		case err := <-done:
			if err != nil {
				t.Error(err)
			}
		case <-time.After(3 * time.Second):
			t.Error("relay did not stop")
		}
	})
	return listener.Addr().String(), ctx
}

func startPublisher(t *testing.T, ctx context.Context, address string, handle func(net.Conn)) context.CancelFunc {
	t.Helper()
	ctx, cancel := context.WithCancel(ctx)
	done := make(chan error, 1)
	go func() { done <- Publish(ctx, address, "test", []string{"echo", "unreachable"}, handle) }()
	t.Cleanup(func() {
		cancel()
		select {
		case <-done:
		case <-time.After(3 * time.Second):
			t.Error("publisher did not stop")
		}
	})
	deadline := time.Now().Add(3 * time.Second)
	for {
		services, err := List(ctx, address, "test")
		if err != nil {
			t.Fatal(err)
		}
		if len(services) == 2 {
			return cancel
		}
		if time.Now().After(deadline) {
			t.Fatal("publisher never registered")
		}
		time.Sleep(time.Millisecond)
	}
}

func TestPublishListAndIndependentStreams(t *testing.T) {
	address, ctx := startRelay(t)
	startPublisher(t, ctx, address, func(c net.Conn) { io.Copy(c, c) })
	services, err := List(ctx, address, "test")
	if err != nil {
		t.Fatal(err)
	}
	if len(services) != 2 || services[0].Name != "echo" || !services[0].Online || services[1].Name != "unreachable" {
		t.Fatalf("unexpected directory: %#v", services)
	}
	if err := Publish(ctx, address, "test", []string{"replacement"}, func(net.Conn) {}); err == nil {
		t.Fatal("duplicate publisher accepted")
	}
	if _, err := Open(ctx, address, "absent"); err == nil {
		t.Fatal("offline channel accepted")
	}
	first, err := Open(ctx, address, "test")
	if err != nil {
		t.Fatal(err)
	}
	defer first.Close()
	second, err := Open(ctx, address, "test")
	if err != nil {
		t.Fatal(err)
	}
	defer second.Close()
	for i, c := range []net.Conn{first, second} {
		c.SetDeadline(time.Now().Add(3 * time.Second))
		payload := []byte(strings.Repeat(string(rune('a'+i)), 2048))
		if _, err := c.Write(payload); err != nil {
			t.Fatal(err)
		}
		got := make([]byte, len(payload))
		if _, err := io.ReadFull(c, got); err != nil {
			t.Fatal(err)
		}
		if !bytes.Equal(got, payload) {
			t.Fatal("stream data mixed or lost")
		}
	}
	first.Close()
	if _, err := second.Write([]byte("still alive")); err != nil {
		t.Fatal(err)
	}
	got := make([]byte, len("still alive"))
	if _, err := io.ReadFull(second, got); err != nil {
		t.Fatal(err)
	}
	if string(got) != "still alive" {
		t.Fatal("closing one stream damaged another")
	}
}

func TestControlFrameDoesNotConsumeRawBytes(t *testing.T) {
	payload := []byte{0, 1, 255, 123, 10}
	var wire bytes.Buffer
	if err := writeMessage(&wire, message{}); err != nil {
		t.Fatal(err)
	}
	wire.Write(payload)
	if _, err := readMessage(&wire); err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(wire.Bytes(), payload) {
		t.Fatal("control reader consumed stream bytes")
	}
	var header [4]byte
	binary.BigEndian.PutUint32(header[:], maxControl+1)
	if _, err := readMessage(bytes.NewReader(header[:])); err == nil {
		t.Fatal("oversized control frame accepted")
	}
}

func TestPublisherCancellationClosesStreams(t *testing.T) {
	address, ctx := startRelay(t)
	accepted := make(chan struct{})
	cancel := startPublisher(t, ctx, address, func(c net.Conn) { close(accepted); io.Copy(io.Discard, c) })
	c, err := Open(ctx, address, "test")
	if err != nil {
		t.Fatal(err)
	}
	defer c.Close()
	select {
	case <-accepted:
	case <-time.After(3 * time.Second):
		t.Fatal("stream not accepted")
	}
	cancel()
	c.SetReadDeadline(time.Now().Add(3 * time.Second))
	var b [1]byte
	if _, err := c.Read(b[:]); err == nil {
		t.Fatal("canceled publisher left stream open")
	} else if timeout, ok := err.(net.Error); ok && timeout.Timeout() {
		t.Fatal("stream closure timed out")
	}
}

func TestStreamHalfClose(t *testing.T) {
	address, ctx := startRelay(t)
	startPublisher(t, ctx, address, func(c net.Conn) {
		data, err := io.ReadAll(c)
		if err == nil {
			c.Write(append([]byte("reply:"), data...))
		}
	})
	c, err := Open(ctx, address, "test")
	if err != nil {
		t.Fatal(err)
	}
	defer c.Close()
	c.SetDeadline(time.Now().Add(3 * time.Second))
	if _, err := c.Write([]byte("request")); err != nil {
		t.Fatal(err)
	}
	if err := c.(interface{ CloseWrite() error }).CloseWrite(); err != nil {
		t.Fatal(err)
	}
	data, err := io.ReadAll(c)
	if err != nil {
		t.Fatal(err)
	}
	if string(data) != "reply:request" {
		t.Fatalf("unexpected reply %q", data)
	}
}
