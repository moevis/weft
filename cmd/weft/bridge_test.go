package main

import (
	"context"
	"net"
	"testing"
	"time"
)

func TestBridgePreservesResponseAfterHalfClose(t *testing.T) {
	listen := func() net.Listener {
		l, e := net.Listen("tcp", "127.0.0.1:0")
		if e != nil {
			t.Fatal(e)
		}
		t.Cleanup(func() { l.Close() })
		return l
	}
	left, right := listen(), listen()
	caller, e := net.Dial("tcp", left.Addr().String())
	if e != nil {
		t.Fatal(e)
	}
	defer caller.Close()
	a, e := left.Accept()
	if e != nil {
		t.Fatal(e)
	}
	defer a.Close()
	b, e := net.Dial("tcp", right.Addr().String())
	if e != nil {
		t.Fatal(e)
	}
	defer b.Close()
	target, e := right.Accept()
	if e != nil {
		t.Fatal(e)
	}
	defer target.Close()
	deadline := time.Now().Add(3 * time.Second)
	caller.SetDeadline(deadline)
	target.SetDeadline(deadline)
	done := make(chan struct{})
	go func() { bridge(a, b); close(done) }()
	caller.Write([]byte("request"))
	caller.(*net.TCPConn).CloseWrite()
	buffer := make([]byte, 32)
	n, e := target.Read(buffer)
	if e != nil || string(buffer[:n]) != "request" {
		t.Fatalf("request: %q %v", buffer[:n], e)
	}
	target.Write([]byte("response"))
	target.(*net.TCPConn).CloseWrite()
	n, e = caller.Read(buffer)
	if e != nil || string(buffer[:n]) != "response" {
		t.Fatalf("response: %q %v", buffer[:n], e)
	}
	ctx, cancel := context.WithTimeout(context.Background(), 3*time.Second)
	defer cancel()
	select {
	case <-done:
	case <-ctx.Done():
		t.Fatal("bridge did not finish")
	}
}
