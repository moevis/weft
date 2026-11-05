package hub

import (
	"context"
	"crypto/rand"
	"encoding/binary"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net"
	"sync"
	"time"
)

// Service is a name advertised by a currently connected publisher.
type Service struct {
	Name   string `json:"name"`
	Online bool   `json:"online"`
}

const (
	maxControl     = 64 * 1024
	maxNames       = 256
	controlTimeout = 15 * time.Second
)

type message struct {
	Op       string    `json:"op,omitempty"`
	Channel  string    `json:"channel,omitempty"`
	Names    []string  `json:"names,omitempty"`
	Token    string    `json:"token,omitempty"`
	Services []Service `json:"services,omitempty"`
	Error    string    `json:"error,omitempty"`
}

// Control messages are length-prefixed rather than buffered JSON streams: no
// decoder can read ahead into the opaque bytes following a successful open.
func readMessage(r io.Reader) (message, error) {
	var m message
	var header [4]byte
	if _, err := io.ReadFull(r, header[:]); err != nil {
		return m, err
	}
	n := binary.BigEndian.Uint32(header[:])
	if n == 0 || n > maxControl {
		return m, errors.New("invalid hub control message length")
	}
	data := make([]byte, int(n))
	if _, err := io.ReadFull(r, data); err != nil {
		return m, err
	}
	if err := json.Unmarshal(data, &m); err != nil {
		return m, err
	}
	return m, nil
}

func writeMessage(w io.Writer, m message) error {
	data, err := json.Marshal(m)
	if err != nil {
		return err
	}
	if len(data) > maxControl {
		return errors.New("hub control message too large")
	}
	var header [4]byte
	binary.BigEndian.PutUint32(header[:], uint32(len(data)))
	if err := writeAll(w, header[:]); err != nil {
		return err
	}
	return writeAll(w, data)
}

func writeAll(w io.Writer, data []byte) error {
	for len(data) != 0 {
		n, err := w.Write(data)
		if err != nil {
			return err
		}
		if n == 0 {
			return io.ErrShortWrite
		}
		data = data[n:]
	}
	return nil
}

func validChannel(channel string) bool { return channel != "" && len(channel) <= 512 }

func validateNames(names []string) error {
	if len(names) == 0 || len(names) > maxNames {
		return errors.New("publisher requires 1 to 256 service names")
	}
	seen := make(map[string]bool, len(names))
	for _, name := range names {
		if name == "" || len(name) > 128 || seen[name] {
			return errors.New("invalid or duplicate service name")
		}
		seen[name] = true
	}
	return nil
}

type publisher struct {
	names  []string
	events chan string
	done   chan struct{}
}

type attachment struct {
	publisher *publisher
	conn      chan net.Conn
	done      chan struct{}
}

type server struct {
	ctx        context.Context
	mu         sync.Mutex
	conns      map[net.Conn]struct{}
	publishers map[string]*publisher
	pending    map[string]*attachment
	wg         sync.WaitGroup
}

// Serve runs the unauthenticated relay until ctx is canceled or Accept fails.
// It closes the listener and all control and data connections before returning.
func Serve(ctx context.Context, listener net.Listener) error {
	serveCtx, cancel := context.WithCancel(ctx)
	defer cancel()
	s := &server{ctx: serveCtx, conns: make(map[net.Conn]struct{}), publishers: make(map[string]*publisher), pending: make(map[string]*attachment)}
	stop := context.AfterFunc(ctx, func() {
		listener.Close()
		s.mu.Lock()
		for c := range s.conns {
			c.Close()
		}
		s.mu.Unlock()
	})
	defer stop()
	var acceptErr error
	for {
		c, err := listener.Accept()
		if err != nil {
			acceptErr = err
			break
		}
		s.mu.Lock()
		if ctx.Err() != nil {
			s.mu.Unlock()
			c.Close()
			break
		}
		s.conns[c] = struct{}{}
		s.wg.Add(1)
		s.mu.Unlock()
		go func() {
			defer s.wg.Done()
			defer func() { c.Close(); s.mu.Lock(); delete(s.conns, c); s.mu.Unlock() }()
			s.handle(c)
		}()
	}
	cancel()
	listener.Close()
	s.mu.Lock()
	for c := range s.conns {
		c.Close()
	}
	s.mu.Unlock()
	s.wg.Wait()
	if ctx.Err() != nil {
		return nil
	}
	return acceptErr
}

func (s *server) handle(c net.Conn) {
	c.SetDeadline(time.Now().Add(controlTimeout))
	m, err := readMessage(c)
	if err != nil {
		return
	}
	if m.Op != "attach" && !validChannel(m.Channel) {
		writeMessage(c, message{Error: "invalid channel"})
		return
	}
	switch m.Op {
	case "publish":
		s.publish(c, m)
	case "list":
		services := make([]Service, 0)
		s.mu.Lock()
		if p := s.publishers[m.Channel]; p != nil {
			for _, name := range p.names {
				services = append(services, Service{Name: name, Online: true})
			}
		}
		s.mu.Unlock()
		writeMessage(c, message{Services: services})
	case "open":
		s.open(c, m.Channel)
	case "attach":
		s.attach(c, m.Token)
	default:
		writeMessage(c, message{Error: "unknown hub operation"})
	}
}

func (s *server) publish(c net.Conn, m message) {
	if err := validateNames(m.Names); err != nil {
		writeMessage(c, message{Error: err.Error()})
		return
	}
	p := &publisher{names: m.Names, events: make(chan string, 32), done: make(chan struct{})}
	s.mu.Lock()
	if s.publishers[m.Channel] != nil {
		s.mu.Unlock()
		writeMessage(c, message{Error: "channel already has a publisher"})
		return
	}
	s.publishers[m.Channel] = p
	s.mu.Unlock()
	defer func() {
		s.mu.Lock()
		delete(s.publishers, m.Channel)
		close(p.done)
		s.mu.Unlock()
	}()
	if writeMessage(c, message{}) != nil {
		return
	}
	c.SetDeadline(time.Time{})
	disconnected := make(chan struct{})
	go func() {
		// Publishers send no further control data. Any data or EOF terminates
		// this registration rather than allowing an unbounded receive buffer.
		var b [1]byte
		c.Read(b[:])
		close(disconnected)
	}()
	for {
		select {
		case <-s.ctx.Done():
			return
		case <-disconnected:
			return
		case token := <-p.events:
			c.SetWriteDeadline(time.Now().Add(controlTimeout))
			if writeMessage(c, message{Op: "incoming", Token: token}) != nil {
				return
			}
		}
	}
}

func (s *server) open(c net.Conn, channel string) {
	var random [32]byte
	if _, err := rand.Read(random[:]); err != nil {
		writeMessage(c, message{Error: "cannot create stream"})
		return
	}
	token := hex.EncodeToString(random[:])
	s.mu.Lock()
	p := s.publishers[channel]
	if p == nil {
		s.mu.Unlock()
		writeMessage(c, message{Error: "channel is offline"})
		return
	}
	if len(s.pending) >= 256 {
		s.mu.Unlock()
		writeMessage(c, message{Error: "relay is busy"})
		return
	}
	a := &attachment{publisher: p, conn: make(chan net.Conn), done: make(chan struct{})}
	s.pending[token] = a
	select {
	case p.events <- token:
	default:
		delete(s.pending, token)
		s.mu.Unlock()
		writeMessage(c, message{Error: "publisher is busy"})
		return
	}
	s.mu.Unlock()
	defer func() { s.mu.Lock(); delete(s.pending, token); s.mu.Unlock(); close(a.done) }()
	timer := time.NewTimer(controlTimeout)
	defer timer.Stop()
	select {
	case peer := <-a.conn:
		go func() {
			select {
			case <-p.done:
				c.Close()
				peer.Close()
			case <-a.done:
			case <-s.ctx.Done():
			}
		}()
		if writeMessage(c, message{}) != nil {
			return
		}
		c.SetDeadline(time.Time{})
		copyStream(c, peer)
	case <-p.done:
		writeMessage(c, message{Error: "publisher disconnected"})
	case <-timer.C:
		writeMessage(c, message{Error: "publisher stream timed out"})
	case <-s.ctx.Done():
	}
}

func (s *server) attach(c net.Conn, token string) {
	s.mu.Lock()
	a := s.pending[token]
	delete(s.pending, token)
	s.mu.Unlock()
	if a == nil {
		writeMessage(c, message{Error: "unknown stream"})
		return
	}
	if writeMessage(c, message{}) != nil {
		return
	}
	c.SetDeadline(time.Time{})
	select {
	case a.conn <- c:
		select {
		case <-a.done:
		case <-s.ctx.Done():
		}
	case <-a.done:
	case <-a.publisher.done:
	case <-s.ctx.Done():
	}
}

func copyStream(a, b net.Conn) {
	finished := make(chan struct{}, 1)
	copyOne := func(dst, src net.Conn) {
		if _, err := io.Copy(dst, src); err != nil {
			a.Close()
			b.Close()
		} else {
			closeWrite(dst)
		}
	}
	go func() { copyOne(a, b); finished <- struct{}{} }()
	copyOne(b, a)
	<-finished
}

func closeWrite(c net.Conn) {
	if half, ok := c.(interface{ CloseWrite() error }); ok {
		half.CloseWrite()
	} else {
		c.Close()
	}
}

func connect(ctx context.Context, address string, request message) (net.Conn, func(), error) {
	c, err := (&net.Dialer{}).DialContext(ctx, "tcp", address)
	if err != nil {
		return nil, nil, err
	}
	stop := context.AfterFunc(ctx, func() { c.Close() })
	cleanup := func() { stop(); c.Close() }
	c.SetDeadline(time.Now().Add(controlTimeout))
	if err := writeMessage(c, request); err != nil {
		cleanup()
		return nil, nil, contextError(ctx, err)
	}
	response, err := readMessage(c)
	if err == nil && response.Error != "" {
		err = errors.New(response.Error)
	}
	if err != nil {
		cleanup()
		return nil, nil, contextError(ctx, err)
	}
	c.SetDeadline(time.Time{})
	return &responseConn{Conn: c, response: response}, func() { stop() }, nil
}

type responseConn struct {
	net.Conn
	response message
}

func contextError(ctx context.Context, err error) error {
	if ctx.Err() != nil {
		return ctx.Err()
	}
	return err
}

// List returns names only, without contacting any published target.
func List(ctx context.Context, address, channel string) ([]Service, error) {
	if !validChannel(channel) {
		return nil, errors.New("invalid channel")
	}
	c, stop, err := connect(ctx, address, message{Op: "list", Channel: channel})
	if err != nil {
		return nil, err
	}
	defer stop()
	defer c.Close()
	return c.(*responseConn).response.Services, nil
}

// Open establishes an independent raw stream to the channel's publisher.
// ctx governs establishment; callers own the returned connection's lifetime.
func Open(ctx context.Context, address, channel string) (net.Conn, error) {
	if !validChannel(channel) {
		return nil, errors.New("invalid channel")
	}
	c, stop, err := connect(ctx, address, message{Op: "open", Channel: channel})
	if err != nil {
		return nil, err
	}
	stop()
	return c.(*responseConn).Conn, nil
}

// Publish registers names and dispatches each independent raw stream to handle.
// Cancellation or a control connection failure closes every active stream.
func Publish(ctx context.Context, address, channel string, names []string, handle func(net.Conn)) error {
	if !validChannel(channel) {
		return errors.New("invalid channel")
	}
	if err := validateNames(names); err != nil {
		return err
	}
	if handle == nil {
		return errors.New("nil stream handler")
	}
	ctx, cancel := context.WithCancel(ctx)
	defer cancel()
	control, stop, err := connect(ctx, address, message{Op: "publish", Channel: channel, Names: names})
	if err != nil {
		return err
	}
	defer stop()
	defer control.Close()
	var wg sync.WaitGroup
	defer wg.Wait()
	// This defer runs before Wait, unblocking both pending dials and handlers.
	defer cancel()
	for {
		m, err := readMessage(control)
		if err != nil {
			return contextError(ctx, err)
		}
		if m.Op != "incoming" || len(m.Token) != 64 {
			return fmt.Errorf("invalid publisher control event")
		}
		wg.Add(1)
		go func(token string) {
			defer wg.Done()
			c, stop, err := connect(ctx, address, message{Op: "attach", Token: token})
			if err != nil {
				return
			}
			defer stop()
			defer c.Close()
			handle(c.(*responseConn).Conn)
		}(m.Token)
	}
}
