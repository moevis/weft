package main

import (
	"context"
	"errors"
	"flag"
	"fmt"
	"io"
	"net"
	"os"
	"os/exec"
	"os/signal"
	"sort"
	"strings"
	"sync"
	"syscall"

	"github.com/BurntSushi/toml"
	"weft/internal/config"
	"weft/internal/tunnel"
)

type values []string

func (v *values) String() string     { return strings.Join(*v, ",") }
func (v *values) Set(s string) error { *v = append(*v, s); return nil }

type options struct {
	conf, channel, endpoint, mode                      string
	publish, bind                                      values
	list, export, save, verbose, exitWithCommand, json bool
	command                                            []string
}

func parse(args []string) (options, error) {
	var o options
	fs := flag.NewFlagSet("weft", flag.ContinueOnError)
	fs.SetOutput(os.Stderr)
	fs.Usage = func() {
		fmt.Fprintln(fs.Output(), "Weft — encrypted service forwarding\n\n  weft -channel phone -endpoint host:/phone -publish adb:5555\n  weft -channel phone -bind adb:5555 [-- command args...]\n  weft -channel phone -list\n  weft -channel phone -export-client\n\nOptions:")
		fs.PrintDefaults()
	}
	fs.StringVar(&o.conf, "conf", "", "config file (default ~/.weft.toml)")
	fs.StringVar(&o.channel, "channel", "", "channel name")
	fs.StringVar(&o.endpoint, "endpoint", "", "relay host[:port]:/channel")
	fs.StringVar(&o.mode, "mode", "", "shared or public (on initial publication)")
	fs.Var(&o.publish, "publish", "name:port or name:host:port (repeatable)")
	fs.Var(&o.bind, "bind", "name[:port] or name:host:port (repeatable)")
	fs.BoolVar(&o.list, "list", false, "list remote services")
	fs.BoolVar(&o.export, "export-client", false, "export client config to stdout")
	fs.BoolVar(&o.save, "save", false, "save command-line overrides")
	fs.BoolVar(&o.verbose, "verbose", false, "show connection details")
	fs.BoolVar(&o.exitWithCommand, "exit-with-command", false, "close bindings when command exits")
	fs.BoolVar(&o.json, "json", false, "machine-readable service list")
	if err := fs.Parse(args); err != nil {
		return o, err
	}
	o.command = fs.Args()
	return o, nil
}
func run(ctx context.Context, args []string) error {
	o, err := parse(args)
	if err != nil {
		return err
	}
	if o.conf == "" {
		o.conf, err = config.DefaultPath()
		if err != nil {
			return err
		}
	}
	cfg, err := config.Load(o.conf)
	if err != nil {
		return err
	}
	if o.channel == "" && o.endpoint != "" {
		_, o.channel, err = config.Endpoint(o.endpoint)
		if err != nil {
			return err
		}
	}
	if o.channel == "" {
		if len(cfg.Channels) == 1 {
			for name := range cfg.Channels {
				o.channel = name
			}
		} else {
			names := make([]string, 0, len(cfg.Channels))
			for name := range cfg.Channels {
				names = append(names, name)
			}
			sort.Strings(names)
			return fmt.Errorf("select a channel with -channel NAME (configured: %s)", strings.Join(names, ", "))
		}
	}
	c, exists := cfg.Channels[o.channel]
	if !exists {
		c = &config.Channel{}
		cfg.Channels[o.channel] = c
	}
	if o.endpoint != "" {
		c.Endpoint = o.endpoint
	}
	if o.mode != "" {
		c.Mode = o.mode
	}
	address, remote, err := config.Endpoint(c.Endpoint)
	if err != nil {
		return err
	}
	actions := 0
	for _, b := range []bool{o.list, o.export, len(o.bind) > 0} {
		if b {
			actions++
		}
	}
	if actions > 1 || (actions > 0 && len(o.publish) > 0) {
		return errors.New("choose one mode: publish, -bind, -list, or -export-client")
	}
	if len(o.command) > 0 && len(o.bind) == 0 {
		return errors.New("commands require -bind; use -- before command arguments")
	}
	if o.exitWithCommand && len(o.command) == 0 {
		return errors.New("-exit-with-command requires a command after --")
	}
	if o.json && !o.list {
		return errors.New("-json requires -list")
	}
	if o.list {
		return list(ctx, address, remote, o.json)
	}
	if o.export {
		if c.ServerPublicKey != "" {
			return errors.New("client configuration cannot export publisher credentials")
		}
		client, e := c.ClientConfig()
		if e != nil {
			return e
		}
		if e = config.Save(o.conf, cfg); e != nil {
			return e
		}
		fmt.Fprintln(os.Stderr, "Client config contains credentials; keep it private.")
		if c.Mode == "public" {
			fmt.Fprintln(os.Stderr, "Restart the publisher to load the new client authorization.")
		}
		return toml.NewEncoder(os.Stdout).Encode(&config.File{Channels: map[string]*config.Channel{o.channel: client}})
	}
	if len(o.bind) > 0 {
		if c.ServerPublicKey == "" {
			return errors.New("missing server_public_key; import a configuration from the publisher's -export-client")
		}
		changed, e := c.EnsureIdentity()
		if e != nil {
			return e
		}
		if changed || o.save {
			if e = config.Save(o.conf, cfg); e != nil {
				return e
			}
		}
		creds, e := c.Credentials()
		if e != nil {
			return e
		}
		return bind(ctx, o, address, remote, creds)
	}
	if c.ServerPublicKey != "" {
		return errors.New("this is a client channel; use -bind SERVICE:PORT or -list")
	}
	if c.Publish == nil {
		c.Publish = map[string]string{}
	}
	firstPublication := len(c.Publish) == 0
	for _, s := range o.publish {
		name, target, ok := strings.Cut(s, ":")
		if !ok || !validName(name) {
			return fmt.Errorf("invalid publication %q; use name:port or name:host:port", s)
		}
		target, e := config.Target(target)
		if e != nil {
			return fmt.Errorf("%s: %w", name, e)
		}
		c.Publish[name] = target
	}
	if len(c.Publish) == 0 {
		return errors.New("no services configured; use -publish adb:5555")
	}
	for name, target := range c.Publish {
		if !validName(name) {
			return fmt.Errorf("invalid service name %q", name)
		}
		normalized, e := config.Target(target)
		if e != nil {
			return fmt.Errorf("%s: %w", name, e)
		}
		c.Publish[name] = normalized
	}
	changed, err := c.EnsurePublisher()
	if err != nil {
		return err
	}
	if changed || !exists || firstPublication || o.save {
		if err = config.Save(o.conf, cfg); err != nil {
			return err
		}
	}
	if c.Mode == "public" && len(c.AllowedClients) == 0 {
		return errors.New("no authorized clients; run -export-client first, then publish")
	}
	creds, err := c.Credentials()
	if err != nil {
		return err
	}
	if o.verbose {
		fmt.Fprintf(os.Stderr, "Relay %s · channel %s · %s mode\n", address, remote, c.Mode)
	}
	names := make([]string, 0, len(c.Publish))
	for name := range c.Publish {
		names = append(names, name)
	}
	sort.Strings(names)
	fmt.Fprintf(os.Stderr, "Publishing %s · %s\n", o.channel, strings.Join(names, ", "))
	return tunnel.Publish(ctx, address, remote, c.Publish, creds)
}
func validName(s string) bool {
	if s == "" {
		return false
	}
	for _, r := range s {
		if !(r >= 'a' && r <= 'z' || r >= 'A' && r <= 'Z' || r >= '0' && r <= '9' || r == '_' || r == '-' || r == '.') {
			return false
		}
	}
	return true
}
func main() {
	ctx, stop := signal.NotifyContext(context.Background(), os.Interrupt, syscall.SIGTERM)
	defer stop()
	if err := run(ctx, os.Args[1:]); err != nil && !errors.Is(err, context.Canceled) && !errors.Is(err, flag.ErrHelp) {
		fmt.Fprintln(os.Stderr, "weft:", err)
		os.Exit(1)
	}
}

// bind establishes a fresh authenticated stream for every local TCP connection.
func bind(ctx context.Context, o options, address, channel string, credentials tunnel.Credentials) error {
	ctx, cancel := context.WithCancel(ctx)
	defer cancel()
	type binding struct {
		name     string
		listener net.Listener
	}
	var bindings []binding
	defer func() {
		for _, b := range bindings {
			b.listener.Close()
		}
	}()
	seen := map[string]bool{}
	for _, s := range o.bind {
		name, target, has := strings.Cut(s, ":")
		if !validName(name) || seen[name] {
			return fmt.Errorf("invalid or duplicate binding %q", name)
		}
		seen[name] = true
		if !has {
			target = "0"
		}
		target, err := config.Target(target)
		if err != nil {
			return fmt.Errorf("%s: %w", name, err)
		}
		// Probe real target and end-to-end credentials before announcing readiness.
		probe, err := tunnel.Dial(ctx, address, channel, name, credentials)
		if err != nil {
			return fmt.Errorf("%s: %w", name, err)
		}
		probe.Close()
		listener, err := net.Listen("tcp", target)
		if err != nil {
			return fmt.Errorf("cannot bind %s at %s: %w; choose another port", name, target, err)
		}
		bindings = append(bindings, binding{name, listener})
	}
	var wg sync.WaitGroup
	defer func() {
		cancel()
		for _, b := range bindings {
			b.listener.Close()
		}
		wg.Wait()
	}()
	go func() {
		<-ctx.Done()
		for _, b := range bindings {
			b.listener.Close()
		}
	}()
	for _, b := range bindings {
		fmt.Fprintf(os.Stderr, "%s · %s → %s/%s\n", o.channel, b.listener.Addr(), channel, b.name)
		wg.Add(1)
		go func(b binding) {
			defer wg.Done()
			for {
				local, err := b.listener.Accept()
				if err != nil {
					return
				}
				wg.Add(1)
				go func() {
					defer wg.Done()
					defer local.Close()
					remote, err := tunnel.Dial(ctx, address, channel, b.name, credentials)
					if err != nil {
						fmt.Fprintf(os.Stderr, "weft: %s: %v\n", b.name, err)
						return
					}
					defer remote.Close()
					done := make(chan struct{})
					defer close(done)
					go func() {
						select {
						case <-ctx.Done():
							local.Close()
							remote.Close()
						case <-done:
						}
					}()
					bridge(local, remote)
				}()
			}
		}(b)
	}
	if len(o.command) > 0 {
		args := append([]string(nil), o.command...)
		for i, arg := range args {
			for _, b := range bindings {
				arg = strings.ReplaceAll(arg, "{"+b.name+".addr}", b.listener.Addr().String())
			}
			args[i] = arg
		}
		cmd := exec.CommandContext(ctx, args[0], args[1:]...)
		cmd.Stdin = os.Stdin
		cmd.Stdout = os.Stdout
		cmd.Stderr = os.Stderr
		if err := cmd.Run(); err != nil {
			cancel()
			return fmt.Errorf("command: %w", err)
		}
		if o.exitWithCommand {
			cancel()
			return nil
		}
		fmt.Fprintln(os.Stderr, "Command exited; tunnel remains active. Ctrl-C to stop.")
	}
	<-ctx.Done()
	return ctx.Err()
}
func bridge(a, b net.Conn) {
	done := make(chan struct{})
	copyOne := func(dst, src net.Conn) {
		if _, err := io.Copy(dst, src); err != nil {
			a.Close()
			b.Close()
			return
		}
		if c, ok := dst.(interface{ CloseWrite() error }); ok {
			c.CloseWrite()
		} else {
			dst.Close()
		}
	}
	go func() { copyOne(a, b); close(done) }()
	copyOne(b, a)
	<-done
}
