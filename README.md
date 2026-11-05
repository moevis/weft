# Weft

Named TCP services through an untrusted relay. `weftd` routes connections; `weft` publishes services or binds them to localhost. Payloads use end-to-end Noise encryption. No relay accounts or relay credential checks.

## Install

After the repository is public and its first GitHub Release is published:

```sh
curl -fsSL https://raw.githubusercontent.com/moevis/weft/main/scripts/install.sh | bash -s -- moevis/weft
```

Downloads the latest stable release, verifies SHA-256, and installs `weft` and
`weftd` into `~/.local/bin` without sudo. Supports Linux/macOS on amd64/arm64.
Requires Bash, curl, tar, and sha256sum or shasum. No configuration is modified.
Checksums detect corrupted downloads; they do not protect against a compromised
release repository. Inspect the installer before running it if required.

Pin a release or change the install directory:

```sh
curl -fsSL https://raw.githubusercontent.com/moevis/weft/main/scripts/install.sh \
  | WEFT_VERSION=v0.1.0 WEFT_INSTALL_DIR="$HOME/bin" bash -s -- moevis/weft
```

## Build

Requires Go 1.25 or newer.

```sh
go build -o weft ./cmd/weft
go build -o weftd ./cmd/weftd
```

## GitHub Actions and releases

GitHub-hosted runners require no self-hosted runner setup:

- Branch pushes and pull requests run formatting checks, `go vet`, race tests,
  and command builds on Ubuntu, using the Go version in `go.mod`. Release builds
  cross-compile with `CGO_ENABLED=0`; macOS binaries are not tested on a hosted Mac.
- Pushing a version tag runs the same checks before packaging both commands for
  Linux and macOS, each on amd64 and arm64. Each archive includes the README;
  `checksums.txt` contains SHA-256 checksums.
- The release job uses the repository's automatic `GITHUB_TOKEN` with
  `contents: write`; no personal access token is needed. It uploads assets to a
  draft before making the release public. Hyphenated versions are prereleases.

Enable Actions in the GitHub repository, push the code, then publish a version:

```sh
git tag v0.1.0
git push origin v0.1.0
```

Use a new tag for each release. Repository/organization policies must permit
GitHub Actions and release creation. Windows and Android binaries are not
included: Unix credential-file permissions are currently part of the contract.

To exercise exactly the release packaging locally:

```sh
bash scripts/package.sh v0.1.0 dist
```

## Publish and connect

```sh
# Publicly reachable relay; default port is 8443.
./weftd -listen :8443

# Publisher: expose services reachable from THIS machine.
./weft -channel phone -endpoint relay.example:/phone-1 \
  -publish adb:5555 -publish localserver:8888
```

First publication creates `~/.weft.toml`, generates an identity and random shared key, and saves the service mappings. Restart with `weft -channel phone`. Keys live directly inside the TOML; there are no separate key files. Keep this file private. Existing malformed or mismatched keys are rejected, never silently replaced.

Export a client configuration on the publisher:

```sh
(umask 077; ./weft -channel phone -export-client > phone-client.toml)
```

Transfer it privately to the client. It includes the shared key, a separate client identity, and the pinned publisher public key; it does NOT contain the publisher private key or local target addresses.

```sh
./weft -conf ./phone-client.toml -channel phone -list
./weft -conf ./phone-client.toml -channel phone -bind adb:5555
# In another terminal:
adb connect localhost:5555
```

Or run the local command once binding is ready:

```sh
./weft -conf ./phone-client.toml -channel phone \
  -bind adb:5555 -- adb connect localhost:5555
```

The tunnel stays active after the command exits, because `adb connect` exits while the ADB server still needs its connection. Ctrl-C stops it. Add `-exit-with-command` for commands whose completion should stop the bindings. A failed child command closes the bindings and returns an error.

Omit the local port to allocate one automatically:

```sh
./weft -conf ./phone-client.toml -channel phone \
  -bind adb -- adb connect '{adb.addr}'
```

`{adb.addr}` expands to the actual local address. Arguments after `--` execute directly, not through a shell. Weft does not start ADB TCP mode, implement ADB, or emulate an Android device: the published target must already be a working `adbd` endpoint. Shizuku is not required by this TCP tunnel.

## Channels and flags

Default config: `~/.weft.toml`; override with `-conf PATH`. One configured channel is selected automatically. With `-endpoint` but no `-channel`, the endpoint path becomes the local channel name. Otherwise select with `-channel NAME`.

```toml
[channels.phone]
endpoint = "relay.example:/phone-1"
mode = "shared"
private_key = "<base64, generated>"
public_key = "<base64, generated>"
secret = "<base64, generated>"

[channels.phone.publish]
adb = "127.0.0.1:5555"
localserver = "127.0.0.1:8888"
```

- `-publish NAME:PORT` / `NAME:HOST:PORT`: repeatable. Default invocation publishes.
- `-bind NAME[:PORT]` / `NAME:HOST:PORT`: repeatable. Defaults to loopback, port zero allocates an available port. Explicit non-loopback bindings expose the service to that network.
- `-list [-json]`: list advertised services, without authenticating to the publisher or probing its local targets. `online` means its publisher is registered, not that the target accepts connections.
- `-export-client`: write client TOML to stdout; notices go to stderr. Contains secrets.
- `-save`: persist overrides. Initial publication and generated credentials are saved automatically; ordinary overrides are otherwise temporary.
- `-verbose`: include relay/channel/mode details. Secrets are never logged.
- `-h`: help. Exit status 0 for success, help, or signal shutdown; 1 for errors.

Configuration writes use a same-directory temporary file, file sync, and atomic rename, with mode 0600. Existing files with group/other access are rejected: use `chmod 600 FILE`. Do not concurrently edit/export the same configuration from multiple processes; stop the publisher when changing identity or authorization, then restart it to reload.

## Public-key mode

No shared secret is needed in public-key mode. Export generates a distinct client identity and adds its public key to the publisher's `allowed_clients`.

```sh
# Create publisher identity and authorize the first client.
(umask 077; ./weft -channel phone -endpoint relay.example:/phone-1 \
  -mode public -export-client > phone-client.toml)

# Publish, then use the exported config on the other machine as above.
./weft -channel phone -publish adb:5555
```

Additional exports create additional client identities. Restart the publisher to load new authorizations. To revoke a public-key client, remove its key from `allowed_clients` and restart. Shared-key clients share access; revoke by rotating `secret` and redistributing client configurations. Do not switch modes by editing only `mode`: public mode must have no `secret`, and clients need matching credentials.

## Transport and security boundaries

- Independent encrypted stream for every local TCP connection; no merging or broadcasting clients' traffic.
- Noise XX or XXpsk3, Curve25519 / ChaCha20-Poly1305 / SHA-256, with fresh ephemeral keys. Clients pin the publisher identity; public-only publishers require a client allowlist.
- Authenticated bounded records, including directional EOF, preserve TCP half-close. Service selection and target errors are encrypted.
- Raw TCP to the relay, not HTTP/WebSocket/TLS. It cannot be deployed behind an HTTP-only reverse proxy. Bindings are byte streams, not UDP forwarding.
- No application queues, silent frame dropping, or unbounded buffering; ordinary TCP flow control applies when peers are slow.
- Relay sees channel names, published service names, connection metadata and traffic sizes. Directory contents are NOT authenticated. Without relay registration authentication, another publisher can occupy an unused channel and deny access; identity pinning prevents it impersonating the expected publisher to a configured client.
- Local program-to-Weft and Weft-to-target links are outside tunnel encryption. Keep them on loopback or another trusted link. Anyone who can reach a local binding can use it.
- Disconnects close existing TCP streams. There is no automatic stream resumption or publisher reconnection; restart the affected process. This implementation has not undergone an independent security audit.

## Verification

```sh
go test -race ./...
```

Tests cover relay routing and shutdown, authenticated stream integrity and half-close, identity pinning, client authorization, target errors, and configuration credential boundaries.
