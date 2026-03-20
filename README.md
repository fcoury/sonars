# Sonars (or sona-rs?)

A fast, single-binary CLI tool that shows what's listening on your local ports. Rust reimplementation of [RasKrebs/sonar](https://github.com/RasKrebs/sonar).

Replace repetitive `lsof` / `ss` commands with a single tool that shows listening ports alongside Docker container names, Compose projects, resource usage, health status, and clickable URLs.

```
$ sonar list --stats
PORT   PID    PROCESS    CPU%  MEM     STATE    CONTAINER        IMAGE              CPORT  URL
3000   12841  node       2.1   48M     running  frontend         myapp-frontend     3000   http://localhost:3000
5432   11923  postgres   0.3   32M     running  db               postgres:16        5432   http://localhost:5432
8080   12100  java       5.4   256M    running  api              myapp-api          8080   http://localhost:8080
```

## Installation

### From source

```sh
cargo install --path .
```

### Build manually

```sh
git clone https://github.com/fcoury/sonars.git
cd sonars
cargo build --release
# Binary at ./target/release/sonar
```

## Usage

### Listing ports

```sh
sonar list                        # all listening ports
sonar list --stats                # include CPU, memory, state, uptime
sonar list --filter docker        # only Docker-mapped ports
sonar list --filter system        # only system ports (< 1024)
sonar list --sort name            # sort by process name
sonar list -a                     # include desktop apps (hidden by default)
sonar list --health               # run HTTP health checks
sonar list --json                 # JSON output
sonar list --host user@server     # scan a remote machine via SSH
sonar list -c port,process,cpu,mem,health,latency   # custom columns
```

Default columns: `PORT PID PROCESS CONTAINER IMAGE CPORT URL`

All available columns: `port`, `process`, `pid`, `type`, `url`, `cpu`, `mem`, `thr`, `uptime`, `state`, `conn`, `container`, `image`, `cport`, `service`, `project`, `user`, `bind`, `ip`, `health`, `latency`

### Port info & management

```sh
sonar info 3000                   # detailed info for a port
sonar kill 3000                   # SIGTERM the process on port 3000
sonar kill 3000 -f                # SIGKILL (force)
sonar kill-all                    # stop everything
sonar kill-all --filter docker    # stop all Docker containers
sonar open 3000                   # open http://localhost:3000 in browser
```

Docker containers are stopped with `docker stop` instead of signals.

### Logs & shell access

```sh
sonar logs 3000                   # tail logs (docker logs or discovered log files)
sonar attach 3000                 # shell into container or TCP connect
```

### Monitoring

```sh
sonar watch                       # poll every 2s, show port changes
sonar watch --interval 5s         # custom interval
sonar watch --diff                # show additions/removals with timestamps
sonar watch --notify              # desktop notifications on changes
sonar watch --stats               # live stats table
```

### Service graph

```sh
sonar graph                       # text graph of inter-service connections
sonar graph --json                # JSON format
sonar graph --dot                 # Graphviz DOT format
```

### Port forwarding

```sh
sonar map 6873 3002               # proxy traffic from :3002 to :6873
```

### Profiles

Snapshot your current port state and restore it later:

```sh
sonar profile create my-app       # save current ports as "my-app"
sonar profile list                # list saved profiles
sonar profile show my-app         # show profile details
sonar profile delete my-app       # remove a profile
sonar up my-app                   # check if profile ports are running
sonar down my-app                 # stop all ports in a profile
```

Profiles are stored as JSON under `~/.config/sonar/profiles/` (or the platform-appropriate config directory).

### Shell completions

```sh
sonar completion bash             # also: zsh, fish, powershell, elvish
```

## Platform support

| Platform | Scanner | Notes                                                          |
| -------- | ------- | -------------------------------------------------------------- |
| macOS    | `lsof`  | Desktop apps (Figma, Discord, Spotify, etc.) hidden by default |
| Linux    | `ss`    | Falls back gracefully when Docker is unavailable               |

Remote host scanning works over SSH, auto-detecting whether the remote uses `lsof` or `ss`.

## Docker integration

When Docker is available, sonar automatically enriches port data with:

- Container name and image
- Container port mappings
- Compose service and project names
- Container stats (CPU, memory) via `docker stats`
- Log tailing via `docker logs`
- Shell access via `docker exec`

## Differences from the Go version

- Single static binary with no runtime dependencies (beyond system tools)
- Built with Rust 2024 edition
- PID shown in default `list` output
- Uses `rustls` instead of system TLS for health checks

## Dependencies

Sonar relies on standard system tools at runtime:

- `lsof` (macOS) or `ss` (Linux) for port scanning
- `ps` for process stats
- `docker` (optional) for container enrichment
- `python3` for datetime parsing

## License

See [LICENSE](LICENSE) for details.
