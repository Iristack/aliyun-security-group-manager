# Security Group Manager
#### [简体中文](/README_zh.md) | English

A lightweight daemon that monitors your host's public IPv4 address and automatically
synchronizes Aliyun ECS security group rules whenever the address changes.

## Features

- Polls public IP at a configurable interval and detects changes
- Batch-syncs security group rules via a single Aliyun API call per direction
- Supports both `allow` (accept) and `drop` policies per rule
- Covers `ingress`, `egress`, and `all` (both directions simultaneously) rule groups
- Automatically removes stale SGM-managed rules that no longer appear in config
- Plugin-based IP detection — ships with two plugins, easily extensible
- Environment variable overrides for credentials (CI/CD and container friendly)
- SQLite-backed IP change history with a CLI viewer
- Rotating log files with platform-appropriate paths

## Requirements

- Python 3.11 or later
- [uv](https://docs.astral.sh/uv/) (recommended) or pip
- `dig` command available in PATH (required by the `DigFromMyIpOpenDns` plugin only)

## Installation

### From source using uv

```bash
git clone https://github.com/your-org/SecurityGroupManager.git
cd SecurityGroupManager
uv sync
```

### Install as a package

```bash
uv pip install .
```

After installation the `sgm` command is available in your environment.

## Configuration

Copy or edit `cfg/sgm.yaml`:

```yaml
plugins:
  ipv4:
    - DigFromMyIpOpenDns   # tries plugins in order; first valid IPv4 wins
    - SocketTrick

interval: 60              # polling interval in seconds (5 – 86400)

aliyun:
  ak: YOUR_ACCESS_KEY_ID
  sk: YOUR_ACCESS_KEY_SECRET

securityGroup:
  - id: sg-xxxxxxxxxxxxxxxx
    region: cn-hangzhou
    ingress:
      allow:
        - proto: tcp
          port: 22
        - proto: tcp
          port: 443
      drop:
        - proto: tcp
          port: 8080
    egress:
      allow:
        - proto: tcp
          port: 80
    all:                  # applied to both ingress and egress
      allow:
        - proto: icmp
          port: 1
```

### Direction keys

| Key       | Applied to              |
|-----------|-------------------------|
| `ingress` | Inbound rules only      |
| `egress`  | Outbound rules only     |
| `all`     | Both inbound and outbound |

### Policy keys

| Key     | Aliyun policy |
|---------|---------------|
| `allow` | `accept`      |
| `drop`  | `drop`        |

### Rule identification

Every rule created by SGM is tagged with `description: "SGM auto managed"`.
Rules without this description are never touched.

## Environment Variable Overrides

Credentials and interval can be supplied via environment variables, which take
precedence over values in the YAML file.

| Variable        | Config path    |
|-----------------|----------------|
| `SGM_ALIYUN_AK` | `aliyun.ak`    |
| `SGM_ALIYUN_SK` | `aliyun.sk`    |
| `SGM_INTERVAL`  | `interval`     |

Example:

```bash
export SGM_ALIYUN_AK=LTAI5xxxxxx
export SGM_ALIYUN_SK=xxxxxxxxxxxxxxxxxxxxxx
sgm run
```

## CLI Usage

```
sgm [OPTIONS] COMMAND [ARGS]

Commands:
  run      Start the IP monitor daemon
  check    Run a single IP check and display result
  history  Show IP change history
```

### run

```bash
# Start daemon with default config
sgm run

# Use a custom config file
sgm run -c /etc/sgm/sgm.yaml

# Run once and exit (useful for cron/systemd oneshot)
sgm run --once

# Enable debug logging
sgm run -v
```

### check

```bash
# Print current public IP and sync if changed
sgm check
```

### history

```bash
# Show last 10 IP changes (default)
sgm history

# Show last 50 changes
sgm history -n 50
```

### version

```bash
sgm --version
```

## Log Files

| Platform | Path                              |
|----------|-----------------------------------|
| Linux    | `/var/log/sgm/sgm.log`            |
| macOS    | `~/Library/Logs/sgm/sgm.log`      |
| Windows  | `%USERPROFILE%\AppData\Local\sgm\sgm.log` |

Logs rotate at 10 MB with up to 5 backup files.

## Sync Logic

For each security group on every IP change, SGM executes at most four API calls:

1. Batch-revoke old-IP rules (ingress)
2. Batch-revoke old-IP rules (egress)
3. Batch-authorize new-IP rules (ingress)
4. Batch-authorize new-IP rules (egress)
5. Describe current rules and batch-revoke any surviving SGM-managed rules not
   present in the current configuration (stale rule cleanup)

## Built-in Plugins

### DigFromMyIpOpenDns

Queries `myip.opendns.com` via `dig` against the OpenDNS resolver.
Requires the `dig` binary (`dnsutils` / `bind-tools` package).

### SocketTrick

Opens a UDP socket toward `8.8.8.8:80` and reads the local address the OS
selected for routing. Works without any external command, but returns the
local routing IP rather than the actual public IP (accurate on most setups
without NAT layers).

## Writing a Custom Plugin

1. Create a Python file inside the `plugins/` directory.
2. Subclass `IpFetcherPlugin` and implement `name` and `fetch`.
3. Add the class name to `plugins.ipv4` in `sgm.yaml`.

```python
# plugins/my_plugin.py
import urllib.request
from ip_fetcher_plugin import IpFetcherPlugin

class MyPlugin(IpFetcherPlugin):

    @property
    def name(self) -> str:
        return "MyPlugin"

    def fetch(self) -> str | None:
        try:
            with urllib.request.urlopen("https://api4.ipify.org", timeout=5) as r:
                return r.read().decode().strip()
        except Exception as e:
            self.logger.error("MyPlugin error: %s", e)
            return None
```

```yaml
plugins:
  ipv4:
    - MyPlugin
    - DigFromMyIpOpenDns   # fallback
```

Plugins are tried in order; the first one that returns a valid IPv4 address wins.

## Running as a systemd Service

```ini
[Unit]
Description=Security Group Manager
After=network-online.target
Wants=network-online.target

[Service]
Type=simple
EnvironmentFile=/etc/sgm/env
ExecStart=/usr/local/bin/sgm run -c /etc/sgm/sgm.yaml
Restart=on-failure
RestartSec=10

[Install]
WantedBy=multi-user.target
```

`/etc/sgm/env`:

```
SGM_ALIYUN_AK=LTAI5xxxxxx
SGM_ALIYUN_SK=xxxxxxxxxxxxxxxxxxxxxx
```

## Development

```bash
# Install dev dependencies
uv sync --extra dev

# Run tests
uv run pytest

# Lint
uv run ruff check .

# Type check
uv run mypy .
```

## License

MIT
