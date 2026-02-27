# cctv-diag — Camera Box Diagnostic Tool

Version 1.0.0 | Bash | Read-only | No internet required (WAN checks optional)

---

## Overview

`cctv-diag.sh` is a redeployable, on-demand diagnostic script for CCTV server
(Camera Box) units. It performs a comprehensive, read-only health check and
produces:

- A **colour-coded console report** (GREEN / AMBER / RED traffic-light system)
- A **machine-readable JSON file**
- A **shareable `.tar.gz` support bundle** containing the report, JSON, command
  outputs, sanitised log excerpts, and a manifest

---

## Prerequisites

| Requirement | Notes |
|---|---|
| Bash ≥ 4.0 | Ships with Ubuntu 18.04+ |
| `ip`, `ss`, `ping` | iproute2 (standard) |
| `systemctl` | systemd-based systems |
| `df`, `mount`, `dmesg` | Standard coreutils |
| `curl` *(optional)* | For HTTP WAN checks |
| `smartctl` *(optional)* | `apt install smartmontools` for SMART checks |
| `timeshift` *(optional)* | Only needed for Timeshift section |
| `tailscale` *(optional)* | Only for Tailscale section |
| `ufw` *(optional)* | Only for UFW section |

> **Root is preferred** but not required. Non-root runs will skip write-permission
> checks on storage and SMART queries; all other checks still run.

---

## Installation

```bash
# Download / copy script
sudo cp cctv-diag.sh /usr/local/bin/cctv-diag
sudo chmod +x /usr/local/bin/cctv-diag

# Optional: create config file
sudo cp cctv-diag.conf.example /etc/cctv-diag.conf
```

---

## Usage

```bash
# Minimal — auto-detect BOX_ID, normal mode, bundle saved to /tmp
sudo cctv-diag

# Specify BOX_ID explicitly
sudo cctv-diag --box-id 42

# Quick scan (fast, less log extraction)
sudo cctv-diag --quick --box-id 42

# Full scan (extended WAN latency, more logs)
sudo cctv-diag --full --box-id 42

# Custom time window and output directory
sudo cctv-diag --since 48h --output-dir /var/support-bundles

# Assert expected configuration
sudo cctv-diag \
  --box-id 7 \
  --expected-hostname cctv-box07 \
  --expected-ip 192.168.7.10 \
  --expected-ufw-state enabled \
  --expected-nx-ports "7001,7002,7004" \
  --require-tailscale

# No bundle (report + JSON only)
sudo cctv-diag --no-bundle --box-id 5

# Logs from a specific date
sudo cctv-diag --since 2024-11-01 --box-id 12
```

---

## CLI Reference

| Flag | Default | Description |
|---|---|---|
| `--quick` | — | Fast mode: skip extended log extraction |
| `--full` | — | Full mode: extended WAN latency test, more logs |
| `--since <window>` | `24h` | Log window: `24h`, `48h`, `7d`, or `YYYY-MM-DD` |
| `--output-dir <path>` | `/tmp` | Where to save the support bundle |
| `--bundle` / `--no-bundle` | bundle | Toggle `.tar.gz` creation |
| `--box-id <N>` | auto-detect | Camera box ID (1–250) |
| `--expected-hostname <name>` | — | Assert hostname matches |
| `--expected-ip <ipv4>` | — | Assert server IP matches |
| `--expected-ufw-state <state>` | — | `enabled` or `disabled` |
| `--expected-nx-ports <list>` | `7001,7002,7004` | Comma-separated NX listening ports |
| `--require-tailscale` | false | Treat Tailscale offline as RED |

---

## Config File `/etc/cctv-diag.conf`

```bash
# /etc/cctv-diag.conf — overrides built-in defaults
DISK_AMBER=85          # % disk usage → AMBER
DISK_RED=95            # % disk usage → RED
INODE_AMBER=80
INODE_RED=90
SNAP_AMBER_DAYS=14     # Days since last Timeshift snapshot → AMBER
SNAP_RED_DAYS=30       # Days since last Timeshift snapshot → RED
NX_PORTS="7001,7002,7004"
CMD_TIMEOUT=10
```

---

## Scheduling

### systemd Timer (recommended — biweekly)

```ini
# /etc/systemd/system/cctv-diag.service
[Unit]
Description=CCTV Camera Box Diagnostic
After=network-online.target

[Service]
Type=oneshot
ExecStart=/usr/local/bin/cctv-diag --output-dir /var/support-bundles --since 336h
User=root
```

```ini
# /etc/systemd/system/cctv-diag.timer
[Unit]
Description=Run CCTV diagnostic every two weeks

[Timer]
# Every 14 days from first activation
OnActiveSec=14d
OnUnitActiveSec=14d
Persistent=true

[Install]
WantedBy=timers.target
```

```bash
sudo systemctl daemon-reload
sudo systemctl enable --now cctv-diag.timer
sudo systemctl list-timers cctv-diag.timer
```

### Cron (fallback)

> Biweekly cron is awkward — cron has no native "every 14 days" interval.
> The cleanest workaround is to schedule weekly and use a state file to skip
> alternate runs, **or** simply run on the 1st and 15th of each month:

```cron
# Run on 1st and 15th of every month at 03:00
0 3 1,15 * * root /usr/local/bin/cctv-diag --output-dir /var/support-bundles >> /var/log/cctv-diag.log 2>&1
```

---

## Traffic Light Interpretation

### 🔴 RED — Immediate action required
These indicate failures that are likely causing service disruption right now:

| RED scenario | What to do |
|---|---|
| NX media server service down | `systemctl start networkoptix-mediaserver` then check logs |
| Recording storage not mounted/writable | Check `/etc/fstab`, run `mount -a`, check NFS/disk health |
| Filesystem I/O errors | Check SMART, consider emergency backup, plan disk replacement |
| Disk usage ≥ 95% | Delete old recordings or expand storage |
| No default route | Check network config, cable, DHCP lease |
| Router unreachable | Physical/ISP issue — check router power, modem, SIM |
| NTP out of sync >5 min | `systemctl restart systemd-timesyncd`, check NTP reachability |
| Tailscale offline (when `--require-tailscale`) | `tailscale up` — check auth token |

### 🟡 AMBER — Investigate soon
Not immediately breaking but needs attention:

| AMBER scenario | What to do |
|---|---|
| Disk usage 85–95% | Plan storage cleanup or expansion |
| Timeshift snapshot >14 days | Run `timeshift --create` manually, check timer |
| NTP unsynced but close | Check time server reachability from this box |
| UFW logging disabled | `ufw logging medium` |
| WAN intermittent loss | Check 4G/ISP signal and router status |
| BOX_ID auto-detect ambiguous | Rerun with explicit `--box-id` |

### 🟢 GREEN — Healthy
No action needed.

---

## Bundle Contents

```
cctv-diag_box42_20241115T030000Z.tar.gz
└── cctv-diag.XXXXXX/
    ├── MANIFEST.txt          — list of all collected files
    ├── report.txt            — full human-readable report
    ├── report.json           — machine-readable findings
    ├── commands/             — stdout from each diagnostic command
    │   ├── ip-addr.txt
    │   ├── ip-route.txt
    │   ├── df.txt
    │   ├── ufw-status.txt
    │   ├── tailscale-status.txt
    │   ├── tailscale_netcheck.txt
    │   ├── timeshift_list.txt
    │   ├── ping_router.txt
    │   ├── ping_wan_*.txt
    │   ├── smart_*.txt
    │   └── ...
    └── logs/
        ├── journal_errors.txt
        ├── nx_critical.txt
        ├── timeshift_errors.txt
        ├── ufw_blocks.txt
        ├── oom.txt
        └── ...
```

> **Security**: The bundle is automatically sanitised — lines matching
> `PRIVATE KEY`, `AUTH_KEY`, `SECRET`, `PASSWORD`, `TOKEN` are redacted before
> packaging. Never share bundles containing raw `/etc/shadow` or key material.

---

## Sample Quick Output

```
╔══════════════════════════════════════════════════════╗
║       CCTV Camera Box Diagnostic Tool v1.0.0         ║
╚══════════════════════════════════════════════════════╝
  Started: 2024-11-15T03:00:01Z
  Running as: root (root: true)
  Mode: quick  |  Since: 24h

══════════════════════════════════════════════════════
  BOX ID & SUBNET DETECTION
══════════════════════════════════════════════════════
[GREEN] BOX_ID: Auto-detected BOX_ID=42 (subnet 192.168.42.0/24)
  BOX_ID=42  |  Subnet=192.168.42.0/24  |  Router=192.168.42.1

══════════════════════════════════════════════════════
  NETWORKING
══════════════════════════════════════════════════════
[GREEN] Subnet-check: Server has IP 192.168.42.10 in 192.168.42.0/24
[GREEN] Default-route: Default gateway: 192.168.42.1
[GREEN] Gateway-match: Default GW matches ROUTER_IP=192.168.42.1
[GREEN] Link[eth0]: UP
[GREEN] Link[tailscale0]: UP

══════════════════════════════════════════════════════
  ROUTER / WAN HEALTH
══════════════════════════════════════════════════════
[GREEN] Router-ping: 192.168.42.1 reachable (avg 2.3ms)
[GREEN] Router-ARP: ARP entry: 192.168.42.1 dev eth0 lladdr aa:bb:cc:dd:ee:ff REACHABLE
[GREEN] WAN-DNS: google.com resolves OK
[GREEN] WAN-ping[8.8.8.8]: Reachable (avg 18ms)
[GREEN] WAN-HTTP: http://detectportal.firefox.com/success.txt → HTTP 200

══════════════════════════════════════════════════════
  STORAGE
══════════════════════════════════════════════════════
[AMBER] Disk[/mnt/nx]: 88% used (>=85% threshold)
[GREEN] Disk[/]: 41% used
[GREEN] NX-storage[/mnt/nx]: Mounted and writable
[GREEN] FS-errors: No filesystem error patterns in dmesg

══════════════════════════════════════════════════════
  WITNESS NX (NETWORK OPTIX)
══════════════════════════════════════════════════════
[GREEN] NX-package: Installed: networkoptix-mediaserver v5.1.0.35151
[GREEN] NX-service: networkoptix-mediaserver.service is running
[GREEN] NX-port[7001]: Listening
[GREEN] NX-port[7002]: Listening
[AMBER] NX-port[7004]: NOT listening on port 7004
[GREEN] NX-process: Process found

══════════════════════════════════════════════════════
  DIAGNOSTIC SUMMARY
══════════════════════════════════════════════════════
  Timestamp : 2024-11-15T03:00:01Z
  Hostname  : cctv-box42
  BOX_ID    : 42
  Router IP : 192.168.42.1

  RED  : 0   AMBER: 2   GREEN: 22

  TOP ACTIONS RECOMMENDED:
    1. [AMBER] Disk[/mnt/nx]: 88% used — plan storage cleanup
    2. [AMBER] NX-port[7004]: NOT listening — check NX config

📦 Support bundle: /tmp/cctv-diag_box42_20241115T030001Z.tar.gz
   (48K compressed)
```

---

## Sample Full Output (additional sections)

```
══════════════════════════════════════════════════════
  ROUTER / WAN HEALTH
══════════════════════════════════════════════════════
── Extended latency test (30s) ──
[AMBER] WAN-latency-ext: Loss=8.3% avg_rtt=45ms — intermittent

══════════════════════════════════════════════════════
  TAILSCALE VPN
══════════════════════════════════════════════════════
[GREEN] Tailscale-daemon: tailscaled active
[GREEN] Tailscale-auth: Authenticated
[GREEN] Tailscale-IP: IPv4=100.64.42.10 IPv6=fd7a::1
[INFO ] Tailscale-peers: Peers visible: 4
[GREEN] Tailscale-netcheck: netcheck completed OK

══════════════════════════════════════════════════════
  TIMESHIFT
══════════════════════════════════════════════════════
[GREEN] Timeshift-age: Last snapshot: 2024-11-13 (2 days ago)
[INFO ] Timeshift-count: 8 snapshot(s) found
[GREEN] Timeshift-space: Snapshot device /dev/sdb1: 62% used

══════════════════════════════════════════════════════
  UFW FIREWALL
══════════════════════════════════════════════════════
[GREEN] UFW-state: UFW is enabled (as expected)
[GREEN] UFW-NX[7001]: UFW ALLOWS port 7001
[GREEN] UFW-NX[7002]: UFW ALLOWS port 7002
[GREEN] UFW-Tailscale: Tailscale interface tailscale0 allowed
[GREEN] UFW-logging: UFW logging: low
[INFO ] UFW-recent-blocks: 14 recent BLOCK entries in /var/log/ufw.log
```
