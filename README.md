# Server Security Healthcheck

Current development version: `v0.3.0`

Standalone, modular security healthcheck for Linux servers.

## Design goals

- independent configuration
- no dependency on another product's credentials or config
- modular checks under `lib/checks/`
- pluggable notifications
- safe, read-only health monitoring
- suitable for redistribution through GitHub
- systemd timer scheduling
- explicit dependency checking

## Repository structure

```text
server-security-healthcheck/
├── bin/
│   └── server-security-healthcheck
├── config/
│   ├── healthcheck.conf.example
│   └── telegram.conf.example
├── docs/
│   ├── ARCHITECTURE.md
│   └── MODULES.md
├── lib/
│   ├── common.sh
│   ├── checks/
│   │   ├── apache.sh
│   │   ├── clamav.sh
│   │   ├── disk.sh
│   │   ├── exim.sh
│   │   ├── lmd.sh
│   │   ├── pureftpd.sh
│   │   └── rspamd.sh
│   └── notify/
│       └── telegram.sh
├── systemd/
│   ├── server-security-healthcheck.service
│   └── server-security-healthcheck.timer
├── install-dependencies.sh
├── install.sh
├── uninstall.sh
├── LICENSE
└── README.md
```

## Checks

### Apache
- verifies Apache/httpd service is active

### ClamAV
- verifies ClamAV service
- checks malware database freshness

### Disk
- checks configured filesystems against a warning threshold

### Exim
- verifies Exim service
- checks queue size

### LMD
- verifies LMD service
- verifies inotify realtime monitoring
- checks recent `threat_detected`
- checks recent `alert_failed`
- checks LMD signature freshness
- compares DirectAdmin webroots with the LMD monitor list
- checks age of last full webroot scan

### PureFTP
- verifies PureFTP upload scan service

### Rspamd
- verifies Rspamd service

## Dependencies

Required project dependencies:

- Bash 4+
- coreutils
- grep
- sed
- awk
- findutils
- util-linux
- procps
- curl
- systemd

Optional software such as LMD, Exim, ClamAV, DirectAdmin, Apache or Rspamd
is only required when the corresponding check is enabled.

## Installation

```bash
sudo ./install-dependencies.sh
sudo ./install.sh
```

Configure:

```bash
sudo nano /etc/server-security-healthcheck/healthcheck.conf
sudo nano /etc/server-security-healthcheck/telegram.conf
sudo chmod 600 /etc/server-security-healthcheck/telegram.conf
```

Test notification:

```bash
sudo server-security-healthcheck --test-notification
```

Run all enabled checks:

```bash
sudo server-security-healthcheck
```

Show available modules:

```bash
sudo server-security-healthcheck --list-checks
```

Enable the timer:

```bash
sudo systemctl enable --now server-security-healthcheck.timer
```

## Exit codes

- `0`: all enabled checks healthy
- `1`: one or more problems found
- `2`: application/configuration error

## Security

The healthcheck is intentionally observational. It does not:

- restart services
- quarantine malware
- delete files
- alter firewall rules
- install updates
- modify service configuration

Telegram credentials are stored separately in:

```text
/etc/server-security-healthcheck/telegram.conf
```

Use:

```bash
chmod 600 /etc/server-security-healthcheck/telegram.conf
```

Telegram messages are plain text to avoid Markdown parsing failures caused by
paths, hostnames, signatures or filenames.
