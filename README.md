# infra-observer

Network Asset Discovery & Inventory tool.

## Purpose

`infra-observer` is a Linux CLI tool designed to monitor network exposure. Unlike ephemeral scanners, it persists scan results to a PostgreSQL database, builds a consolidated inventory (the latest known state per port), and performs strict drift detection to alert operators when a service changes, a new port opens, or a TLS certificate is about to expire.

## Capabilities

- **Smart Discovery:** Unprivileged ICMP (`udp4`) host discovery with TCP fallback.
- **Service Fingerprinting:** TCP connect scanning with passive banner grabbing and HTTP/HTTPS probing.
- **TLS Telemetry:** Extracts TLS cipher suites, SNI routing, SANs, and expiration warnings.
- **Stateful Inventory:** Embedded PostgreSQL migrations ensure seamless tracking of assets over time.
- **Drift Detection:** Compares scans to report exact infrastructure changes.
- **Automation Ready:** Supports `-audit` mode to emit exit codes on network drift, and `-json` for seamless `jq` integration..

## Requirements

- Linux/macOS environment.
- PostgreSQL 13+ database.

## Installation

### Option 1: Using Make (Recommended for Linux/macOS)
Clone the repository and install it globally:
```bash
git clone [https://github.com/diegoa18/infra-observer.git](https://github.com/diegoa18/infra-observer.git)
cd infra-observer
make build
sudo make install
```

### Option 2: Using Go Install
If you have Go installed, you can download and install the binary directly:
```bash
go install [github.com/diegoa18/infra-observer/cmd/infra-observer@latest](https://github.com/diegoa18/infra-observer/cmd/infra-observer@latest)
```

## Quick Start
1. Export your database credentials (the schema initializes automatically):
```bash
export DATABASE_URL="postgres://user:password@127.0.0.1:5432/infra_observer?sslmode=disable"
```
2. Scan a target and store the results:
```bash
infra-observer scan -store -probe -p 22,80,443 192.168.1.0/24
```
3. View your consolidated infrastructure inventory:
```bash
infra-observer inventory
```
4. Audit changes (Drift Detection):
```bash
infra-observer changes 192.168.1.10
```
