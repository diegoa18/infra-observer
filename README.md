# infra-observer

Network Asset Discovery & Inventory

## Purpose

infra-observer is a Linux CLI for discovering network hosts, identifying accessible TCP services, and maintaining a persistent infrastructure inventory.

The project tracks historical observations and detects network infrastructure changes over time to provide the latest known state per port.

## Current capabilities

- IPv4 address, CIDR, and hostname targets
- ICMP host discovery with TCP fallback
- Concurrent TCP connect service discovery
- Passive banner retrieval for common protocols
- HTTP/HTTPS probing
- PostgreSQL integration for persistent observations
- Historical tracking of network states
- Change detection between scans
- Consolidated inventory showing the latest known state per port
- Human-readable CLI output

## Requirements

- PostgreSQL database
- `DATABASE_URL` environment variable exported (e.g., `postgres://user:pass@127.0.0.1:5432/infra_observer?sslmode=disable`)

## Current limitations

- IPv4 only
