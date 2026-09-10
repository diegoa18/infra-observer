# infra-observer

Network Asset Discovery & Inventory

## Purpose

infra-observer is a Linux CLI for discovering network hosts and identifying
accessible TCP services.

The project is being developed toward persistent infrastructure inventory,
historical observations, and network change detection.

## Current capabilities

- IPv4 address, CIDR, and hostname targets
- ICMP host discovery
- TCP-based host discovery fallback
- TCP connect service discovery
- Passive banner retrieval for common protocols
- HTTP/HTTPS probing
- Concurrent port scanning
- Human-readable CLI output

## Current limitations

- No persistent inventory yet
- No historical observations yet
- No change detection yet
- No PostgreSQL integration yet
- IPv4 only
