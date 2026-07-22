# Alpha Monitoring: Dashboards and Alerting

Operational observability configuration for the continuous Testnet11 Alpha.
This document defines the metrics, dashboard panels, and alert rules that
must be instrumented before opening public writes.

## 1. Health and Availability

### Dashboard Panels
- **API health** — `/health` response code and latency (p50/p95/p99).
- **Uptime** — systemd unit `solslot-api-staging.service` active state.
- **Artifact integrity** — signed V2 artifact hash match (boolean gauge).
- **Write-mode flag** — current state of `alpha_writes_enabled`, `minting_writes_enabled`, `payment_omnichain_enabled`.
- **Active connections** — concurrent HTTP connections (uvicorn workers).

### Alert Rules
| Rule | Condition | Severity |
|------|-----------|----------|
| API health failure | `/health` returns non-200 for > 60s | critical |
| Artifact drift | computed artifact hash ≠ frozen artifact hash | critical |
| Unexpected write enablement | `minting_writes_enabled` or `payment_omnichain_enabled` transitions to `true` outside maintenance window | high |
| High error rate | HTTP 5xx rate > 5% over 5 min | high |
| Latency spike | p95 latency > 2s over 5 min | medium |

## 2. Payment Pipeline

### Dashboard Panels
- **Pending payment age** — histogram of `(now - created_at)` for non-terminal payments, grouped by rail (XCH/Base USDC/Voucher).
- **Payment funnel** — counts per state: `RequestSent` → `VoucherIssued` / `SettledSuccess` / `SettledRefund` / `EmergencyRefund`.
- **Voucher series inventory** — per-series: sold, active, refunded, redeemed, remaining.
- **CCIP/Warp message status** — `Queued` / `WarpSent` / `ResultQueued` / `ResultSent` counts.
- **Base gateway fee balance** — current ETH/LINK balance of gateway contract.
- **Reconciliation delta** — difference between spoke USDC balance and sum of non-terminal deposit amounts.

### Alert Rules
| Rule | Condition | Severity |
|------|-----------|----------|
| Stale pending payment | any payment in non-terminal state > 30 min | high |
| Payment mismatch | reconciliation delta ≠ 0 | critical |
| Fee treasury low | gateway ETH balance < 0.05 ETH | high |
| CCIP/Warp failure spike | > 3 failed messages in 15 min | high |
| Voucher solvency drift | sum of active voucher USDC ≠ spoke voucher USDC hold | critical |

## 3. Validator and Bridge

### Dashboard Panels
- **Validator quorum** — number of reachable validators (target: 2 of 3).
- **Bridge inventory** — pending Warp messages, KoS checkout queue depth.
- **Samuel coordinator status** — last heartbeat, pending checkouts.
- **KoS fulfillment rate** — successful vs failed fulfillments per hour.

### Alert Rules
| Rule | Condition | Severity |
|------|-----------|----------|
| Quorum loss | < 2 validators reachable for > 2 min | critical |
| Bridge queue depth | > 10 pending Warp messages for > 10 min | high |
| KoS failure | any KoS fulfillment failure | high |
| Validator heartbeat | any validator silent > 5 min | medium |

## 4. Identity and Credential

### Dashboard Panels
- **zkPassport stamp rate** — successful vs failed attestations per hour.
- **Vault registration rate** — new vaults per hour.
- **Forgery attempts** — rejected stamps with invalid nullifiers, wrong chain, replayed events.

### Alert Rules
| Rule | Condition | Severity |
|------|-----------|----------|
| Forgery spike | > 5 rejected attestation attempts in 10 min | high |
| Stamp failure rate | > 20% failure rate over 15 min | medium |

## 5. Telemetry and User Reports

### Dashboard Panels
- **Active Alpha users** — unique pseudonymous IDs per hour (from `/alpha/telemetry`).
- **Bug report volume** — reports per hour, with/without diagnostics.
- **Error class distribution** — top error categories from telemetry events.
- **Session funnel** — app-open → wallet-connect → vault-register → purchase-attempt → purchase-complete.

### Alert Rules
| Rule | Condition | Severity |
|------|-----------|----------|
| Bug report spike | > 10 reports in 30 min | medium |
| Zero active users | no telemetry events for > 1 hour during expected active period | medium |

## 6. Rate Limiting and Security

### Dashboard Panels
- **429 rate** — throttled requests per minute, by IP prefix.
- **401/403 rate** — unauthorized/forbidden responses per minute.
- **CORS rejection rate** — blocked origin attempts.
- **Challenge quota usage** — SQLite-WAL quota fill percentage.

### Alert Rules
| Rule | Condition | Severity |
|------|-----------|----------|
| 429 saturation | > 50% of requests throttled over 5 min | medium |
| Credential brute force | > 20 failed auth attempts from same IP in 5 min | high |
| WAL quota exhaustion | quota fill > 90% | medium |

## 7. Infrastructure

### Dashboard Panels
- **Disk usage** — SQLite DB size, telemetry/bug-report storage, log volume.
- **Memory/CPU** — API process resource utilization.
- **Certificate expiry** — days until TLS certificate renewal.
- **Backup freshness** — time since last successful backup.

### Alert Rules
| Rule | Condition | Severity |
|------|-----------|----------|
| Disk > 85% | root or data partition > 85% full | high |
| Backup stale | no successful backup in > 24 hours | high |
| Certificate expiry | < 14 days until TLS expiry | medium |
| OOM risk | process RSS > 80% of available memory | high |

## Implementation Notes

- **Metrics source**: API logs (structured JSON), SQLite queries, systemd status, chain RPC polling.
- **Scraping**: Prometheus-compatible `/metrics` endpoint or log-based extraction.
- **Alerting channel**: Ops channel (Discord/Slack webhook) + admin email for critical.
- **Retention**: Dashboard data retained for Alpha duration; alert history preserved with incident records.
- **Privacy**: No PII in metrics; pseudonymous telemetry IDs only; no wallet addresses in dashboards.
