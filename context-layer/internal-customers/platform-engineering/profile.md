---
Last Verified: 2026-03-09
Verified By: Cyber Defense Team
Status: Active
---

# Platform Engineering — Security Customer Profile

## Team Overview

Platform Engineering owns the core logistics SaaS platform: routing engine, dispatch services, real-time tracking, customer portal, billing integration, and the APIs that logistics customers depend on for daily operations.

## Criticality

**Tier 1** — Revenue-generating, customer-facing. Outage or breach directly impacts customers, SLAs, and revenue. This team's services are the product.

## Ownership

### Services & Systems
- Routing engine (route optimization, ETA calculation)
- Dispatch service (driver assignment, load matching)
- Real-time tracking (GPS ingestion, event streaming)
- Customer portal (shipment visibility, document management)
- Billing and invoicing service
- Platform API gateway (REST + GraphQL, serving 200+ logistics customers)
- PostgreSQL clusters (shipment data, customer records)
- Kafka event streams (shipment events, tracking updates)

### Key Repositories
- `logistics-platform-core`
- `routing-engine`
- `dispatch-service`
- `tracking-service`
- `customer-portal`
- `platform-api-gateway`

## Data Classification

| Data Type | Classification | Notes |
|-----------|---------------|-------|
| Customer PII | **Confidential** | Names, addresses, contact info, business details |
| Shipment data | **Confidential** | Origin/destination, contents, timing, pricing |
| Financial transactions | **Restricted** | Payment processing, invoicing, billing records |
| GPS/tracking data | **Confidential** | Real-time location of vehicles and shipments |
| API keys/tokens | **Restricted** | Customer API credentials for platform access |

## Regulatory Exposure

- **SOC 2 Type II** — Platform controls audited annually
- **PCI-DSS** — Payment processing flow (billing service)
- **GDPR** — EU customer data, right to deletion, data residency
- **CCPA** — California customer data protection

## Key Contacts

| Role | Name | Contact |
|------|------|---------|
| VP Engineering | TBD | |
| Engineering Manager | TBD | |
| Tech Lead | TBD | |
| On-Call Rotation | | `#platform-oncall` in Slack |

## What Security Success Means to This Team

- Zero customer-impacting security incidents
- Vulnerability remediation integrated into CI/CD (no separate "security sprint")
- Compliance certifications (SOC 2, PCI) maintained without heroics
- Security doesn't slow down shipping — fast, clear, actionable findings
- Confidence that customer data is protected at rest and in transit
