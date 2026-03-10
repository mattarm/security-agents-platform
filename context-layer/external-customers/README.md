# External Customer Security Delivery

## Tiered Model

External customers receive security services based on their tier. Unlike internal customers (who get full context directories), external customers are served through **category-level templates** that define standard service commitments.

### Flagship (Dedicated Profiles)

Strategic customers who warrant their own context — those with specific contractual security obligations, direct CISO-to-CISO relationships, or where a security incident would be existential. Full artifact set, lighter than internal customers.

Flagship profiles live in `flagship/<company-name>/` with the same artifact structure as internal customers.

### Category Templates

All other external customers are served through standardized templates in `templates/`:

- **`supplier-partner.md`** — Third-party risk management, API security, data sharing controls
- **`enterprise-direct.md`** — Full enterprise security package with compliance reporting
- **`smb.md`** — Baseline security controls, shared infrastructure posture

These define **what the cyber defense team delivers to each category**, not per-customer context. When a customer's needs outgrow their template, they graduate to a flagship profile.
