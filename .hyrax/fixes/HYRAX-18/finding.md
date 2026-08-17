# `reportlab` upper-bound pins out the current stable major (5.x excluded)

**Tool:** `deps`
**Severity:** medium
**Category:** operations
**Location:** `requirements.txt:7`

## What's wrong

The constraint `reportlab>=4.2,<5` permanently excludes `reportlab` 5.0.0, which is the current stable release as of the audit. The project is locked to the `4.x` line, which will receive no further feature development and will eventually lose security patches.

Because `reportlab` is used to generate deployment forms (OF-286, OF-288, SF-261 PDFs) and the constraint is a hard upper bound, any new install resolves to the last 4.x release (`4.5.1`) even though 5.0.0 is available. This also blocks automated tools like Dependabot from proposing the upgrade.

## What changed

Verify compatibility with `reportlab` 5.x (the changelog indicates a PDF-generation API cleanup). If no breaking changes affect the app's usage:

1. Widen the constraint to `reportlab>=4.2,<6` (or drop the upper bound).
2. Test PDF generation in a staging environment.
3. Regenerate the lockfile after updating the constraint.
