# Security Policy

VMGA is security-sensitive software, but this repository is not yet claiming a
stable production security boundary.

## Reporting

Use GitHub Private Vulnerability Reporting for this repository:

https://github.com/AlderlineSystems/vmga/security/advisories/new

Do not include live Gmail tokens, approval secrets, OAuth client JSON, or
private mailbox contents in reports. If evidence requires sensitive material,
describe the shape of the issue first and coordinate a minimal redacted
reproducer through the private advisory.

## Scope

In scope:

- Proposal, approval, execution, and evidence integrity issues.
- Bypass paths in the VMGA control flow.
- Secret exposure in examples, packaging, or documentation.
- Misleading security claims in docs.

Out of scope:

- Host compromise.
- Prompt-injection prevention claims VMGA does not make.
- Gmail, Hermes, OpenClaw, or Google OAuth vulnerabilities outside the VMGA
  integration boundary.
