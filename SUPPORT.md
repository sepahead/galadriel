# Support policy

## Abbreviations

| Short form | Meaning |
|---|---|
| SLA | service-level agreement |

Galadriel 0.9.0 is a research source release.
Sepehr Mahmoudian is the maintainer and release author.

**GLD-090-META-001:** General reproducible defects **SHALL** use the GitHub issue tracker.
Each report **SHALL** include the exact commit, platform, Rust toolchain, command, and configuration.
It **SHALL** include a minimal reproducer that contains no sensitive data.
Use GitHub Discussions for questions when that feature is available.

**GLD-090-META-002:** Suspected security vulnerabilities **SHALL NOT** use public issues.
Use the repository's private GitHub Security Advisory channel or the address in `SECURITY.md`.

There is no production support SLA.
There is also no uptime, compatibility, remediation-time, or response-time SLA.
The maintainer targets a three-business-day acknowledgment for private security reports.
This target is a best-effort research commitment.

The 0.9.x stable-source policy applies only to `galadriel-core`.
`docs/API-SURFACE.md` defines this policy. It is not an operational maintenance promise.
