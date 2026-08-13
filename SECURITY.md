# Security policy

## Reporting a vulnerability

Please use GitHub's private vulnerability reporting when it is enabled for the public repository. If it is unavailable, do not open a public issue containing sensitive details; use the repository owner's private contact channel shown on their GitHub profile until a dedicated security contact is published.

Include:

- affected version or commit;
- a minimal non-destructive reproduction;
- expected versus observed behavior;
- impact and any suggested remediation.

## Scanner safety promise

The supported static audit path must not import or execute target source. A report that target code ran during an audit is considered a security vulnerability.

## Scope

Security reports about parser safety, path traversal, unintended target execution, secret disclosure, unsafe output handling, or incorrect trust-boundary claims are in scope. Generic feature requests and expected false positives/negatives should use ordinary issues.
