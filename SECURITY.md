# Security policy

## Reporting a vulnerability

Please use GitHub's private vulnerability reporting for the repository. Do not open a public issue for a suspected vulnerability that could expose users.

Include:

- affected version or commit;
- a minimal non-destructive reproduction;
- expected versus observed behavior;
- impact and any suggested remediation.

## Scanner safety promise

The supported static audit path must not import or execute target source. A report that target code ran during an audit is considered a security vulnerability.

## Scope

Security reports about parser safety, path traversal, unintended target execution, secret disclosure, unsafe output handling, or incorrect trust-boundary claims are in scope. Generic feature requests and expected false positives/negatives should use ordinary issues.
