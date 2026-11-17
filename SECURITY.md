# Security policy

## Supported versions

| Version | Supported |
|---|---|
| 0.1.x | ✅ |

## Reporting a vulnerability

Please **do not open a public issue** for security problems.

Report privately through GitHub's
[private vulnerability reporting](https://github.com/Muath-into-AI/IOC-AI/security/advisories/new)
(Security tab → "Report a vulnerability"). Include:

- a description of the issue and its impact,
- steps to reproduce or a proof of concept,
- the affected version / commit.

You should get an acknowledgement within 7 days. Once a fix is ready it will be released
and credited to you (unless you prefer to stay anonymous).

## Scope

In scope: bugs in ioc-enrich itself — for example, leaking API keys, sending IOCs to
an unconfigured destination, unsafe handling of input files or API responses.

Out of scope: vulnerabilities in the third-party threat-intel services; report those to
the service provider.

## Handling API keys

Never include real API keys in issues, pull requests, logs or test fixtures. If you
accidentally expose a key, revoke it with the provider immediately.
