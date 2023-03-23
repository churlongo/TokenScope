# Security Policy

## Supported versions

| Version | Supported |
|---|---|
| 1.x | yes |
| < 1.0 | no |

## Reporting a vulnerability

Report suspected vulnerabilities privately to [MAINTAINER CONTACT]. Do not open
a public issue for a security problem. Include the version, the input that
triggers the issue, and the observed output. You will get a response within
seven days.

## Scope

TokenScope is an offline analysis tool. It reads local files and never opens a
socket, resolves a name, or makes an HTTP request. The realistic security
surface is therefore narrow: malformed input that causes a crash, a hang, or
unbounded memory use while parsing a hostile file.
