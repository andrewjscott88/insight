# ADR 0002: Sign-in throttling by delay, not lockout

Status: accepted (0.2.0); refined by [ADR 0012](0012-single-api-key-and-rate-limits.md) (invalid API keys are
throttled per client address the same way) and [ADR 0015](0015-totp-second-factor.md) (optional second factor)

## Context
0.1.0 locked every sign-in for a minute after 10 failures. Any local process could deny the operator access.
Per-IP limits do not help, because Docker's port proxy makes all clients appear from one address. Generated
passwords carry about 144 bits of entropy.

## Decision
Password checks run one at a time, each failure waits 1 s, and 30 failures per minute is a hard backstop.
Failures are logged (never the password).

## Consequences
Online guessing is slowed to about 1 attempt per second, and the operator can still sign in after a flood.
This is superseded by identity-provider sign-in at Milestone 3.
