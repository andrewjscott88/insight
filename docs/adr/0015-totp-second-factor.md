# ADR 0015: Optional TOTP second factor (off by default), managed on the host

Status: accepted (unreleased); refines ADR 0002

## Context
The instance is going public with one operator and one password. ADR 0002 slows guessing but cannot stop a
phished or reused password. Identity-provider sign-in is not available yet.

## Decision
An optional TOTP second factor (RFC 6238: HMAC-SHA1, 6 digits, 30 s, ±1 step), implemented with the standard
library (no new dependency in the hash-pinned supply chain) and compatible with common authenticator apps.
It is **off by default**, at the operator's choice. Two separate parts: *pairing* (`insight mfa setup` shows the
secret and saves it only after the operator types a matching code; that code's time step is recorded as used)
and the *switch* `INSIGHT_MFA=on|off` (default off). The Makefile's `mfa-enable` pairs if needed, sets the switch
and restarts; `mfa-disable` clears the switch and keeps the pairing. With the switch on and nothing paired,
sign-in is refused rather than silently password-only; an invalid switch value stops start-up. Sign-in checks the password first and the code only if the password is correct,
in the same serialised, delayed check as ADR 0002, with one message for either mistake. Each accepted code, and
anything older, is refused afterwards. There are no recovery codes: turning the switch off (`make mfa-disable`)
and `insight mfa reset` on the host are the recovery path, the same root of trust as API key management (ADR 0012).

## Consequences
A stolen password alone no longer signs in. The TOTP secret is stored in the database in recoverable form, so
database backups must be protected like the password. Clock drift beyond ±30 s breaks sign-in until the clocks
are fixed (NTP). While MFA is off (the default), the password alone protects sign-in.
