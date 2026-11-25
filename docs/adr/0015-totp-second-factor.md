# ADR 0015: Optional TOTP second factor (off by default), managed on the host

Status: Accepted; refines ADR 0002

## Context
The instance is going public with one operator and one password. ADR 0002 slows guessing but cannot stop a
phished or reused password. Identity-provider sign-in is not available yet.

## Decision
Insight verifies standard six-digit RFC 6238 codes using HMAC-SHA1 and a 30-second time step, accepting one
step of clock drift in either direction. Code generation and verification use the Python standard library.
It is **off by default**, at the operator's choice. Two separate parts: *pairing* (`insight mfa setup` shows the
secret and saves it only after the operator types a matching code; that code's time step is recorded as used)
and the *switch* `INSIGHT_MFA=on|off` (default off). The Makefile's `mfa-enable` pairs if needed, sets the switch
and restarts; `mfa-disable` clears the switch and keeps the pairing. With the switch on and nothing paired,
sign-in is refused rather than silently password-only; an invalid switch value stops start-up. Sign-in checks the password first and the code only if the password is correct,
in the same serialised, delayed check as ADR 0002, with one message for either mistake. Each accepted code, and
anything older, is refused afterwards. There are no recovery codes: turning the switch off (`make mfa-disable`)
and `insight mfa reset` on the host are the recovery path, the same root of trust as API key management (ADR 0012).

## Consequences
Verifying codes requires access to the original pairing secret. Insight uses the hash-pinned
`cryptography` package to store it under AES-256-GCM, deriving a dedicated key from the existing
`INSIGHT_SESSION_SECRET` using HKDF-SHA256. Migration `0017` encrypts an existing pairing and preserves its
last accepted time step. Subsequent sign-ins continue to reject previously used codes.

Operators restoring an encrypted pairing need the corresponding session secret. Deliberately rotating
that secret requires a fresh pairing. A pre-`0017` database backup may contain the plaintext seed.
Protect older copies according to the same retention policy as other credentials.
[Operator recovery procedure](../RUNBOOK.md#sign-in-second-factor-mfa)

A stolen password alone no longer signs in when MFA is on. Excessive clock drift can break sign-in
until the clocks are synchronized. While MFA is off, the password alone protects sign-in.
