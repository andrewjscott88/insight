# ADR 0002: Sign-in throttling by delay, not lockout

Status: accepted (0.2.0); refined by [ADR 0012](0012-single-api-key-and-rate-limits.md) (invalid API keys are
throttled per client address the same way) and [ADR 0015](0015-totp-second-factor.md) (optional second factor)

## Context
0.1.0 locked every sign-in for a minute after 10 failures. Any local process could deny the operator access.
Per-IP limits do not help, because Docker's port proxy makes all clients appear from one address. Generated
passwords carry about 144 bits of entropy.

## Decision
Password checks run one at a time, and each failure waits 1 s before it is answered. Failures are logged
(never the password). After 30 failures in a minute, wrong passwords are refused with `429`, still after the
delay; the right password (and code, with MFA) always signs in.

**Revised 2026-11-21 (code review M1).** Before, the backstop refused every sign-in once 30 failures were
counted, the right password included, and the delay ran while the check lock was held. Anyone who could reach
`/login` could keep the operator out with about 30 bad guesses a minute, and the operator's own attempt queued
behind every pending guess. Now the backstop only refuses wrong passwords, and the delay is served after the
lock is released.

## Consequences
The operator can always sign in, even during a flood, without waiting behind other clients' failures. The
trade-off: once the backstop is reached, guesses are no longer serialised to about one per second across all
clients; each wrong guess still costs its sender the 1 s delay, so the rate depends on how many connections an
attacker holds open. Limits per client address were considered and not added: behind Docker's port proxy every
client has the same address, so they would bring the lockout back. Generated passwords carry about 144 bits
of entropy, which no online guessing reaches; operators who choose their own password should use
`make env` or turn on MFA (`make mfa-enable`), which a guesser cannot pass without the authenticator app.
This is superseded by identity-provider sign-in at Milestone 3.
