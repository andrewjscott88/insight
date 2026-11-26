"""Token-bucket rate limiter, driven by a fake clock."""

from __future__ import annotations

import threading

import pytest

from insight.ratelimit import IOC_EXPORT, READ, Policy, RateLimiter

TEN_PER_MINUTE = Policy('test', 10, 60)


class Clock:
    def __init__(self) -> None:
        self.now = 1000.0

    def __call__(self) -> float:
        return self.now


@pytest.fixture
def clock() -> Clock:
    return Clock()


def test_allows_a_full_burst_then_refuses(clock: Clock) -> None:
    limiter = RateLimiter(clock)
    decisions = [limiter.hit('caller', TEN_PER_MINUTE) for _ in range(11)]
    assert [d.allowed for d in decisions] == [True] * 10 + [False]
    assert [d.remaining for d in decisions[:3]] == [9, 8, 7]
    refused = decisions[-1]
    assert refused.remaining == 0
    assert refused.retry_after == pytest.approx(6.0)  # one token every 6 s
    assert refused.reset_after == pytest.approx(60.0)


def test_refills_continuously(clock: Clock) -> None:
    limiter = RateLimiter(clock)
    for _ in range(10):
        limiter.hit('caller', TEN_PER_MINUTE)
    clock.now += 5.9
    assert not limiter.hit('caller', TEN_PER_MINUTE).allowed
    clock.now += 0.2
    assert limiter.hit('caller', TEN_PER_MINUTE).allowed
    clock.now += 3600
    assert limiter.hit('caller', TEN_PER_MINUTE).remaining == 9  # never refills beyond the limit


def test_a_clock_stepping_backwards_never_drains_a_bucket(clock: Clock) -> None:
    """Regression: a negative elapsed time subtracted tokens, locking a caller out for a long time."""
    limiter = RateLimiter(clock)
    limiter.hit('caller', TEN_PER_MINUTE)
    clock.now -= 5000
    decision = limiter.hit('caller', TEN_PER_MINUTE)
    assert decision.allowed
    assert decision.remaining == 8


def test_callers_and_policies_have_separate_buckets(clock: Clock) -> None:
    limiter = RateLimiter(clock)
    for _ in range(10):
        limiter.hit('script', TEN_PER_MINUTE)
    assert not limiter.hit('script', TEN_PER_MINUTE).allowed
    assert limiter.hit('operator', TEN_PER_MINUTE).allowed
    assert limiter.hit('script', Policy('other', 10, 60)).allowed


def test_refused_requests_do_not_consume_tokens(clock: Clock) -> None:
    limiter = RateLimiter(clock)
    for _ in range(50):
        limiter.hit('caller', TEN_PER_MINUTE)
    clock.now += 6.01
    assert limiter.hit('caller', TEN_PER_MINUTE).allowed  # hammering while refused does not extend the wait


def test_allows_looks_without_taking(clock: Clock) -> None:
    limiter = RateLimiter(clock)
    assert limiter.allows('caller', TEN_PER_MINUTE)
    assert limiter._buckets == {}, 'looking never creates a bucket'
    for _ in range(10):
        assert limiter.allows('caller', TEN_PER_MINUTE)
        limiter.hit('caller', TEN_PER_MINUTE)
    assert not limiter.allows('caller', TEN_PER_MINUTE)
    assert limiter.allows('other', TEN_PER_MINUTE)
    clock.now += 6.1
    assert limiter.allows('caller', TEN_PER_MINUTE)
    assert limiter.allows('caller', TEN_PER_MINUTE), 'still there: allows took nothing'
    assert not limiter.allows('caller', TEN_PER_MINUTE, cost=2)


def test_cost_takes_several_tokens(clock: Clock) -> None:
    limiter = RateLimiter(clock)
    assert limiter.hit('caller', TEN_PER_MINUTE, cost=7).remaining == 3
    refused = limiter.hit('caller', TEN_PER_MINUTE, cost=7)
    assert not refused.allowed
    assert refused.retry_after == pytest.approx(24.0)


def test_headers(clock: Clock) -> None:
    limiter = RateLimiter(clock)
    allowed = limiter.hit('caller', READ)
    assert allowed.headers() == {'RateLimit-Policy': '"read";q=300;w=60', 'RateLimit': '"read";r=299;t=1'}
    for _ in range(30):
        limiter.hit('caller', IOC_EXPORT)
    refused = limiter.hit('caller', IOC_EXPORT).headers()
    assert refused['RateLimit-Policy'] == '"ioc-export";q=30;w=3600'
    assert refused['RateLimit'] == '"ioc-export";r=0;t=3600'
    assert refused['Retry-After'] == '120'


def test_retry_after_is_at_least_one_second(clock: Clock) -> None:
    limiter = RateLimiter(clock)
    fast = Policy('fast', 1000, 1)
    for _ in range(1000):
        limiter.hit('caller', fast)
    assert limiter.hit('caller', fast).headers()['Retry-After'] == '1'


def test_memory_is_bounded_without_forgetting_partly_used_buckets(clock: Clock) -> None:
    limiter = RateLimiter(clock, max_buckets=4)
    for _ in range(30):
        limiter.hit('victim', IOC_EXPORT)  # empty bucket, refills over an hour
    for n in range(3):
        limiter.hit(f'idle-{n}', TEN_PER_MINUTE)  # one token used: full again after 6 s
    assert len(limiter._buckets) == 4
    clock.now += 120  # long enough for the idle buckets to refill, far too short for the export bucket
    limiter.hit('newcomer', TEN_PER_MINUTE)  # at capacity: triggers pruning
    assert {caller for _, caller in limiter._buckets} == {'victim', 'newcomer'}
    # Remembered: 120 s refilled one token (one per 120 s). A forgotten bucket would be full again (29 left).
    assert limiter.hit('victim', IOC_EXPORT).remaining == 0


def test_least_recently_used_half_is_dropped_when_nothing_has_refilled(clock: Clock) -> None:
    limiter = RateLimiter(clock, max_buckets=4)
    for n in range(4):
        clock.now += 1
        limiter.hit(f'c{n}', TEN_PER_MINUTE)
    limiter.hit('c4', TEN_PER_MINUTE)
    assert {caller for _, caller in limiter._buckets} == {'c2', 'c3', 'c4'}


def test_thread_safety() -> None:
    limiter = RateLimiter(lambda: 0.0)  # frozen clock: exactly `limit` requests may ever pass
    policy = Policy('threads', 500, 60)
    allowed: list[bool] = []
    lock = threading.Lock()

    def worker() -> None:
        results = [limiter.hit('caller', policy).allowed for _ in range(100)]
        with lock:
            allowed.extend(results)

    threads = [threading.Thread(target=worker) for _ in range(10)]
    for thread in threads:
        thread.start()
    for thread in threads:
        thread.join()
    assert allowed.count(True) == 500
