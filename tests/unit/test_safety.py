from dhcpig.core.safety import RateLimiter, ScopeGuard


def test_scope_guard():
    g = ScopeGuard(["172.20.0.0/16"])
    assert g.allows("172.20.5.5")
    assert not g.allows("10.9.9.9")
    assert not g.allows("garbage")
    assert ScopeGuard(None).allows("1.2.3.4")  # unrestricted when no scope


def test_rate_limiter_consumes_tokens_deterministically():
    rl = RateLimiter(5)  # bucket starts full with 5 tokens
    for _ in range(5):
        rl.acquire(now=100.0)  # same timestamp => no refill
    # 6th call at the same instant would have to wait; deterministic mode returns without sleep
    rl.acquire(now=100.0)  # should not raise / not hang
