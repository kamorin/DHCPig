"""Pure logic in core/eviction.py: the outcome-rung ordering. The stateful eviction phases
(_do_arp_conflict, _evict_phase, ...) stay engine methods and are covered in test_engine.py."""

from dhcpig.core.eviction import rung_max


def test_rung_max_picks_the_higher_rung():
    assert rung_max("no_reaction", "defended") == "defended"
    assert rung_max("declined", "defended") == "declined"
    assert rung_max("rediscovered", "apipa") == "apipa"
