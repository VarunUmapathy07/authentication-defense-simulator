"""
test_defenses.py - Tests for defense mechanisms

Simple tests to verify defenses work correctly.
"""
import sys
import os
sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from clock import Clock
from database import Database
from defenses import get_defense


def test_lockout_triggers_at_threshold():
    """Test that lockout triggers after max_failures attempts"""
    clock = Clock()
    database = Database()
    database.add_user("testuser", "password123", clock.now())
    
    # Config: lock after 3 failures
    config = {'max_failures': 3, 'lockout_time': 300}
    check, update = get_defense("lockout", database, clock, config)
    
    # First 3 attempts should be allowed
    for i in range(3):
        allowed, reason = check("testuser", "10.0.0.1")
        assert allowed == True, f"Attempt {i+1} should be allowed"
        update("testuser", "10.0.0.1", "failure")
    
    # 4th attempt should be blocked
    allowed, reason = check("testuser", "10.0.0.1")
    assert allowed == False, "Should be locked after 3 failures"
    assert reason == "locked", "Reason should be 'locked'"
    
    print("PASS: Lockout triggers at threshold")


def test_lockout_resets_on_success():
    """Test that lockout counter resets on successful login"""
    clock = Clock()
    database = Database()
    database.add_user("testuser", "password123", clock.now())
    
    config = {'max_failures': 5}
    check, update = get_defense("lockout", database, clock, config)
    
    # 2 failures
    update("testuser", "10.0.0.1", "failure")
    update("testuser", "10.0.0.1", "failure")
    
    # Then success
    update("testuser", "10.0.0.1", "success")
    
    # Should be back to 0 failures - can fail 5 more times
    for i in range(5):
        allowed, reason = check("testuser", "10.0.0.1")
        assert allowed == True
        update("testuser", "10.0.0.1", "failure")
    
    # 6th should lock
    allowed, reason = check("testuser", "10.0.0.1")
    assert allowed == False
    
    print("PASS: Lockout resets on success")


def test_backoff_delay_doubles():
    """Test that backoff delay doubles each failure"""
    clock = Clock()
    database = Database()
    database.add_user("testuser", "password123", clock.now())
    
    config = {'base_delay': 1.0, 'max_delay': 60.0}
    check, update = get_defense("backoff", database, clock, config)
    
    # First failure
    update("testuser", "10.0.0.1", "failure")
    state = database.get_login_state("testuser")
    first_delay = state['locked_until'] - clock.now()
    assert abs(first_delay - 1.0) < 0.01, f"First delay should be 1s, got {first_delay}"
    
    # Move past first delay
    clock.advance(2.0)
    
    # Second failure
    update("testuser", "10.0.0.1", "failure")
    state = database.get_login_state("testuser")
    second_delay = state['locked_until'] - clock.now()
    assert abs(second_delay - 2.0) < 0.01, f"Second delay should be 2s, got {second_delay}"
    
    # Move past second delay
    clock.advance(3.0)
    
    # Third failure
    update("testuser", "10.0.0.1", "failure")
    state = database.get_login_state("testuser")
    third_delay = state['locked_until'] - clock.now()
    assert abs(third_delay - 4.0) < 0.01, f"Third delay should be 4s, got {third_delay}"
    
    print("PASS: Backoff delay doubles correctly")


def test_token_bucket_blocks_when_empty():
    """Test that token bucket blocks when empty"""
    clock = Clock()
    database = Database()
    
    config = {'refill_rate': 0.5, 'max_tokens': 2}
    check, update = get_defense("rate_limit", database, clock, config)
    
    # Use both tokens (check consumes the token)
    check("testuser", "10.0.0.1")
    check("testuser", "10.0.0.1")
    
    # Should be blocked now
    allowed, reason = check("testuser", "10.0.0.1")
    assert allowed == False
    assert reason == "rate_limited"
    
    print("PASS: Token bucket blocks when empty")


def test_token_bucket_refills():
    """Test that token bucket refills over time"""
    clock = Clock()
    database = Database()
    
    config = {'refill_rate': 1.0, 'max_tokens': 2}
    check, update = get_defense("rate_limit", database, clock, config)
    
    # Use both tokens
    check("testuser", "10.0.0.1")
    check("testuser", "10.0.0.1")
    
    # Should be blocked
    allowed, reason = check("testuser", "10.0.0.1")
    assert allowed == False
    
    # Wait 1 second (should refill 1 token)
    clock.advance(1.0)
    
    # Should have 1 token available now
    allowed, reason = check("testuser", "10.0.0.1")
    assert allowed == True, "Should have refilled 1 token after 1 second"
    
    print("PASS: Token bucket refills over time")


def test_hybrid_checks_ip_then_account():
    """Test that hybrid defense checks IP before account"""
    clock = Clock()
    database = Database()
    database.add_user("user1", "pass1", clock.now())
    database.add_user("user2", "pass2", clock.now())
    
    config = {
        'ip_refill_rate': 1.0,
        'ip_max_tokens': 2,
        'account_refill_rate': 0.5,
        'account_max_tokens': 5
    }
    check, update = get_defense("hybrid", database, clock, config)
    
    # Use up IP tokens (2 attempts from same IP, different users)
    check("user1", "10.0.0.1")
    check("user2", "10.0.0.1")
    
    # 3rd attempt from same IP should be blocked (IP limit hit)
    allowed, reason = check("user1", "10.0.0.1")
    assert allowed == False
    assert reason == "rate_limited", "Should be blocked by IP limit"
    
    # But different IP should still work
    allowed, reason = check("user1", "10.0.0.2")
    assert allowed == True, "Different IP should not be blocked"
    
    print("PASS: Hybrid checks IP then account")


def run_all_tests():
    """Run all tests"""
    print("\nRunning defense tests...")
    
    test_lockout_triggers_at_threshold()
    test_lockout_resets_on_success()
    test_backoff_delay_doubles()
    test_token_bucket_blocks_when_empty()
    test_token_bucket_refills()
    test_hybrid_checks_ip_then_account()
    
    print("\nAll tests passed")


if __name__ == "__main__":
    run_all_tests()
