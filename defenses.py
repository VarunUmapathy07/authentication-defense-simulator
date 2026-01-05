"""
defenses.py - Different ways to defend against attackers

Each defense is just a simple function that decides:
1. Should we allow this login attempt?
2. What should we do after the attempt (success or failure)?
"""


def lockout_defense(database, clock, username, ip, result, max_failures=5, lockout_time=300):
    """
    LOCKOUT DEFENSE
    
    How it works:
    - Count failed login attempts
    - After too many failures (like 5), lock the account for a while (like 5 minutes)
    - Reset the counter when user logs in successfully
    
    Problem: Real users who forget their password get locked out too
    """
    state = database.get_login_state(username)
    if not state:
        return True, None  # Unknown user, let it through
    
    now = clock.now()
    
    # Check if user is currently locked
    if state['locked_until'] and now < state['locked_until']:
        return False, "locked"
    
    # Check if they've failed too many times
    if state['failed_attempts'] >= max_failures:
        # Lock them out
        lock_until = now + lockout_time
        database.update_login_state(username, locked_until=lock_until)
        return False, "locked"
    
    # After login attempt happens, update the state
    if result == 'success':
        # Reset everything on successful login
        database.update_login_state(
            username,
            failed_attempts=0,
            locked_until=None,
            last_failure_time=None
        )
    elif result == 'failure':
        # Increment failure count
        new_count = state['failed_attempts'] + 1
        database.update_login_state(
            username,
            failed_attempts=new_count,
            last_failure_time=now
        )
    
    return True, None


def rate_limit_defense(buckets, clock, username, ip, result, refill_rate=0.5, max_tokens=3):
    """
    RATE LIMIT DEFENSE (by account)
    
    How it works:
    - Give each account a "bucket" with tokens in it
    - Each login attempt uses 1 token
    - Tokens slowly refill over time (like 0.5 per second)
    - If bucket is empty, block the attempt
    
    This slows down attackers who try many passwords quickly.
    """
    # Get or create bucket for this username
    if username not in buckets:
        buckets[username] = {
            'tokens': max_tokens,
            'last_refill': clock.now()
        }
    
    bucket = buckets[username]
    now = clock.now()
    
    # Refill tokens based on time passed
    time_passed = now - bucket['last_refill']
    tokens_to_add = time_passed * refill_rate
    bucket['tokens'] = min(max_tokens, bucket['tokens'] + tokens_to_add)
    bucket['last_refill'] = now
    
    # Check if we have a token available
    if bucket['tokens'] >= 1:
        bucket['tokens'] -= 1
        return True, None
    else:
        return False, "rate_limited"


def backoff_defense(database, clock, username, ip, result, base_delay=1.0, max_delay=60.0):
    """
    EXPONENTIAL BACKOFF DEFENSE
    
    How it works:
    - After each failure, make user wait before trying again
    - Wait time doubles each time: 1 sec, 2 sec, 4 sec, 8 sec, etc.
    - Caps out at some maximum (like 60 seconds)
    - Reset to normal after successful login
    
    This slows attackers down without permanently locking accounts.
    """
    state = database.get_login_state(username)
    if not state:
        return True, None
    
    now = clock.now()
    
    # Check if user is in backoff period
    if state['locked_until'] and now < state['locked_until']:
        return False, "backoff"
    
    # After login attempt happens, update state
    if result == 'success':
        # Reset on success
        database.update_login_state(
            username,
            failed_attempts=0,
            locked_until=None,
            last_failure_time=None
        )
    elif result == 'failure':
        # Calculate exponential delay
        # Delay = base_delay * 2^(number of failures - 1)
        new_count = state['failed_attempts'] + 1
        delay = base_delay * (2 ** (new_count - 1))
        delay = min(delay, max_delay)  # Don't exceed max
        
        backoff_until = now + delay
        database.update_login_state(
            username,
            failed_attempts=new_count,
            locked_until=backoff_until,
            last_failure_time=now
        )
    
    return True, None


def get_defense(name, database, clock, config=None):
    """
    Pick which defense to use with custom config
    
    config: dict with defense parameters like:
        - max_failures, lockout_time (for lockout)
        - base_delay, max_delay (for backoff)
        - refill_rate, max_tokens (for rate_limit)
    
    Returns a function you can call to check if login should be allowed
    """
    if config is None:
        config = {}
    
    # We'll keep state for rate limiting here
    account_buckets = {}
    ip_buckets = {}
    
    if name == "lockout":
        max_failures = config.get('max_failures', 5)
        lockout_time = config.get('lockout_time', 300)
        
        def check(username, ip):
            return lockout_defense(database, clock, username, ip, None, max_failures, lockout_time)
        def update(username, ip, result):
            lockout_defense(database, clock, username, ip, result, max_failures, lockout_time)
        return check, update
    
    elif name == "rate_limit":
        refill_rate = config.get('refill_rate', 0.5)
        max_tokens = config.get('max_tokens', 3)
        
        def check(username, ip):
            return rate_limit_defense(account_buckets, clock, username, ip, None, refill_rate, max_tokens)
        def update(username, ip, result):
            rate_limit_defense(account_buckets, clock, username, ip, result, refill_rate, max_tokens)
        return check, update
    
    elif name == "backoff":
        base_delay = config.get('base_delay', 1.0)
        max_delay = config.get('max_delay', 60.0)
        
        def check(username, ip):
            return backoff_defense(database, clock, username, ip, None, base_delay, max_delay)
        def update(username, ip, result):
            backoff_defense(database, clock, username, ip, result, base_delay, max_delay)
        return check, update
    
    elif name == "rate_limit_ip":
        refill_rate = config.get('refill_rate', 1.0)
        max_tokens = config.get('max_tokens', 5)
        
        def check(username, ip):
            return rate_limit_defense(ip_buckets, clock, ip, username, None, refill_rate, max_tokens)
        def update(username, ip, result):
            rate_limit_defense(ip_buckets, clock, ip, username, result, refill_rate, max_tokens)
        return check, update
    
    elif name == "hybrid":
        ip_refill_rate = config.get('ip_refill_rate', 1.0)
        ip_max_tokens = config.get('ip_max_tokens', 5)
        account_refill_rate = config.get('account_refill_rate', 0.5)
        account_max_tokens = config.get('account_max_tokens', 3)
        
        # Combine IP and account rate limiting
        def check(username, ip):
            # Check IP first
            allowed, reason = rate_limit_defense(ip_buckets, clock, ip, username, None, ip_refill_rate, ip_max_tokens)
            if not allowed:
                return False, reason
            # Then check account
            return rate_limit_defense(account_buckets, clock, username, ip, None, account_refill_rate, account_max_tokens)
        
        def update(username, ip, result):
            rate_limit_defense(ip_buckets, clock, ip, username, result, ip_refill_rate, ip_max_tokens)
            rate_limit_defense(account_buckets, clock, username, ip, result, account_refill_rate, account_max_tokens)
        
        return check, update
    
    else:
        raise ValueError(f"Unknown defense: {name}")
