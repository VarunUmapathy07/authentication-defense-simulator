"""
auth_service.py - Handles login requests

This is the authentication service that:
1. Takes login requests
2. Checks the defense policy
3. Verifies the password
4. Logs everything that happens
"""
import csv


class AuthService:
    def __init__(self, database, clock, defense_check, defense_update, log_file=None):
        """
        database: Where user accounts are stored
        clock: Keeps track of time
        defense_check: Function that checks if request should be blocked
        defense_update: Function that updates defense state after attempt
        log_file: Where to write logs (optional)
        """
        self.database = database
        self.clock = clock
        self.defense_check = defense_check
        self.defense_update = defense_update
        self.log_file = log_file
        
        # Set up log file if provided
        if self.log_file:
            with open(self.log_file, 'w', newline='') as f:
                writer = csv.writer(f)
                writer.writerow(['timestamp', 'username', 'ip', 'result', 'reason'])
    
    def login(self, username, password, ip):
        """
        Try to log in
        
        Returns a dict with:
        - success: True if login worked
        - reason: Why it failed (if it failed)
        - token: Login token (if successful)
        """
        now = self.clock.now()
        
        # Step 1: Check defense policy - should we even allow this attempt?
        allowed, block_reason = self.defense_check(username, ip)
        
        if not allowed:
            # Defense blocked it
            self._log(now, username, ip, 'blocked', block_reason)
            return {'success': False, 'reason': block_reason}
        
        # Step 2: Check if password is correct
        correct = self.database.check_password(username, password)
        
        # Step 3: Update defense policy with result
        result = 'success' if correct else 'failure'
        self.defense_update(username, ip, result)
        
        # Step 4: Log what happened
        if correct:
            self._log(now, username, ip, 'success', None)
            return {'success': True, 'token': 'fake-token-12345'}
        else:
            self._log(now, username, ip, 'bad_password', None)
            return {'success': False, 'reason': 'bad_password'}
    
    def _log(self, timestamp, username, ip, result, reason):
        """Write to the log file"""
        if self.log_file:
            with open(self.log_file, 'a', newline='') as f:
                writer = csv.writer(f)
                writer.writerow([timestamp, username, ip, result, reason or ''])
