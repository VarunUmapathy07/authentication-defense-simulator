"""
actors.py - The attackers and normal users in our simulation

This file has simple classes for:
- Attackers who try to break in
- Regular users who just want to login
"""
import random


class Attacker:
    """
    An attacker trying to guess passwords
    
    They have a list of passwords to try and they keep going
    until they succeed or run out of passwords.
    """
    def __init__(self, name, target_user, passwords, ip, guesses_per_second=2.0):
        self.name = name
        self.target_user = target_user
        self.passwords = passwords
        self.ip = ip
        self.guesses_per_second = guesses_per_second
        
        self.current_password = 0  # Which password we're on
        self.succeeded = False
        self.blocked_count = 0  # Track how many times blocked
    
    def next_attempt_time(self, current_time):
        """When should the next attempt happen?"""
        if self.succeeded or self.current_password >= len(self.passwords):
            return None  # Done attacking
        
        # Next attempt is 1/rate seconds from now
        return current_time + (1.0 / self.guesses_per_second)
    
    def get_credentials(self):
        """Get the username and password to try"""
        password = self.passwords[self.current_password]
        return self.target_user, password, self.ip
    
    def record_result(self, success, blocked=False):
        """Record what happened with the login attempt"""
        if blocked:
            self.blocked_count += 1
            return  # Don't consume a password guess when blocked
        
        if success:
            self.succeeded = True
        
        self.current_password += 1


class NormalUser:
    """
    A regular user who logs in occasionally
    
    They sometimes make typos and will retry a couple times if login fails.
    """
    def __init__(self, name, username, password, ip, rng_seed):
        self.name = name
        self.username = username
        self.password = password
        self.ip = ip
        self.rng = random.Random(rng_seed)
        
        # When user wants to login (in seconds)
        self.next_login = self.rng.uniform(0, 60)

        
        # Track retries
        self.retry_count = 0
        self.max_retries = 4
        
        # Track blocks
        self.times_blocked = 0
    
    def next_attempt_time(self, current_time):
        """When does this user want to login?"""
        return self.next_login
    
    def get_credentials(self):
        """Get username and password (might have a typo)"""
        password = self.password
        
        # 60% chance of typing wrong password
        if self.rng.random() < 0.60:
            password = self.password + "X"  # Typo!
        
        return self.username, password, self.ip
    
    def record_result(self, success, blocked=False):
        """Record what happened"""
        if blocked:
            # Got blocked by defense
            self.times_blocked += 1
            self.next_login += 60  # Try again in a minute
            self.retry_count = 0
            
        elif success:
            # Successfully logged in
            # Schedule next login in about 3 minutes (plus/minus 1 min)
            self.next_login += 30 + self.rng.uniform(-10, 10)
            self.retry_count = 0
            
        else:
            # Failed (bad password)
            if self.retry_count < self.max_retries:
                # Try again immediately
                self.retry_count += 1
            else:
                # Give up, try later
                self.next_login += 3600
                self.retry_count = 0


def create_attackers():
    """
    Create different types of attackers
    
    Returns a list of attacker objects
    """
    attackers = []
    
    # Common passwords that attackers try
    common_passwords = [
        "password", "123456", "12345678", "qwerty", "abc123",
        "monkey", "1234567", "letmein", "trustno1", "dragon",
        "baseball", "iloveyou", "master", "sunshine", "ashley",
        "bailey", "shadow", "123123", "654321", "superman",
        "secret_password"  # Add victim's actual password so attacker can find it
    ]
    
    # Attacker 1: Brute force on "victim" account
    # Tries passwords quickly from one IP
    attackers.append(Attacker(
        name="brute_force",
        target_user="victim",
        passwords=common_passwords,
        ip="10.0.0.1",
        guesses_per_second=2.0
    ))
    
    # Attacker 2-21: Distributed botnet
    # Many bots, each from different IP, attacking slowly
    for i in range(20):
        # Each bot tries just a few passwords
        attackers.append(Attacker(
            name=f"bot_{i}",
            target_user="victim",
            passwords=common_passwords[:5],  # First 5 passwords only
            ip=f"10.0.{i // 256}.{i % 256}",
            guesses_per_second=0.1  # Very slow
        ))
    
    return attackers


def create_users(num_users, shared_ip=True):
    """
    Create normal users
    
    If shared_ip is True, some users will share IPs (like at an office or home)
    """
    users = []
    
    for i in range(num_users):
        username = f"user{i}"
        password = f"pass{i}"
        
        # Decide IP address
        if shared_ip and i < 15:
            # First 15 users share an IP (like home WiFi)
            ip = "192.168.1.100"
        else:
            # Everyone else has unique IP
            ip = f"192.168.{i // 256}.{i % 256}"
        
        users.append(NormalUser(
            name=f"normal_user_{i}",
            username=username,
            password=password,
            ip=ip,
            rng_seed=1000 + i
        ))
    
    return users