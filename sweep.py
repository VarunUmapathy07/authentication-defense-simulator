"""
sweep.py - Run parameter sweeps across different defense configurations
"""
import os
import sys
import random
from clock import Clock
from database import Database
from defenses import get_defense
from auth_service import AuthService
from actors import create_attackers, create_users
from run_simulation import run_simulation
import csv


def run_one_trial(defense_name, config, trial_number, output_dir, duration=86400, attacker_model="baseline"):
    """Run one trial with specific defense config"""
    # Set seed for reproducibility
    random.seed(trial_number)
    
    # Set up
    clock = Clock()
    database = Database()
    
    # Add victim account
    database.add_user("victim", "secret_password", clock.now())
    
    # Add normal users
    users = create_users(num_users=50, shared_ip=True)
    for user in users:
        database.add_user(user.username, user.password, clock.now())
    
    # Get defense with config
    defense_check, defense_update = get_defense(defense_name, database, clock, config)
    
    # Create log files
    trial_dir = os.path.join(output_dir, f"trial_{trial_number}")
    os.makedirs(trial_dir, exist_ok=True)
    
    auth_log = os.path.join(trial_dir, "auth_log.csv")
    detail_log = os.path.join(trial_dir, "detail_log.csv")
    
    # Create auth service
    auth_service = AuthService(database, clock, defense_check, defense_update, auth_log)
    
    # Create attackers based on model
    if attacker_model == "cred_stuffing":
        attackers = create_attackers_cred_stuffing(trial_number)
    else:
        attackers = create_attackers()
    
    # Combine all actors
    actors = []
    for attacker in attackers:
        actors.append((attacker, 'attacker'))
    for user in users:
        actors.append((user, 'user'))
    
    # Run simulation
    run_simulation(auth_service, clock, actors, duration, detail_log)
    
    return trial_dir


def create_attackers_cred_stuffing(seed):
    """Create credential stuffing attackers (spread across many accounts)"""
    from actors import Attacker
    
    # Use seeded RNG for reproducibility
    rng = random.Random(seed)
    
    # Common passwords
    common_passwords = [
        "password", "123456", "12345678", "qwerty", "abc123",
        "monkey", "letmein", "dragon", "sunshine"
    ]
    
    # Build credential pairs - target many users
    credential_pairs = []
    for i in range(50):  # Try users 0-49
        # 15% chance of correct leaked password
        if rng.random() < 0.15:
            password = f"pass{i}"  # Correct leaked credential
        else:
            password = rng.choice(common_passwords)  # Wrong guess
        credential_pairs.append((f"user{i}", password))
    
    # Also add victim attempts with leaked credential
    # Mix of wrong guesses and correct password
    for pwd in common_passwords:
        credential_pairs.append(("victim", pwd))
    credential_pairs.append(("victim", "secret_password"))  # Leaked correct one
    
    # Create one attacker cycling through all credential pairs
    class CredStuffingAttacker:
        def __init__(self):
            self.name = "cred_stuffer"
            self.credentials = credential_pairs
            self.current = 0
            self.succeeded = False
            self.blocked_count = 0
            self.guesses_per_second = 1.0
        
        def next_attempt_time(self, current_time):
            if self.current >= len(self.credentials):
                return None
            return current_time + (1.0 / self.guesses_per_second)


        
        def get_credentials(self):
            username, password = self.credentials[self.current]
            # Return (username, password, ip) - use different IP for each attempt
            ip = f"10.1.{self.current // 256}.{self.current % 256}"
            return username, password, ip
        
        def record_result(self, success, blocked=False):
            if blocked:
                self.blocked_count += 1
                return  # don't consume a credential attempt when blocked
            
            # Always move to the next credential pair.
            # IMPORTANT: do NOT stop after a success, or you won't stress the defense.
            self.current += 1


    
    return [CredStuffingAttacker()]


def get_sweep_configs():
    """
    Define parameter values to sweep for each defense
    
    Returns dict: defense_name -> list of (param_name, param_value, config_dict)
    """
    configs = {}
    
    # Lockout: sweep max_failures
    configs['lockout'] = [
        ('max_failures', 3, {'max_failures': 3, 'lockout_time': 300}),
        ('max_failures', 5, {'max_failures': 5, 'lockout_time': 300}),
        ('max_failures', 10, {'max_failures': 10, 'lockout_time': 300}),
    ]
    
    # Backoff: sweep base_delay
    configs['backoff'] = [
        ('base_delay', 0.25, {'base_delay': 0.25, 'max_delay': 60.0}),
        ('base_delay', 0.5, {'base_delay': 0.5, 'max_delay': 60.0}),
        ('base_delay', 1.0, {'base_delay': 1.0, 'max_delay': 60.0}),
        ('base_delay', 2.0, {'base_delay': 2.0, 'max_delay': 60.0}),
    ]
    
    # Rate limit: sweep (refill_rate, max_tokens) combos
    configs['rate_limit'] = [
        ('tokens', '2_0.3', {'refill_rate': 0.3, 'max_tokens': 2}),
        ('tokens', '3_0.5', {'refill_rate': 0.5, 'max_tokens': 3}),
        ('tokens', '5_0.5', {'refill_rate': 0.5, 'max_tokens': 5}),
        ('tokens', '5_1.0', {'refill_rate': 1.0, 'max_tokens': 5}),
    ]
    
    # Rate limit IP
    configs['rate_limit_ip'] = [
        ('tokens', '3_0.5', {'refill_rate': 0.5, 'max_tokens': 3}),
        ('tokens', '5_1.0', {'refill_rate': 1.0, 'max_tokens': 5}),
        ('tokens', '10_2.0', {'refill_rate': 2.0, 'max_tokens': 10}),
    ]
    
    return configs


def run_sweep(output_base="results", seeds=3, duration=3600, attacker_model="baseline"):
    """
    Run parameter sweep across all defenses
    
    output_base: Where to save results
    seeds: Number of trials per configuration
    duration: Simulation duration (default 1 hour)
    attacker_model: "baseline" or "cred_stuffing"
    """
    # Check if running in CI - use minimal config
    if os.environ.get("CI"):
        print("CI mode detected - running minimal sweep")
        seeds = 1
        duration = 60
    
    os.makedirs(output_base, exist_ok=True)
    
    sweep_configs = get_sweep_configs()
    
    # In CI mode, only test one defense with one param
    if os.environ.get("CI"):
        sweep_configs = {'lockout': sweep_configs['lockout'][:1]}
    
    all_results = []
    trial_id = 0
    
    for defense_name, param_configs in sweep_configs.items():
        print(f"\nDefense: {defense_name}")
        
        for param_name, param_value, config in param_configs:
            print(f"  Parameter: {param_name}={param_value}")
            
            for seed in range(seeds):
                print(f"    Seed {seed}...")
                
                trial_dir = os.path.join(output_base, f"trial_{trial_id}")
                run_one_trial(defense_name, config, trial_id, output_base, duration, attacker_model)
                
                # Record metadata
                all_results.append({
                    'trial_id': trial_id,
                    'defense': defense_name,
                    'param_name': param_name,
                    'param_value': str(param_value),
                    'seed': seed,
                    'attacker_model': attacker_model,
                    'config': str(config)
                })
                
                trial_id += 1
    
    # Save metadata
    metadata_file = os.path.join(output_base, "sweep_metadata.csv")
    with open(metadata_file, 'w', newline='') as f:
        writer = csv.DictWriter(f, fieldnames=['trial_id', 'defense', 'param_name', 'param_value', 'seed', 'attacker_model', 'config'])
        writer.writeheader()
        writer.writerows(all_results)
    
    print(f"\n\nSweep complete: {trial_id} trials")
    print(f"Metadata saved to: {metadata_file}")
    print(f"\nNext step:")
    print(f"  python analyze_sweep.py {output_base}")


if __name__ == "__main__":
    run_sweep(output_base="results", attacker_model="baseline", duration=7200)
    run_sweep(output_base="results_credstuff", attacker_model="cred_stuffing", duration=7200)