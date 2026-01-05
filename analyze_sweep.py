"""
analyze_sweep.py - Analyze parameter sweep results

Computes metrics including time_to_compromise and throughput,
then aggregates across seeds to get mean and std.
"""
import os
import csv
import sys


def analyze_trial(trial_dir, duration):
    """
    Analyze one trial with enhanced metrics
    
    Returns dict with:
    - compromised, compromise_rate, time_to_compromise
    - block_rate, users_impacted
    - throughput
    """
    detail_log = os.path.join(trial_dir, "detail_log.csv")
    
    # Read all events
    events = []
    with open(detail_log, 'r') as f:
        reader = csv.DictReader(f)
        for row in reader:
            events.append(row)
    
    # Separate attacker and user events
    attacker_events = [e for e in events if e['actor_type'] == 'attacker']
    user_events = [e for e in events if e['actor_type'] == 'user']
    
    # Did attackers succeed on victim account?
    attacker_successes = [e for e in attacker_events if e['result'] == 'success' and e['username'] == 'victim']
    compromised = 1 if len(attacker_successes) > 0 else 0
    
    # Also track non-victim compromises (credential stuffing)
    non_victim_successes = [e for e in attacker_events if e['result'] == 'success' and e['username'] != 'victim']
    non_victim_compromised = len(set([e['username'] for e in non_victim_successes]))
    
    # Time to compromise
    if attacker_successes:
        # Get earliest success timestamp
        time_to_compromise = min([float(e['timestamp']) for e in attacker_successes])
    else:
        time_to_compromise = duration  # Never compromised
    
    # Compromise rate (fraction of attacker attempts that succeeded)
    if len(attacker_events) > 0:
        compromise_rate = len(attacker_successes) / len(attacker_events)
    else:
        compromise_rate = 0.0
    
    # User blocking
    user_attempts = [e for e in user_events if e['result'] != '']
    user_blocked = [e for e in user_attempts if e['result'] == 'blocked']
    
    if len(user_attempts) > 0:
        block_rate = len(user_blocked) / len(user_attempts)
    else:
        block_rate = 0.0
    
    # Users impacted
    blocked_users = set([e['actor_name'] for e in user_blocked])
    all_users = set([e['actor_name'] for e in user_events])
    
    if len(all_users) > 0:
        impacted_users_pct = len(blocked_users) / len(all_users)
    else:
        impacted_users_pct = 0.0
    
    # Throughput (total login attempts per second)
    if duration > 0:
        throughput = len(events) / duration
    else:
        throughput = 0.0
    
    return {
        'compromised': compromised,
        'compromise_rate': compromise_rate,
        'time_to_compromise': time_to_compromise,
        'block_rate': block_rate,
        'impacted_users_pct': impacted_users_pct,
        'throughput': throughput,
        'total_events': len(events),
        'non_victim_compromised': non_victim_compromised
    }


def analyze_sweep(results_dir, duration=3600):
    """
    Analyze all trials from sweep and aggregate by (defense, param_value, attacker_model)
    """
    print(f"Analyzing sweep results in {results_dir}/")
    
    # Load metadata
    metadata_file = os.path.join(results_dir, "sweep_metadata.csv")
    if not os.path.exists(metadata_file):
        print("Error: sweep_metadata.csv not found!")
        print("Make sure you ran sweep.py first")
        return
    
    with open(metadata_file, 'r') as f:
        reader = csv.DictReader(f)
        metadata = list(reader)
    
    # Analyze each trial
    all_results = []
    for meta in metadata:
        trial_id = meta['trial_id']
        trial_dir = os.path.join(results_dir, f"trial_{trial_id}")
        
        if not os.path.exists(trial_dir):
            print(f"Warning: {trial_dir} not found, skipping")
            continue
        
        print(f"Analyzing trial_{trial_id}...")
        
        metrics = analyze_trial(trial_dir, duration)
        
        # Combine metadata and metrics
        result = {
            'trial_id': int(trial_id),
            'defense': meta['defense'],
            'param_name': meta['param_name'],
            'param_value': meta['param_value'],
            'seed': int(meta['seed']),
            'attacker_model': meta.get('attacker_model', 'baseline'),
            'compromise_rate': metrics['compromise_rate'],
            'time_to_compromise': metrics['time_to_compromise'],
            'block_rate': metrics['block_rate'],
            'impacted_users_pct': metrics['impacted_users_pct'],
            'throughput': metrics['throughput'],
            'non_victim_compromised': metrics['non_victim_compromised']
        }
        
        all_results.append(result)
    
    # Save per-trial results
    trials_file = os.path.join(results_dir, "summary.csv")
    if all_results:
        with open(trials_file, 'w', newline='') as f:
            writer = csv.DictWriter(f, fieldnames=all_results[0].keys())
            writer.writeheader()
            writer.writerows(all_results)
        print(f"\nPer-trial results saved to: {trials_file}")
    
    # Aggregate by (defense, param_value, attacker_model)
    from collections import defaultdict
    import statistics
    
    grouped = defaultdict(list)
    for r in all_results:
        key = (r['defense'], r['param_name'], r['param_value'], r['attacker_model'])
        grouped[key].append(r)
    
    aggregated = []
    for key, trials in grouped.items():
        defense, param_name, param_value, attacker_model = key
        
        # Compute mean and std
        compromise_rates = [t['compromise_rate'] for t in trials]
        block_rates = [t['block_rate'] for t in trials]
        impacted = [t['impacted_users_pct'] for t in trials]
        
        mean_compromise = sum(compromise_rates) / len(compromise_rates)
        mean_block = sum(block_rates) / len(block_rates)
        mean_impacted = sum(impacted) / len(impacted)
        
        std_compromise = statistics.stdev(compromise_rates) if len(compromise_rates) > 1 else 0.0
        std_block = statistics.stdev(block_rates) if len(block_rates) > 1 else 0.0
        std_impacted = statistics.stdev(impacted) if len(impacted) > 1 else 0.0
        
        aggregated.append({
            'defense': defense,
            'param_name': param_name,
            'param_value': param_value,
            'attacker_model': attacker_model,
            'n_trials': len(trials),
            'mean_compromise_rate': mean_compromise,
            'std_compromise_rate': std_compromise,
            'mean_block_rate': mean_block,
            'std_block_rate': std_block,
            'mean_impacted_pct': mean_impacted,
            'std_impacted_pct': std_impacted
        })
    
    # Save aggregated results
    agg_file = os.path.join(results_dir, "summary_aggregated.csv")
    if aggregated:
        with open(agg_file, 'w', newline='') as f:
            writer = csv.DictWriter(f, fieldnames=aggregated[0].keys())
            writer.writeheader()
            writer.writerows(aggregated)
        print(f"Aggregated results saved to: {agg_file}")
    
    # Print summary
    print("\nAggregated results:")
    for row in aggregated:
        print(f"\n{row['defense']}: {row['param_name']}={row['param_value']} (attacker={row['attacker_model']})")
        print(f"  Compromise: {row['mean_compromise_rate']:.2%} +/- {row['std_compromise_rate']:.2%}")
        print(f"  Block rate: {row['mean_block_rate']:.2%} +/- {row['std_block_rate']:.2%}")
        print(f"  Users hit:  {row['mean_impacted_pct']:.2%} +/- {row['std_impacted_pct']:.2%}")
    
    print(f"\n\nNext step:")
    print(f"  python plot_frontier.py {results_dir}")


if __name__ == "__main__":
    if len(sys.argv) > 1:
        results_dir = sys.argv[1]
    else:
        results_dir = "results"
    
    analyze_sweep(results_dir)