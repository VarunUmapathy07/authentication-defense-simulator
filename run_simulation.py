"""
run_simulation.py - Runs the actual simulation

This simulates attackers and users trying to login over time.
We use an "event queue" which is just a list of things that will happen,
sorted by when they happen.
"""
import heapq
import csv


def run_simulation(auth_service, clock, actors, duration, detail_log):
    """
    Run the simulation for a certain amount of time
    
    auth_service: The login system
    clock: Time tracker
    actors: List of attackers and users
    duration: How long to simulate (in seconds)
    detail_log: Where to write detailed logs
    """
    # Set up detailed log file
    with open(detail_log, 'w', newline='') as f:
        writer = csv.writer(f)
        writer.writerow(['timestamp', 'actor_name', 'actor_type', 'username', 'ip', 'result', 'reason'])
    
    # Event queue: list of (time, actor_index, actor_type)
    # We use a heap so the next event is always first
    events = []
    
    # Schedule first event for each actor
    for i, (actor, actor_type) in enumerate(actors):
        next_time = actor.next_attempt_time(clock.now())
        if next_time is not None:
            heapq.heappush(events, (next_time, i, actor_type))
    
    # Process events until we run out or hit time limit
    event_count = 0
    while events:
        # Get next event
        event_time, actor_index, actor_type = heapq.heappop(events)
        
        # Check if we're past the time limit
        if event_time > duration:
            break
        
        # Move time forward
        clock.current_time = event_time
        
        # Get the actor
        actor, _ = actors[actor_index]
        
        # Get their login credentials
        username, password, ip = actor.get_credentials()
        
        # Try to login
        result = auth_service.login(username, password, ip)
        
        # Figure out what happened
        if result['success']:
            outcome = 'success'
            reason = ''
            actor.record_result(success=True, blocked=False)
        elif result['reason'] in ['locked', 'rate_limited', 'backoff']:
            outcome = 'blocked'
            reason = result['reason']
            if hasattr(actor, 'record_result'):
                if hasattr(actor, 'times_blocked'):  # It's a user
                    actor.record_result(success=False, blocked=True)
                else:  # It's an attacker
                    actor.record_result(success=False)
        else:
            outcome = 'failed'
            reason = result['reason']
            actor.record_result(success=False, blocked=False)
        
        # Write to detailed log
        with open(detail_log, 'a', newline='') as f:
            writer = csv.writer(f)
            writer.writerow([
                clock.now(),
                actor.name,
                actor_type,
                username,
                ip,
                outcome,
                reason
            ])
        
        # Schedule next event for this actor
        next_time = actor.next_attempt_time(clock.now())
        if next_time is not None and next_time <= duration:
            heapq.heappush(events, (next_time, actor_index, actor_type))
        
        event_count += 1
        if event_count % 500 == 0:
            print(f"  Processed {event_count} events (time: {clock.now():.0f}s)")
    
    print(f"Simulation complete: {event_count} total events")
    return event_count
