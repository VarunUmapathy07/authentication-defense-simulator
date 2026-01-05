"""
clock.py - Keeps track of time in the simulation

In real life, you'd use actual time. But we want to simulate 24 hours
in just a few seconds, so we use "fake time" that we can speed up.
"""

class Clock:
    def __init__(self):
        # Start at time zero
        self.current_time = 0.0
    
    def now(self):
        """Get the current time"""
        return self.current_time
    
    def advance(self, seconds):
        """Move time forward by some number of seconds"""
        self.current_time += seconds
    
    def reset(self):
        """Set time back to zero"""
        self.current_time = 0.0
