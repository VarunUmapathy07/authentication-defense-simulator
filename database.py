"""
database.py - Stores user accounts and tracks login attempts

This is where we keep:
- User passwords (hashed, not plain text)
- How many times each user failed to login
- When users are locked out
"""
import sqlite3
import hashlib


def hash_password(password):
    """Turn a password into a hash so we don't store it directly"""
    return hashlib.sha256(password.encode()).hexdigest()


class Database:
    def __init__(self):
        # Use in-memory database (goes away when program ends)
        self.conn = sqlite3.connect(":memory:", check_same_thread=False)
        self.conn.row_factory = sqlite3.Row
        self._create_tables()
    
    def _create_tables(self):
        """Set up the database tables"""
        cursor = self.conn.cursor()
        
        # Table for user accounts
        cursor.execute("""
            CREATE TABLE users (
                username TEXT PRIMARY KEY,
                password_hash TEXT,
                created_at REAL
            )
        """)
        
        # Table for tracking login failures and lockouts
        # This is where we keep count of failed attempts
        cursor.execute("""
            CREATE TABLE login_state (
                username TEXT PRIMARY KEY,
                failed_attempts INTEGER DEFAULT 0,
                locked_until REAL,
                last_failure_time REAL
            )
        """)
        
        self.conn.commit()
    
    def add_user(self, username, password, created_at):
        """Add a new user account"""
        cursor = self.conn.cursor()
        cursor.execute(
            "INSERT INTO users (username, password_hash, created_at) VALUES (?, ?, ?)",
            (username, hash_password(password), created_at)
        )
        # Also add entry to track their login attempts
        cursor.execute(
            "INSERT INTO login_state (username) VALUES (?)",
            (username,)
        )
        self.conn.commit()
    
    def check_password(self, username, password):
        """Check if the password is correct - returns True or False"""
        cursor = self.conn.cursor()
        result = cursor.execute(
            "SELECT password_hash FROM users WHERE username = ?",
            (username,)
        ).fetchone()
        
        if not result:
            return False
        
        return result['password_hash'] == hash_password(password)
    
    def get_login_state(self, username):
        """Get info about failed logins for this user"""
        cursor = self.conn.cursor()
        result = cursor.execute(
            "SELECT * FROM login_state WHERE username = ?",
            (username,)
        ).fetchone()
        
        if result:
            return dict(result)
        return None
    
    def update_login_state(self, username, **fields):
        """Update the login tracking info for a user"""
        cursor = self.conn.cursor()
        
        # Build the UPDATE query
        set_parts = []
        values = []
        for field_name, field_value in fields.items():
            set_parts.append(f"{field_name} = ?")
            values.append(field_value)
        
        if set_parts:
            query = f"UPDATE login_state SET {', '.join(set_parts)} WHERE username = ?"
            values.append(username)
            cursor.execute(query, values)
            self.conn.commit()
