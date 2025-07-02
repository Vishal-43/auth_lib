import os
import bcrypt
import psycopg2
from contextlib import contextmanager

class db:
    """
    Handles all database interactions with a PostgreSQL database.
    """
    def __init__(self, dbname, user, password, host, port=5432):
        self.dbname = dbname
        self.user = user
        self.password = password
        self.host = host
        self.port = port
        self.conn = None
        self.cur = None

        if not all([self.dbname, self.user, self.password, self.host, self.port]):
            self.flag = False
            print("Database parameters are not fully set.")
        else:
            self.flag = True

    @contextmanager
    def _get_cursor(self):
        if not self.flag:
            raise ConnectionError("Database connection parameters are not configured.")
        try:
            self.conn = psycopg2.connect(
                dbname=self.dbname,
                user=self.user,
                password=self.password,
                host=self.host,
                port=self.port
            )
            self.cur = self.conn.cursor()
            yield self.cur
            self.conn.commit()
        except Exception as e:
            if self.conn:
                self.conn.rollback()
            print(f"Database transaction failed: {e}")
            raise
        finally:
            if self.cur:
                self.cur.close()
            if self.conn:
                self.conn.close()

    def setup_database(self):
        try:
            with self._get_cursor() as cur:
                cur.execute("""
                    CREATE TABLE IF NOT EXISTS users (
                        id SERIAL PRIMARY KEY,
                        username VARCHAR(255) NOT NULL,
                        email TEXT UNIQUE NOT NULL,
                        password TEXT NOT NULL,
                        verification_status BOOLEAN DEFAULT FALSE
                    )
                """)
            print("Database table 'users' is ready.")
            return True
        except Exception as e:
            print(f"Error setting up database: {e}")
            return False

    def create_user(self, username, email, hashed_password):
        try:
            with self._get_cursor() as cur:
                cur.execute("SELECT email FROM users WHERE email = %s", (email,))
                if cur.fetchone():
                    return [False, "User with this email already exists."]
                cur.execute(
                    "INSERT INTO users (username, email, password) VALUES (%s, %s, %s)",
                    (username, email, hashed_password)
                )
                return [True, "User created successfully."]
        except Exception as e:
            return [False, f"Error creating user: {e}"]

    def get_user_by_email(self, email):
        try:
            with self._get_cursor() as cur:
                cur.execute("SELECT * FROM users WHERE email = %s", (email,))
                user = cur.fetchone()
                if user:
                    return [True, "User found.", user]
                else:
                    return [False, "User not found."]
        except Exception as e:
            return [False, f"Error finding user: {e}"]

    def update_password(self, email, new_hashed_password):
        try:
            with self._get_cursor() as cur:
                cur.execute("UPDATE users SET password = %s WHERE email = %s", (new_hashed_password, email))
                if cur.rowcount > 0:
                    return [True, "Password updated successfully."]
                else:
                    return [False, "User not found, password not updated."]
        except Exception as e:
            return [False, f"Error updating password: {e}"]
    def update_verification_status(self, email, status=True):
        """Updates the verification status of a user."""
        try:
            with self._get_cursor() as cur:
                cur.execute("UPDATE users SET verification_status = %s WHERE email = %s", (status, email))
                if cur.rowcount > 0:
                    return [True, "Verification status updated successfully."]
                else:
                    return [False, "User not found, verification status not updated."]
        except Exception as e:
            return [False, f"Error updating verification status: {e}"]





class auth:
    """
    Handles user authentication: signup, login, password management.
    Uses bcrypt for secure password hashing.
    """
    def __init__(self, db_instance):
        self.db = db_instance

    def hash_password(self, password):
        return bcrypt.hashpw(password.encode(), bcrypt.gensalt()).decode()

    def check_password(self, password, hashed_password):
        return bcrypt.checkpw(password.encode(), hashed_password.encode())

    def signup(self, username, email, password, confirm_password):
        if password != confirm_password:
            return [False, "Passwords do not match."]
        try:
            hashed_password = self.hash_password(password)
            return self.db.create_user(username, email, hashed_password)
        except Exception as e:
            return [False, f"An error occurred during signup: {e}"]

    def login(self, email, password):
        try:
            found, msg, user = self.db.get_user_by_email(email)
            if not found:
                return [False, msg]

            hashed_password = user[3]  # Assuming password is in the 4th column
            verified = user[4]         # verification_status

            if not self.check_password(password, hashed_password):
                return [False, "Invalid credentials."]

            if not verified:
                return [False, "User not verified."]
            return [True, "Login successful.", user]
        except Exception as e:
            return [False, f"An error occurred during login: {e}"]

    def reset_password(self, email, new_password, confirm_new_password):
        if new_password != confirm_new_password:
            return [False, "New passwords do not match."]
        try:
            found, msg, _ = self.db.get_user_by_email(email)
            if not found:
                return [False, "User not found."]

            hashed_new_password = self.hash_password(new_password)
            return self.db.update_password(email, hashed_new_password)
        except Exception as e:
            return [False, f"An error occurred while resetting password: {e}"]


    def verify_user(self, email):
        """Sets a user's verification status to True."""
        try:
            found, _, _ = self.db.get_user_by_email(email)
            if not found:
                return [False, "User not found."]
            return self.db.update_verification_status(email, True)
        except Exception as e:
            return [False, f"An error occurred while verifying user: {e}"]
