import unittest
import os
import psycopg2
import dotenv
from auth import db, auth # Import your classes from the saved file

# --- IMPORTANT: CONFIGURE YOUR TEST DATABASE ---
# Use a SEPARATE database for testing to avoid data loss.
TEST_DB_NAME = os.getenv("DB_NAME")  # Use environment variable or default
TEST_DB_USER = os.getenv("DB_USER")  # Use environment variable or default
TEST_DB_PASS = os.getenv("DB_PASSWORD")  # Use environment variable or default
TEST_DB_HOST = "localhost"
TEST_DB_PORT = 5432
db_instance = db(dbname=TEST_DB_NAME, user=TEST_DB_USER, password=TEST_DB_PASS, host=TEST_DB_HOST, port=TEST_DB_PORT)
db_instance.setup_database()
auth_system = auth(db_instance)

# Signup a user
print(auth_system.signup("Alice", "alice1@example.com", "password123", "password123"))

print(auth_system.verify_user("alice1@example.com"))

# Login
print(auth_system.login("alice1@example.com", "password123"))

# Reset password
print(auth_system.reset_password("alice1@example.com", "newpass", "newpass"))

# Verify a user by email


# Reset password

