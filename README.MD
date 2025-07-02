# 🔐 auth_lib_web - Authentication Library for Python Web Apps

A secure, modular authentication library built with Python and PostgreSQL. `auth_lib_web` provides essential features like user registration, login, password hashing, email verification, and password reset, all backed by strong security and clean design principles.

---

## 🚀 Features

### 1. 👤 User Management
- **User Registration** with input validation
- **User Login** with secure credential verification
- **Email-based User Verification** system with status tracking

### 2. 🔑 Secure Password Management
- Password **Hashing with bcrypt**
- Password **Reset** and **Change**
- Password **Confirmation** during signup and reset

### 3. 🗄️ Database Integration (PostgreSQL)
- Automatic user table setup
- Safe database connection handling with context managers
- Transaction safety with auto-rollback on failure

### 4. 🛡️ Security Features
- Password hashing with salt (bcrypt)
- Email uniqueness enforcement
- User verification flag
- Secure and isolated DB connection handling

### 5. 🧱 Database Schema

The system manages a `users` table with the following structure:

| Column              | Type           | Description                      |
|---------------------|----------------|----------------------------------|
| `id`                | SERIAL (PK)    | Unique identifier                |
| `username`          | TEXT           | User’s display name              |
| `email`             | TEXT (Unique)  | User’s email (login identifier) |
| `password`          | TEXT           | Hashed password                  |
| `verification_status` | BOOLEAN      | Indicates if user is verified    |

### 6. ❗ Error Handling & Validation
- Detailed error messages
- Input validation (e.g. email format, password match)
- Graceful handling of DB and connection errors
- Transaction rollback for data safety

### 7. ⚙️ Environment Configuration
- Uses `.env` for managing database credentials
- Configurable host, port, DB name, user, and password

---

## 🛠️ Tech Stack

- **Python** – Core language
- **PostgreSQL** – Database
- **bcrypt** – Password hashing
- **psycopg2** – PostgreSQL adapter
- **python-dotenv** – Secure environment variable loading

---

## 📦 Installation

```bash
git clone https://github.com/Vishal-43/auth_lib.git
cd auth_lib_web
pip install -r requirements.txt
