# HealthCureAlpha Secure Patient Portal

A simple secure healthcare web application prototype developed as part of the **KH6000CMD – Security** coursework.  
The system demonstrates core security concepts including authentication, authorization, secure data handling, and basic security auditing.

---

## Project Overview

The HealthCureAlpha Secure Patient Portal is an internal web-based system designed to manage patient records securely.  
It supports role-based access control, ensuring that only authorized users can access sensitive data and administrative functionality.

The project focuses on **secure system design and evaluation**, rather than feature completeness or production deployment.

---

## Features

- User registration and login
- Password hashing using bcrypt
- Session-based authentication
- Role-based access control (Admin / Staff)
- Secure patient record storage and retrieval
- Administrative user management (enable/disable users, promote/demote roles)
- CSRF protection using Flask-WTF
- Server-side input validation
- Security testing using OWASP ZAP

---

## Technology Stack

- **Backend:** Python (Flask)
- **Database:** SQLite (development)
- **Authentication:** Flask-Login
- **Security:** bcrypt, Flask-WTF (CSRF)
- **Testing:** OWASP ZAP

---

## Security Design Highlights

- Passwords are never stored in plaintext and are hashed using bcrypt.
- All protected routes require authentication.
- Administrative functionality is restricted using server-side role checks.
- CSRF tokens are enforced on all state-changing requests.
- Session cookies are protected using HttpOnly and SameSite attributes.
- A bootstrap mechanism ensures that only the first user can create an admin account; subsequent admin privileges are granted by existing administrators.

---

## Installation and Setup

```bash
# 1. Clone the repository
git clone https://github.com/bedda-wm/healthcurealpha-secure-portal
cd healthcurealpha-secure-portal

# 2. Create a virtual environment
python3 -m venv .venv

# 3. Activate the virtual environment
# macOS / Linux
source .venv/bin/activate
# Windows
# .venv\Scripts\activate

# 4. Install dependencies
pip install -r requirements.txt

# 5. Run the application
python app.py

# 6. Open in browser
# http://127.0.0.1:5000
