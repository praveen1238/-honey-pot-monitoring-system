# Honeypot Attack Monitoring System

This project is a controlled, educational Flask web application that simulates a fake server login page and records attacker-style interactions in a SQLite database. It includes a dark-themed admin dashboard, filtering/search, and CSV/PDF export functions.

## Features
- Admin authentication with protected session handling
- Fake login page that records login attempts
- SQLite-backed storage for all captured attempt metadata
- Dashboard with summary cards and Chart.js visualizations
- Search and filtering by IP, username, date, and attack count
- CSV and PDF export

## Setup
1. Install Python 3.10+
2. Create a virtual environment:
   - `python -m venv venv`
3. Activate the virtual environment:
   - Windows: `venv\Scripts\activate`
4. Install dependencies:
   - `pip install -r requirements.txt`
5. Run the app:
   - `python app.py`
6. Open: http://127.0.0.1:5000/

## Default admin credentials
- Username: `admin`
- Password: `admin123`

## Notes
This application is intended for educational and authorized testing purposes only.
