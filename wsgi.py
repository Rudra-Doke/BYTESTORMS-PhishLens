"""
Production WSGI entry point for PhishLens.

Development:
    python app.py

Production:
    gunicorn --bind 0.0.0.0:5000 wsgi:app
"""

from app import app

__all__ = ["app"]