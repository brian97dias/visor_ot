"""Disposable SQLite settings ONLY for Django tests.

Usage:
    python manage.py test assets.tests_software_services --settings=config.settings_test_sqlite

Never use these settings for the application server or real OT inventory.
SQLite is a convenient functional test substitute when the PostgreSQL user
cannot CREATE DATABASE; PostgreSQL-specific behavior still needs separate
validation before production.
"""

from .settings import *  # noqa: F403,F401

DATABASES = {
    "default": {
        "ENGINE": "django.db.backends.sqlite3",
        "NAME": ":memory:",
    }
}
