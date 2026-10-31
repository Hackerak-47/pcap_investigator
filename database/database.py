"""
database/database.py - Flask-SQLAlchemy setup
"""

from flask_sqlalchemy import SQLAlchemy

db = SQLAlchemy()


def init_app(app):
    """Bind SQLAlchemy to the Flask app and create all tables."""
    db.init_app(app)
    with app.app_context():
        # Import models so they are registered before create_all
        import database.models  # noqa: F401
        import database.school_models  # noqa: F401
        db.create_all()
        from database.migrations import migrate
        migrate()
