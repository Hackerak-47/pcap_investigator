"""Versioned, additive SQLite migrations. Never drop existing evidence tables."""
from sqlalchemy import text, inspect
from database.database import db

PACKET_COLUMNS = {'transport_protocol': 'VARCHAR(20)', 'tls_version': 'VARCHAR(30)',
                  'tls_cipher': 'VARCHAR(100)', 'tls_handshake': 'VARCHAR(100)',
                  'dns_is_response': 'BOOLEAN'}

def migrate():
    with db.engine.begin() as connection:
        connection.execute(text('CREATE TABLE IF NOT EXISTS schema_versions (version INTEGER PRIMARY KEY)'))
        present = {c['name'] for c in inspect(connection).get_columns('packets')}
        for name, kind in PACKET_COLUMNS.items():
            if name not in present:
                connection.execute(text(f'ALTER TABLE packets ADD COLUMN {name} {kind}'))
        connection.execute(text('INSERT OR IGNORE INTO schema_versions(version) VALUES (1)'))
