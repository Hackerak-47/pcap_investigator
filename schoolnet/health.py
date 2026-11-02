"""Local readiness checks and an explicit, synthetic live AI probe."""
from datetime import datetime, timezone
from pathlib import Path
from flask import request, session, redirect, url_for
from sqlalchemy import text
from database.database import db
from database.school_models import ModelRecord
import config


def check_page():
    from schoolnet.routes import page
    if request.method == 'POST':
        from schoolnet.ai_engine import ask_provider
        try:
            result = ask_provider({'scope': 'Synthetic connectivity check; no capture data.',
                                   'flows': [{'reference': 'flow:1', 'protocol': 'TCP', 'packet_count': 3}]},
                                  'Summarize this synthetic flow in one sentence. Do not infer an attack.')
            status = 'Live response verified' if result else 'Offline mode: no provider response'
            detail = result['answer'] if result else 'Configure a provider and API key to enable live AI.'
        except RuntimeError as exc:
            status, detail = 'Live AI unavailable', str(exc)
        except Exception:
            status, detail = 'Live AI unavailable', 'Connection timed out, network failed, or response validation failed. Offline evidence summaries remain available.'
        session['ai_check'] = {'status': status, 'detail': detail,
                               'time': datetime.now(timezone.utc).strftime('%Y-%m-%d %H:%M UTC'),
                               'model': config.GEMINI_MODEL if config.AI_PROVIDER in ('gemini', 'google') else config.OPENAI_MODEL}
        return redirect(url_for('check_page'))
    checks = []
    try:
        db.session.execute(text('SELECT 1'))
        checks.append(('Database', 'Ready', 'Local database responds.'))
    except Exception:
        db.session.rollback()
        checks.append(('Database', 'Needs attention', 'Database connection failed.'))
    model = ModelRecord.query.filter_by(active=True).first()
    checks.append(('Anomaly model', 'Ready' if model else 'Training required',
                   'Active baseline available.' if model else 'Train a separate normal capture; rule detection works without ML.'))
    from schoolnet.crypto import aes_key
    try:
        aes_key()
        checks.append(('Report encryption', 'Ready', 'Configured AES key has the required format.'))
    except Exception:
        checks.append(('Report encryption', 'Needs configuration', 'Set a base64-encoded 32-byte REPORT_AES_KEY.'))
    try:
        from cryptography.hazmat.primitives import serialization
        from cryptography.hazmat.primitives.asymmetric import rsa
        key = serialization.load_pem_private_key(Path(config.SIGNING_KEY_PATH).read_bytes(),
                 password=config.SIGNING_KEY_PASSWORD.encode() if config.SIGNING_KEY_PASSWORD else None)
        assert isinstance(key, rsa.RSAPrivateKey) and key.key_size >= 2048
        checks.append(('Report signing', 'Ready', 'RSA private key loads successfully.'))
    except Exception:
        checks.append(('Report signing', 'Needs configuration', 'Check the signing key file and password.'))
    return page('school_check.html', checks=checks, ai_check=session.get('ai_check'),
                provider=config.AI_PROVIDER, model_name=config.GEMINI_MODEL if config.AI_PROVIDER in ('gemini','google') else config.OPENAI_MODEL)
