"""Administrator session protection.
Handles authentication-related checks and session/security protections.
Local-only mode is explicit when unconfigured."""
import secrets,hmac
from flask import request,session,redirect,url_for,abort
import config

def install_security(app):
    app.config.update(SESSION_COOKIE_HTTPONLY=True,SESSION_COOKIE_SAMESITE='Lax')
    class CSRFToken(str):
        def __call__(self):
            return self

    @app.context_processor
    def security_context():
        if 'csrf' not in session: session['csrf']=secrets.token_hex(24)
        token = CSRFToken(session['csrf'])
        return {'csrf_token':token,'auth_configured':bool(config.ADMIN_PASSWORD_HASH)}
    @app.before_request
    def guard():
        if request.endpoint=='static': return
        if config.ADMIN_PASSWORD_HASH:
            if not session.get('admin') and request.endpoint!='schoolnet.login': return redirect(url_for('schoolnet.login'))
        elif request.remote_addr not in ('127.0.0.1','::1',None):
            abort(403,description='Configure administrator authentication before remote access')
        if request.method=='POST' and not app.config.get('TESTING'):
            supplied=request.headers.get('X-CSRF-Token') or request.form.get('csrf_token','')
            if not hmac.compare_digest(supplied,session.get('csrf','missing')): abort(400,description='Invalid form token; refresh and retry')
    @app.after_request
    def headers(response):
        response.headers['X-Content-Type-Options']='nosniff'
        response.headers['X-Frame-Options']='DENY'
        response.headers['Referrer-Policy']='same-origin'
        return response
