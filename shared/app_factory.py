"""
Builds a Flask app with everything every service needs:
  * consistent JSON error handling (400/401/403/404/405/413/415/500)
  * exception handling for database errors (no stack traces leaked to the client)
  * request size limit (stops oversized / malicious payloads)
  * security response headers
  * X-Student-Name header on every response (who implemented the route)
  * file logging to logs/<service>.log
"""
import logging
import os
import sqlite3
from logging.handlers import RotatingFileHandler

from flask import Flask, request

from shared import audit_client
from shared.config import LOG_DIR, STUDENT_NAME
from shared.db import init_db
from shared.errors import ValidationError, bad_request, error_response, not_found

MAX_BODY_BYTES = 16 * 1024  # 16 KB is plenty for any request of these services


def setup_logging(service_slug):
    os.makedirs(LOG_DIR, exist_ok=True)
    handler = RotatingFileHandler(os.path.join(LOG_DIR, f"{service_slug}.log"),
                                  maxBytes=1_000_000, backupCount=5, encoding="utf-8")
    handler.setFormatter(logging.Formatter("%(asctime)s - %(levelname)s - %(name)s - %(message)s"))
    root = logging.getLogger()
    root.setLevel(logging.INFO)
    if not any(isinstance(h, RotatingFileHandler) for h in root.handlers):
        root.addHandler(handler)
    console = logging.StreamHandler()
    console.setLevel(logging.WARNING)
    root.addHandler(console)


def create_app(service_name, service_slug, blueprint, audit_name, local_audit_writer=None):
    """audit_name is the 'related_service' value written in audit logs (e.g. 'Users')."""
    setup_logging(service_slug)
    init_db()
    audit_client.configure(audit_name, local_audit_writer)

    app = Flask(service_name)
    app.json.sort_keys = False
    app.config["MAX_CONTENT_LENGTH"] = MAX_BODY_BYTES
    app.register_blueprint(blueprint)
    log = logging.getLogger(service_slug)

    @app.before_request
    def require_json_content_type():
        if request.method in ("POST", "PUT") and request.content_length:
            if not request.is_json:
                return error_response("Content-Type must be application/json", 415)

    @app.after_request
    def add_headers(response):
        response.headers["X-Student-Name"] = STUDENT_NAME
        response.headers["X-Service-Name"] = service_name
        response.headers["X-Content-Type-Options"] = "nosniff"
        response.headers["X-Frame-Options"] = "DENY"
        response.headers["Cache-Control"] = "no-store"
        return response

    @app.errorhandler(ValidationError)
    def handle_validation(e):
        return bad_request(e.message, e.details)

    @app.errorhandler(sqlite3.Error)
    def handle_db_error(e):
        log.exception("Database error: %s", e)
        return error_response("A database error occurred", 500)

    @app.errorhandler(400)
    def handle_400(e):
        return bad_request("Bad request: the body must be valid JSON")

    @app.errorhandler(404)
    def handle_404(e):
        return not_found("Endpoint not found")

    @app.errorhandler(405)
    def handle_405(e):
        return error_response("Method not allowed", 405)

    @app.errorhandler(413)
    def handle_413(e):
        return error_response(f"Request body too large (max {MAX_BODY_BYTES} bytes)", 413)

    @app.errorhandler(415)
    def handle_415(e):
        return error_response("Content-Type must be application/json", 415)

    @app.errorhandler(Exception)
    def handle_unexpected(e):
        from werkzeug.exceptions import HTTPException
        if isinstance(e, HTTPException):
            return error_response(e.description or e.name, e.code)
        log.exception("Unhandled error: %s", e)
        return error_response("Internal server error", 500)

    @app.route("/health", methods=["GET"])
    def health():
        return {"status": "success", "service": service_name}, 200

    return app


def run(app, port):
    from shared.config import FLASK_DEBUG, HOST, SSL_CERT_FILE, SSL_KEY_FILE, USE_HTTPS
    ssl_context = (SSL_CERT_FILE, SSL_KEY_FILE) if USE_HTTPS else None
    # threaded=True: services call each other while handling a request
    app.run(host=HOST, port=port, debug=FLASK_DEBUG, threaded=True, ssl_context=ssl_context)
