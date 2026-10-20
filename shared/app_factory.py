import logging
import os
import sqlite3
from logging.handlers import RotatingFileHandler

from flask import Flask, request

from shared import audit_client
from shared.config import LOG_DIR, STUDENT_NAME
from shared.db import init_db
from shared.errors import ValidationError, bad_request, error_response, not_found

MAX_BODY_BYTES = 16 * 1024


# sets up logging so each service writes to its own log file and warnings also show in the console
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


# builds the flask app for a service, registers its routes under /Reina_Hani and adds all the error handlers
def create_app(service_name, service_slug, blueprint, audit_name, local_audit_writer=None, url_prefix=None):
    setup_logging(service_slug)
    init_db()
    audit_client.configure(audit_name, local_audit_writer)

    app = Flask(service_name)
    app.json.sort_keys = False
    app.config["MAX_CONTENT_LENGTH"] = MAX_BODY_BYTES
    app.register_blueprint(blueprint, url_prefix=url_prefix)
    log = logging.getLogger(service_slug)

    # before each post or put, makes sure the body is sent as json or answers with 415
    @app.before_request
    def require_json_content_type():
        if request.method in ("POST", "PUT") and request.content_length:
            if not request.is_json:
                return error_response("Content-Type must be application/json", 415)

    # adds my name, the service name and some security headers to every response
    @app.after_request
    def add_headers(response):
        response.headers["X-Student-Name"] = STUDENT_NAME
        response.headers["X-Service-Name"] = service_name
        response.headers["X-Content-Type-Options"] = "nosniff"
        response.headers["X-Frame-Options"] = "DENY"
        response.headers["Cache-Control"] = "no-store"
        return response

    # turns a ValidationError into a clean 400 answer
    @app.errorhandler(ValidationError)
    def handle_validation(e):
        return bad_request(e.message, e.details)

    # if the database fails i log the real error and only send a general 500 to the client
    @app.errorhandler(sqlite3.Error)
    def handle_db_error(e):
        log.exception("Database error: %s", e)
        return error_response("A database error occurred", 500)

    # used when the body is not valid json
    @app.errorhandler(400)
    def handle_400(e):
        return bad_request("Bad request: the body must be valid JSON")

    # answers 404 when someone calls a route that does not exist
    @app.errorhandler(404)
    def handle_404(e):
        return not_found("Endpoint not found")

    # answers 405 when the route exists but not with this method
    @app.errorhandler(405)
    def handle_405(e):
        return error_response("Method not allowed", 405)

    # stops requests whose body is bigger than the limit
    @app.errorhandler(413)
    def handle_413(e):
        return error_response(f"Request body too large (max {MAX_BODY_BYTES} bytes)", 413)

    # rejects bodies that are not application/json
    @app.errorhandler(415)
    def handle_415(e):
        return error_response("Content-Type must be application/json", 415)

    # catches any error i did not expect so the server never shows a stack trace
    @app.errorhandler(Exception)
    def handle_unexpected(e):
        from werkzeug.exceptions import HTTPException
        if isinstance(e, HTTPException):
            return error_response(e.description or e.name, e.code)
        log.exception("Unhandled error: %s", e)
        return error_response("Internal server error", 500)

    # simple route to check if the service is running
    @app.route("/health", methods=["GET"])
    def health():
        return {"status": "success", "service": service_name}, 200

    return app


# starts the app on the given port, with https only if it is enabled in .env
def run(app, port):
    from shared.config import FLASK_DEBUG, HOST, SSL_CERT_FILE, SSL_KEY_FILE, USE_HTTPS
    ssl_context = (SSL_CERT_FILE, SSL_KEY_FILE) if USE_HTTPS else None
    app.run(host=HOST, port=port, debug=FLASK_DEBUG, threaded=True, ssl_context=ssl_context)
