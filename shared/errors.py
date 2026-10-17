"""
Uniform JSON responses for every service.

Errors always look like:   {"status": "error",   "message": "..."}
Success always looks like: {"status": "success", "message": "...", "data": ...}
"""
from flask import jsonify


def success(message, data=None, status_code=200, **extra):
    body = {"status": "success", "message": message}
    if data is not None:
        body["data"] = data
    body.update(extra)
    return jsonify(body), status_code


def error_response(message, status_code, details=None):
    body = {"status": "error", "message": message}
    if details:
        body["details"] = details
    return jsonify(body), status_code


def bad_request(message, details=None):        # validation errors
    return error_response(message, 400, details)


def unauthorized(message="Authentication required"):   # not logged in / bad token
    return error_response(message, 401)


def forbidden(message="User does not have permission to perform this operation"):
    return error_response(message, 403)


def not_found(message="Resource not found"):
    return error_response(message, 404)


def conflict(message):                         # duplicates
    return error_response(message, 409)


def service_unavailable(message):
    return error_response(message, 503)


class ValidationError(Exception):
    """Raised by validators; turned into a 400 response by the app error handler."""

    def __init__(self, message, details=None):
        super().__init__(message)
        self.message = message
        self.details = details
