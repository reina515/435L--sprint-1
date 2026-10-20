from flask import jsonify


# every successful answer goes through here so they all have the same json shape
def success(message, data=None, status_code=200, **extra):
    body = {"status": "success", "message": message}
    if data is not None:
        body["data"] = data
    body.update(extra)
    return jsonify(body), status_code


# builds the json error answer with a status of error and a message
def error_response(message, status_code, details=None):
    body = {"status": "error", "message": message}
    if details:
        body["details"] = details
    return jsonify(body), status_code


# 400 when the input is wrong
def bad_request(message, details=None):
    return error_response(message, 400, details)


# 401 when the user is not logged in or the token is bad
def unauthorized(message="Authentication required"):
    return error_response(message, 401)


# 403 when the user is logged in but not allowed to do this
def forbidden(message="User does not have permission to perform this operation"):
    return error_response(message, 403)


# 404 when the record does not exist
def not_found(message="Resource not found"):
    return error_response(message, 404)


# 409 for duplicates like an existing username
def conflict(message):
    return error_response(message, 409)


# 503 when another service i depend on is down
def service_unavailable(message):
    return error_response(message, 503)


class ValidationError(Exception):
    # keeps the message and the details so the handler can send them back as a 400
    def __init__(self, message, details=None):
        super().__init__(message)
        self.message = message
        self.details = details
