import logging

import requests

from shared.config import (SERVICE_API_KEY, SERVICE_TIMEOUT_SECONDS, USE_HTTPS, SSL_CERT_FILE)

log = logging.getLogger("service_client")
SERVICE_KEY_HEADER = "X-Service-Key"


class ServiceClient:
    # saves the base url of the service i want to call
    def __init__(self, base_url):
        self.base_url = base_url.rstrip("/")

    # does the actual http call with the service key and never crashes if the other service is down
    def _request(self, method, path, **kwargs):
        headers = kwargs.pop("headers", {})
        headers[SERVICE_KEY_HEADER] = SERVICE_API_KEY
        try:
            response = requests.request(
                method, f"{self.base_url}{path}", headers=headers,
                timeout=SERVICE_TIMEOUT_SECONDS,
                verify=SSL_CERT_FILE if USE_HTTPS else True,
                **kwargs,
            )
            try:
                body = response.json()
            except ValueError:
                body = {}
            return response.status_code, body
        except requests.RequestException as exc:
            log.warning("Call %s %s%s failed: %s", method, self.base_url, path, exc)
            return None, {}

    # shortcut for a get request
    def get(self, path, **kwargs):
        return self._request("GET", path, **kwargs)

    # shortcut for a post request with a json body
    def post(self, path, json=None, **kwargs):
        return self._request("POST", path, json=json, **kwargs)
