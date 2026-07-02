"""HTTP transport for the Phoenix Security API.

Implements the platform conventions:
  - Token: GET /v1/auth/access_token with HTTP Basic (client_id:client_secret),
    response {"token": ..., "expiry": <unix-ts>}. The token is cached and
    refreshed when <5 minutes of validity remain, and re-acquired once on 401.
  - Retries: 429/503 honour the Retry-After header (default 5s); 5xx retried
    with exponential backoff + jitter; bounded attempts.
  - Pagination: pageNumber/pageSize query params, standard paged envelope
    with content/totalPages/last.
"""

import base64
import random
import time

import requests

from phoenix_cli.errors import PhoenixAPIError, PhoenixAuthError

TOKEN_PATH = "/v1/auth/access_token"
TOKEN_REFRESH_MARGIN = 300   # refresh when <5 min validity left
MAX_RETRIES = 3
BACKOFF_BASE = 2.0
BACKOFF_MAX = 30.0
RETRIABLE_STATUSES = (429, 500, 502, 503, 504)


class Transport:
    """Authenticated HTTP session against one Phoenix API environment.

    Exposes only inputs (method, path, params, JSON body) and outputs
    (decoded JSON) — token management and retries are internal.
    """

    def __init__(self, client_id, client_secret, base_url, timeout=60,
                 verify_tls=True, user_agent="phoenix-security-cli"):
        self._client_id = client_id
        self._client_secret = client_secret
        self.base_url = base_url.rstrip("/")
        self.timeout = timeout
        self._session = requests.Session()
        self._session.verify = verify_tls
        self._session.headers["User-Agent"] = user_agent
        self._token = None
        self._token_expiry = 0.0

    # -- token lifecycle ----------------------------------------------------

    def authenticate(self):
        """Fetch a fresh access token. Returns the token metadata dict."""
        creds = f"{self._client_id}:{self._client_secret}".encode("utf-8")
        auth_header = "Basic " + base64.b64encode(creds).decode("ascii")
        response = self._session.get(
            self.base_url + TOKEN_PATH,
            headers={"Authorization": auth_header},
            timeout=self.timeout,
        )
        if response.status_code == 401:
            raise PhoenixAuthError(
                "Authentication failed (401): client_id/client_secret rejected "
                f"by {self.base_url}. Verify the credentials (Organisation > "
                "API Access) and that they belong to this environment."
            )
        if response.status_code != 200:
            raise PhoenixAPIError(response.status_code, _safe_text(response),
                                  "GET", TOKEN_PATH)
        data = response.json()
        self._token = data.get("token")
        # Server returns an absolute unix timestamp; fall back to +1h.
        self._token_expiry = float(data.get("expiry") or (time.time() + 3600))
        if not self._token:
            raise PhoenixAuthError("Token endpoint returned no 'token' field.")
        return {"expiry": self._token_expiry}

    def _ensure_token(self):
        if not self._token or time.time() > (self._token_expiry - TOKEN_REFRESH_MARGIN):
            self.authenticate()
        return self._token

    # -- request core -------------------------------------------------------

    def request(self, method, path, params=None, json_body=None,
                expect_json=True):
        """Perform an authenticated request; returns decoded JSON (or None
        for empty bodies such as 204 responses)."""
        url = self.base_url + path
        reauthenticated = False
        attempt = 0
        while True:
            token = self._ensure_token()
            headers = {
                "Authorization": f"Bearer {token}",
                "Content-Type": "application/json",
            }
            response = self._session.request(
                method, url, params=params, json=json_body,
                headers=headers, timeout=self.timeout,
            )

            if response.status_code == 401 and not reauthenticated:
                # Token invalid/expired despite local expiry check: re-auth once.
                self._token = None
                reauthenticated = True
                continue

            if response.status_code in RETRIABLE_STATUSES and attempt < MAX_RETRIES:
                attempt += 1
                time.sleep(_retry_delay(response, attempt))
                continue

            if response.status_code >= 400:
                raise PhoenixAPIError(response.status_code, _safe_text(response),
                                      method, path)

            if not expect_json or response.status_code == 204 or not response.content:
                return None
            try:
                return response.json()
            except ValueError:
                # Some success responses (e.g. import) may return empty/plain
                # bodies — surface raw text instead of failing.
                return {"raw": response.text}

    # -- pagination ---------------------------------------------------------

    def paginate(self, method, path, params=None, json_body=None,
                 page_size=100, max_items=None):
        """Iterate a paged endpoint, yielding items from each page's
        'content'. Follows the standard envelope (totalPages/last)."""
        params = dict(params or {})
        page_number = 0
        yielded = 0
        while True:
            params.update({"pageNumber": page_number, "pageSize": page_size})
            page = self.request(method, path, params=params, json_body=json_body)
            content = (page or {}).get("content") or []
            for item in content:
                yield item
                yielded += 1
                if max_items and yielded >= max_items:
                    return
            if not content or page.get("last") is True:
                return
            total_pages = page.get("totalPages")
            page_number += 1
            if total_pages is not None and page_number >= int(total_pages):
                return


def _retry_delay(response, attempt):
    retry_after = response.headers.get("Retry-After")
    if retry_after:
        try:
            return max(1.0, float(retry_after))
        except ValueError:
            pass
    exp = min(BACKOFF_MAX, BACKOFF_BASE ** attempt)
    return exp + random.uniform(0, 0.1 * exp)


def _safe_text(response, limit=500):
    try:
        text = response.text or ""
    except Exception:
        text = ""
    return text[:limit]
