"""
Authentication support for the Covecta Tools SDK.

Provides Cognito client-credentials token management for standalone use.
The ToolHubClient manages its own tokens internally, so this module is
only needed if you want lower-level control over token lifecycle.
"""

import os
import time
import logging
from typing import Optional, Dict

import requests as _requests

logger = logging.getLogger(__name__)


class AuthenticationError(Exception):
    """Authentication error."""
    pass


class AuthenticatedSession:
    """
    Manages a Cognito client-credentials session with auto-refresh.

    Usage:
        session = AuthenticatedSession(
            token_url="https://xxx.auth.region.amazoncognito.com/oauth2/token",
            client_id="your-client-id",
            client_secret="your-client-secret",
        )
        headers = session.get_auth_headers()  # {"Authorization": "Bearer ..."}
    """

    def __init__(
        self,
        token_url: str = None,
        client_id: str = None,
        client_secret: str = None,
        token_scopes: str = "covecta-api/tools.read covecta-api/tools.invoke",
        request_timeout: float = 30.0,
        auth_token: str = None,
    ):
        """
        Args:
            token_url: Cognito OAuth2 token endpoint URL
            client_id: Cognito App Client ID
            client_secret: Cognito App Client Secret
            token_scopes: OAuth2 scopes for client credentials flow
            request_timeout: HTTP timeout for token requests in seconds
            auth_token: Pre-obtained auth token (optional, skips Cognito)
        """
        self._auth_token = auth_token
        self._token_url = token_url or os.environ.get('COGNITO_TOKEN_URL')
        self._client_id = client_id or os.environ.get('COGNITO_CLIENT_ID')
        self._client_secret = client_secret or os.environ.get('COGNITO_CLIENT_SECRET')
        self._token_scopes = token_scopes
        self._request_timeout = request_timeout
        self._token_expires_at: float = 0

        if auth_token:
            logger.debug("Using provided auth token")
        elif self._token_url and self._client_id and self._client_secret:
            logger.debug("Client credentials flow configured (token_url=%s)", self._token_url)
        else:
            logger.debug("No authentication configured")

    def get_auth_headers(self) -> Dict[str, str]:
        """Get authentication headers for API requests."""
        token = self.get_token()
        if token:
            return {'Authorization': f'Bearer {token}'}
        return {}

    def get_token(self) -> Optional[str]:
        """
        Get a valid authentication token, refreshing automatically if needed.

        Returns:
            Valid token string, or None if not authenticated
        """
        # Client credentials flow -- auto-fetch/refresh
        if self._token_url and self._client_id and self._client_secret:
            if self._auth_token and time.time() < self._token_expires_at - 60:
                return self._auth_token
            return self._refresh_client_credentials()

        # Static token
        if self._auth_token:
            return self._auth_token

        return None

    def _refresh_client_credentials(self) -> str:
        """Fetch a new access token using the OAuth2 client credentials grant."""
        logger.debug("Requesting new access token via client credentials")
        response = _requests.post(
            self._token_url,
            data={
                "grant_type": "client_credentials",
                "client_id": self._client_id,
                "client_secret": self._client_secret,
                "scope": self._token_scopes,
            },
            headers={"Content-Type": "application/x-www-form-urlencoded"},
            timeout=self._request_timeout,
        )
        response.raise_for_status()

        token_data = response.json()
        self._auth_token = token_data["access_token"]
        self._token_expires_at = time.time() + token_data.get("expires_in", 3600)
        logger.debug("Successfully obtained access token via client credentials")
        return self._auth_token

    def is_authenticated(self) -> bool:
        """Check if the session is authenticated."""
        return self.get_token() is not None


def create_session(
    token_url: str = None,
    client_id: str = None,
    client_secret: str = None,
    auth_token: str = None,
    **kwargs
) -> AuthenticatedSession:
    """
    Create an authenticated session.

    For client credentials (machine-to-machine):
        session = create_session(
            token_url="https://xxx.auth.region.amazoncognito.com/oauth2/token",
            client_id="your-client-id",
            client_secret="your-client-secret",
        )

    For pre-obtained tokens:
        session = create_session(auth_token="eyJ...")
    """
    return AuthenticatedSession(
        auth_token=auth_token,
        token_url=token_url,
        client_id=client_id,
        client_secret=client_secret,
        **kwargs,
    )
