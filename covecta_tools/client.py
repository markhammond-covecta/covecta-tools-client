"""
ToolHubClient - Multi-tenant client for the Tool Hub API.

Every request is scoped to a tenant namespace via a signed RS256 assertion.
The client holds a single set of credentials (OAuth2 client + signing key)
and creates per-tenant assertions at runtime.

Usage:
    from covecta_tools import ToolHubClient, ToolHubConfig

    config = ToolHubConfig(
        api_url="https://facade.amazonaws.com",
        cognito_token_url="https://xxx.auth.region.amazoncognito.com/oauth2/token",
        client_id="your-client-id",
        client_secret="your-client-secret",
        signing_private_key=open("private.pem").read(),
        signing_key_id="your-key-id",
    )

    client = ToolHubClient(config)
    tools = client.list_tools(namespace="AcmeCorp", user_id="jane@acme.com")
"""

import json
import time
import hashlib
import secrets
import logging
from pathlib import Path
from typing import Optional, Dict, Any, List
from dataclasses import dataclass

import requests
from requests.exceptions import RequestException, Timeout, ConnectionError as RequestsConnectionError

from covecta_tools.exceptions import (
    CovectaToolsException,
    CovectaToolsConnectionError,
    CovectaToolsNotFoundError,
    CovectaToolsValidationError,
    CovectaToolsServerError,
    CovectaToolsTimeoutError,
    CovectaToolsBadGatewayError,
)
from covecta_tools.models import ToolSummary, ToolDetails, InvokeToolRequest, TemplateSummary

logger = logging.getLogger(__name__)

# JWT and crypto imports (required for tenant assertions)
try:
    import jwt
    from cryptography.hazmat.primitives import serialization
    from cryptography.hazmat.backends import default_backend
    JWT_AVAILABLE = True
except ImportError:
    JWT_AVAILABLE = False
    logger.warning("PyJWT or cryptography not available - install with: pip install PyJWT cryptography")


# =============================================================================
# Configuration
# =============================================================================

@dataclass
class ToolHubConfig:
    """Configuration for the Tool Hub client."""

    # Tool Hub API endpoint (facade URL)
    api_url: str

    # Cognito OAuth2 token endpoint
    cognito_token_url: str

    # Application credentials (OAuth2 client credentials)
    client_id: str
    client_secret: str

    # Signing key for tenant assertions (RS256)
    signing_private_key: str  # PEM-encoded RSA private key
    signing_key_id: str       # Key ID registered in Tool Hub (kid header)

    # Optional: direct registry Lambda URL for admin operations (namespace management)
    registry_url: str = ''

    # Optional settings
    token_scopes: str = "covecta-api/tools.read covecta-api/tools.invoke"
    request_timeout: float = 30.0
    assertion_validity_seconds: int = 60

    @classmethod
    def from_cli_config(cls, namespace: Optional[str] = None) -> "ToolHubConfig":
        """Load configuration from the CLI config file (~/.toolhub/config.json).

        Reads the same config file used by ``covecta auth setup``.  If a
        *namespace* is provided, looks for a matching profile and uses its
        credentials; otherwise uses the default (top-level) credentials.

        Args:
            namespace: If provided, select the profile whose ``namespaces``
                list contains this value.

        Returns:
            A fully populated ToolHubConfig.

        Raises:
            FileNotFoundError: If ~/.toolhub/config.json does not exist.
            ValueError: If required fields are missing from the config.
        """
        config_file = Path.home() / ".toolhub" / "config.json"
        if not config_file.exists():
            raise FileNotFoundError(
                f"{config_file} not found. Run 'covecta auth setup' first."
            )

        with open(config_file) as f:
            data = json.load(f)

        # Resolve profile if namespace is provided
        creds = data  # default: top-level credentials
        if namespace:
            for _name, pdata in data.get("profiles", {}).items():
                if namespace in pdata.get("namespaces", []):
                    # Merge: profile credentials override top-level
                    creds = {**data, **pdata}
                    break

        api_url = creds.get("api_url", "")
        token_url = creds.get("token_url", "")
        client_id = creds.get("client_id", "")
        client_secret = creds.get("client_secret", "")
        key_id = creds.get("assertion_key_id", "")
        key_file = creds.get("assertion_key_file", "")

        if not api_url:
            raise ValueError("api_url not found in config. Run 'covecta auth setup'.")
        if not token_url:
            raise ValueError("token_url not found in config. Run 'covecta auth setup'.")

        # Load private key PEM from file
        private_key_pem = ""
        if key_file:
            key_path = Path(key_file).expanduser().resolve()
            if key_path.exists():
                private_key_pem = key_path.read_text()
            else:
                logger.warning(f"Assertion key file not found: {key_path}")

        return cls(
            api_url=api_url,
            cognito_token_url=token_url,
            client_id=client_id,
            client_secret=client_secret,
            signing_private_key=private_key_pem,
            signing_key_id=key_id,
            registry_url=creds.get("registry_url", ""),
        )


# =============================================================================
# Assertion Signer
# =============================================================================

class TenantAssertionSigner:
    """Creates signed JWT assertions for tenant identity."""

    def __init__(self, private_key_pem: str, key_id: str):
        """
        Args:
            private_key_pem: PEM-encoded RSA private key
            key_id: Key identifier (Tool Hub uses this to find the public key)
        """
        if not JWT_AVAILABLE:
            raise RuntimeError("PyJWT and cryptography packages required: pip install PyJWT cryptography")

        self.private_key = serialization.load_pem_private_key(
            private_key_pem.encode() if isinstance(private_key_pem, str) else private_key_pem,
            password=None,
            backend=default_backend()
        )
        self.key_id = key_id

    def create_assertion(
        self,
        tenant_id: str,
        user_id: Optional[str] = None,
        validity_seconds: int = 60
    ) -> str:
        """
        Create a signed tenant assertion.

        Args:
            tenant_id: The tenant/namespace identifier
            user_id: Optional end-user identifier for audit trail
            validity_seconds: How long the assertion is valid

        Returns:
            Signed JWT assertion string
        """
        now = int(time.time())

        payload = {
            "iat": now,
            "exp": now + validity_seconds,
            "nbf": now,
            "tenant_id": tenant_id,
            "assertion_type": "tenant_context",
            "acting_user": user_id,
            "jti": secrets.token_hex(16)
        }

        headers = {
            "kid": self.key_id,
            "typ": "JWT",
            "alg": "RS256"
        }

        return jwt.encode(payload, self.private_key, algorithm="RS256", headers=headers)


# =============================================================================
# Client
# =============================================================================

class ToolHubClient:
    """
    Client for accessing Tool Hub with multi-tenant namespace isolation.

    Holds a single set of credentials (OAuth2 client + signing key) and creates
    per-tenant assertions at runtime based on which tenant is active:

        client = ToolHubClient(config)

        # Serve tenant A
        tools_a = client.list_tools(namespace="TenantA", user_id="alice@a.com")

        # Serve tenant B (same client, different namespace)
        tools_b = client.list_tools(namespace="TenantB", user_id="bob@b.com")

    Each API call creates a fresh, short-lived assertion for the specified
    tenant. The assertion is cryptographically signed so the tenant identity
    cannot be tampered with in transit.

    Security model:
    - OAuth2 access token proves the *application* identity (who is calling?)
    - Tenant assertion proves the *namespace* binding (for which tenant?)
    - Both are required: Cognito validates the app, Tool Hub validates the tenant

    The application must be pre-authorized for each tenant namespace via
    `covecta client authorize-namespace --client-id <id> --namespace <ns>`.
    """

    def __init__(self, config: ToolHubConfig):
        """
        Args:
            config: ToolHubConfig with API URLs, credentials, and signing key
        """
        self.config = config
        self.signer = TenantAssertionSigner(
            config.signing_private_key,
            config.signing_key_id
        )

        # Token cache
        self._access_token: Optional[str] = None
        self._token_expires_at: float = 0

        # HTTP session for connection pooling
        self._session = requests.Session()

        logger.info(f"ToolHubClient initialized for {config.api_url}")

    def _get_access_token(self) -> str:
        """Get a valid access token, refreshing if necessary."""
        if self._access_token and time.time() < self._token_expires_at - 60:
            return self._access_token

        logger.debug("Requesting new access token from Cognito")
        response = self._session.post(
            self.config.cognito_token_url,
            data={
                "grant_type": "client_credentials",
                "client_id": self.config.client_id,
                "client_secret": self.config.client_secret,
                "scope": self.config.token_scopes
            },
            headers={"Content-Type": "application/x-www-form-urlencoded"},
            timeout=self.config.request_timeout
        )
        response.raise_for_status()

        token_data = response.json()
        self._access_token = token_data["access_token"]
        self._token_expires_at = time.time() + token_data.get("expires_in", 3600)

        logger.debug("Successfully obtained access token")
        return self._access_token

    # =========================================================================
    # Response Handling
    # =========================================================================

    @staticmethod
    def _handle_response(response: requests.Response) -> Dict[str, Any]:
        """
        Handle HTTP response and raise appropriate exceptions.

        Returns:
            Parsed JSON response data

        Raises:
            CovectaToolsNotFoundError: For 404 responses
            CovectaToolsValidationError: For 422 validation errors
            CovectaToolsBadGatewayError: For 502 bad gateway errors
            CovectaToolsTimeoutError: For 504 timeout errors
            CovectaToolsServerError: For 5xx server errors
            CovectaToolsException: For other error responses
        """
        try:
            error_detail = response.json()
        except ValueError:
            error_detail = {"detail": response.text or "Unknown error"}

        status_code = response.status_code

        def extract_message(detail_obj, max_depth=10):
            if max_depth <= 0:
                return str(detail_obj) if detail_obj is not None else "Unknown error"
            if detail_obj is None:
                return "Unknown error"
            if isinstance(detail_obj, dict):
                if "detail" in detail_obj:
                    nested = detail_obj["detail"]
                    if isinstance(nested, str):
                        return nested
                    elif isinstance(nested, dict):
                        return extract_message(nested, max_depth - 1)
                if "message" in detail_obj:
                    msg = detail_obj["message"]
                    if isinstance(msg, str):
                        return msg
                if len(detail_obj) == 1:
                    key, value = next(iter(detail_obj.items()))
                    if isinstance(value, str):
                        return value
                    elif isinstance(value, dict):
                        return extract_message(value, max_depth - 1)
                return str(detail_obj)
            elif isinstance(detail_obj, str):
                return detail_obj
            else:
                return str(detail_obj)

        if status_code == 404:
            detail_value = error_detail.get("detail", "Resource not found")
            detail = extract_message(detail_value)
            if not isinstance(detail, str):
                detail = str(detail)
            raise CovectaToolsNotFoundError(
                message=detail, status_code=status_code, detail=error_detail
            )
        elif status_code == 422:
            raise CovectaToolsValidationError(
                message="Request validation failed", status_code=status_code, detail=error_detail
            )
        elif status_code == 502:
            detail = extract_message(error_detail.get("detail", "Bad gateway error"))
            raise CovectaToolsBadGatewayError(
                message=detail, status_code=status_code, detail=error_detail
            )
        elif status_code == 504:
            detail = extract_message(error_detail.get("detail", "Request timed out"))
            raise CovectaToolsTimeoutError(
                message=detail, status_code=status_code, detail=error_detail
            )
        elif 400 <= status_code < 500:
            detail = extract_message(error_detail.get("detail", "Client error"))
            raise CovectaToolsException(
                message=detail, status_code=status_code, detail=error_detail
            )
        elif status_code >= 500:
            detail = extract_message(error_detail.get("detail", "Server error"))
            raise CovectaToolsServerError(
                message=detail, status_code=status_code, detail=error_detail
            )

        # Success (2xx)
        if not response.content:
            return {}

        try:
            return response.json()
        except ValueError:
            return {
                "content": response.text,
                "content_type": response.headers.get("Content-Type", "unknown"),
                "note": "Response was not JSON-encoded"
            }

    # =========================================================================
    # Request Helpers
    # =========================================================================

    def _make_request(
        self,
        method: str,
        endpoint: str,
        namespace: str,
        user_id: Optional[str] = None,
        params: Optional[Dict[str, Any]] = None,
        json_data: Optional[Dict[str, Any]] = None,
    ) -> Dict[str, Any]:
        """
        Make an authenticated request with tenant assertion.

        Args:
            method: HTTP method
            endpoint: API endpoint (e.g., "/tools")
            namespace: Tenant namespace to access
            user_id: Optional end-user ID for audit
            params: Query parameters
            json_data: JSON request body
        """
        access_token = self._get_access_token()

        tenant_assertion = self.signer.create_assertion(
            tenant_id=namespace,
            user_id=user_id,
            validity_seconds=self.config.assertion_validity_seconds
        )

        headers = {
            "Authorization": f"Bearer {access_token}",
            "X-Tenant-Assertion": tenant_assertion,
            "Content-Type": "application/json"
        }

        url = f"{self.config.api_url.rstrip('/')}{endpoint}"

        try:
            response = self._session.request(
                method,
                url,
                headers=headers,
                params=params,
                json=json_data,
                timeout=self.config.request_timeout,
            )
            return self._handle_response(response)
        except RequestsConnectionError as e:
            raise CovectaToolsConnectionError(
                message=f"Unable to connect to Tool Hub at {self.config.api_url}: {e}"
            )
        except Timeout:
            raise CovectaToolsTimeoutError(
                message=f"Request to {url} timed out after {self.config.request_timeout} seconds"
            )
        except RequestException as e:
            raise CovectaToolsConnectionError(
                message=f"Request failed: {e}"
            )

    # =========================================================================
    # Public API
    # =========================================================================

    def list_tools(
        self,
        namespace: str,
        user_id: Optional[str] = None
    ) -> List[ToolSummary]:
        """
        List all tools available in a namespace.

        Args:
            namespace: Tenant namespace
            user_id: End-user making the request (for audit)

        Returns:
            List of ToolSummary objects
        """
        response = self._make_request(
            "GET", "/tools",
            namespace=namespace, user_id=user_id
        )
        tools_data = response.get("tools", [])
        return [ToolSummary(**tool) for tool in tools_data]

    def get_tool(
        self,
        tool_name: str,
        namespace: str,
        user_id: Optional[str] = None
    ) -> ToolDetails:
        """
        Get details about a specific tool.

        Args:
            tool_name: Name of the tool
            namespace: Tenant namespace
            user_id: End-user making the request

        Returns:
            ToolDetails object with complete tool information
        """
        response = self._make_request(
            "GET", f"/tools/{tool_name}",
            namespace=namespace, user_id=user_id
        )

        # Defense in depth: strip fields the facade should already filter
        response.pop("namespaces", None)
        response.pop("metadata", None)

        if "functions" in response:
            for function_name, function_data in response["functions"].items():
                if isinstance(function_data, dict):
                    if "parameters" in function_data and isinstance(function_data["parameters"], list):
                        function_data["parameters"] = [
                            p for p in function_data["parameters"]
                            if p != "namespace"
                        ]
                    if "parameters_schema" in function_data and isinstance(function_data["parameters_schema"], dict):
                        function_data["parameters_schema"].pop("namespace", None)

        return ToolDetails(**response)

    def invoke_tool(
        self,
        tool_name: str,
        parameters: Dict[str, Any],
        namespace: str,
        user_id: Optional[str] = None,
        function: Optional[str] = None,
        correlation_id: Optional[str] = None,
        idempotency_key: Optional[str] = None,
        nocache: bool = False,
    ) -> Dict[str, Any]:
        """
        Invoke a tool.

        Args:
            tool_name: Name of the tool to invoke
            parameters: Tool parameters
            namespace: Tenant namespace
            user_id: End-user making the request
            function: Specific function to call (optional)
            correlation_id: Caller-supplied trace ID (max 128 chars); echoed in
                X-Correlation-ID response header and stored in consumption records
            idempotency_key: Deduplication key (max 256 chars); identical key +
                payload within 60 s returns the cached response without re-invoking
                the tool. Response includes X-Idempotent-Replay: true on a replay.
            nocache: If True, bypass the response cache for this request

        Returns:
            Tool execution result
        """
        request_body = InvokeToolRequest(parameters=parameters)
        try:
            json_data = request_body.model_dump()
        except AttributeError:
            json_data = request_body.dict()

        params: Dict[str, Any] = {}
        if function:
            params["method"] = function
        if correlation_id:
            params["correlation_id"] = correlation_id
        if idempotency_key:
            params["idempotency_key"] = idempotency_key
        if nocache:
            params["nocache"] = "true"

        return self._make_request(
            "POST", f"/tools/{tool_name}/invoke",
            namespace=namespace, user_id=user_id,
            params=params or None,
            json_data=json_data,
        )

    def list_templates(
        self,
        namespace: str,
        user_id: Optional[str] = None
    ) -> List[TemplateSummary]:
        """
        List templates available in a namespace.

        Args:
            namespace: Tenant namespace
            user_id: End-user making the request (for audit)

        Returns:
            List of TemplateSummary objects
        """
        response = self._make_request(
            "GET", "/templates",
            namespace=namespace, user_id=user_id
        )
        templates_data = response.get("templates", [])
        return [TemplateSummary(**t) for t in templates_data]

    def get_template(
        self,
        template_name: str,
        namespace: str,
        user_id: Optional[str] = None
    ) -> Dict[str, Any]:
        """
        Get a template definition.

        Args:
            template_name: Name of the template
            namespace: Tenant namespace
            user_id: End-user making the request (for audit)

        Returns:
            Template definition as a dict
        """
        return self._make_request(
            "GET", f"/templates/{template_name}",
            namespace=namespace, user_id=user_id
        )

    def invoke_template(
        self,
        template_name: str,
        input_data: Dict[str, Any],
        namespace: str,
        user_id: Optional[str] = None,
        correlation_id: Optional[str] = None,
        idempotency_key: Optional[str] = None,
    ) -> Dict[str, Any]:
        """
        Invoke a saved template with input data.

        Args:
            template_name: Name of the template to invoke
            input_data: Input data for the template parameters
            namespace: Tenant namespace
            user_id: End-user making the request (for audit)
            correlation_id: Caller-supplied trace ID (max 128 chars)
            idempotency_key: Deduplication key (max 256 chars)

        Returns:
            Template execution result
        """
        return self.invoke_tool(
            tool_name=template_name,
            parameters=input_data,
            namespace=namespace,
            user_id=user_id,
            function="invoke",
            correlation_id=correlation_id,
            idempotency_key=idempotency_key,
        )

    # =========================================================================
    # Namespace Management (Registry Direct)
    # =========================================================================

    def _registry_request(self, method: str, path: str, **kwargs) -> Dict[str, Any]:
        """Make a SigV4-signed request to the registry Lambda.

        Args:
            method: HTTP method.
            path: URL path (appended to registry_url).
            **kwargs: Passed to requests.request().

        Returns:
            Parsed JSON response.

        Raises:
            CovectaToolsException: If registry_url is not configured.
        """
        if not self.config.registry_url:
            raise CovectaToolsException(
                message="registry_url must be configured for namespace management"
            )
        url = f"{self.config.registry_url.rstrip('/')}{path}"
        try:
            from aws.sigv4_request import sigv4_request
            response = sigv4_request(method, url, **kwargs)
        except ImportError:
            # Fall back to unsigned request (for local development)
            response = self._session.request(
                method, url, timeout=self.config.request_timeout, **kwargs
            )
        return self._handle_response(response)

    def create_namespace(
        self,
        namespace: str,
        description: str = '',
        metadata: Optional[Dict[str, Any]] = None,
    ) -> Dict[str, Any]:
        """Create a new namespace with automatic security provisioning.

        Args:
            namespace: Unique namespace identifier.
            description: Purpose / notes.
            metadata: Arbitrary key-value metadata.

        Returns:
            Namespace record with credentials (one-time only).
        """
        body = {
            'namespace': namespace,
            'description': description,
            'metadata': metadata or {},
        }
        return self._registry_request('POST', '/namespaces', json=body)

    def list_namespaces(self) -> List[Dict[str, Any]]:
        """List all provisioned namespaces.

        Returns:
            List of namespace records.
        """
        result = self._registry_request('GET', '/namespaces')
        return result.get('namespaces', [])

    def get_namespace(self, namespace: str) -> Dict[str, Any]:
        """Get namespace detail including tool count.

        Args:
            namespace: Namespace identifier.

        Returns:
            Namespace record.
        """
        return self._registry_request('GET', f'/namespaces/{namespace}')

    def update_namespace(self, namespace: str, **fields) -> Dict[str, Any]:
        """Update namespace metadata.

        Args:
            namespace: Namespace identifier.
            **fields: Fields to update (description, metadata).

        Returns:
            Updated namespace record.
        """
        body = {k: v for k, v in fields.items() if v is not None}
        return self._registry_request('PUT', f'/namespaces/{namespace}', json=body)

    def delete_namespace(self, namespace: str) -> Dict[str, Any]:
        """Delete a namespace and cascade-clean security artifacts.

        The namespace must have no tools assigned.

        Args:
            namespace: Namespace identifier.

        Returns:
            Deletion confirmation with cleanup summary.
        """
        return self._registry_request('DELETE', f'/namespaces/{namespace}')

    # =========================================================================
    # Client access management
    # =========================================================================

    def list_clients(self, namespace: str) -> List[Dict[str, Any]]:
        """List all clients authorized for a namespace.

        Args:
            namespace: Namespace identifier.

        Returns:
            List of client records (without credentials).
        """
        result = self._registry_request('GET', f'/namespaces/{namespace}/clients')
        return result.get('clients', [])

    def grant_access(
        self,
        namespace: str,
        name: str,
        role: str = 'consumer',
        permissions: Optional[List[str]] = None,
    ) -> Dict[str, Any]:
        """Grant a new client access to a namespace.

        Args:
            namespace: Namespace to grant access to.
            name: Human-readable label for the client.
            role: One of 'owner', 'admin', 'consumer'.
            permissions: Explicit permission overrides (optional).

        Returns:
            Dict with client_id, role, permissions, and one-time credentials.
        """
        body: Dict[str, Any] = {'name': name, 'role': role}
        if permissions:
            body['permissions'] = permissions
        return self._registry_request('POST', f'/namespaces/{namespace}/clients', json=body)

    def revoke_access(self, namespace: str, client_id: str) -> Dict[str, Any]:
        """Revoke a client's access to a namespace.

        Args:
            namespace: Namespace identifier.
            client_id: Client to revoke.

        Returns:
            Revocation confirmation.
        """
        return self._registry_request('DELETE', f'/namespaces/{namespace}/clients/{client_id}')

    def update_client(
        self,
        namespace: str,
        client_id: str,
        role: Optional[str] = None,
        permissions: Optional[List[str]] = None,
        name: Optional[str] = None,
    ) -> Dict[str, Any]:
        """Update a client's role or permissions.

        Args:
            namespace: Namespace identifier.
            client_id: Client to update.
            role: New role (optional).
            permissions: New explicit permissions (optional).
            name: New display name (optional).

        Returns:
            Updated client record.
        """
        body: Dict[str, Any] = {}
        if role is not None:
            body['role'] = role
        if permissions is not None:
            body['permissions'] = permissions
        if name is not None:
            body['name'] = name
        return self._registry_request('PATCH', f'/namespaces/{namespace}/clients/{client_id}', json=body)

    def rotate_client_keys(self, namespace: str, client_id: str) -> Dict[str, Any]:
        """Rotate signing keys for a client.

        Args:
            namespace: Namespace identifier.
            client_id: Client whose keys to rotate.

        Returns:
            Dict with new signing_key_id and signing_private_key_pem.
        """
        return self._registry_request('POST', f'/namespaces/{namespace}/clients/{client_id}/rotate-keys')

    def close(self):
        """Close the HTTP session."""
        self._session.close()

    def __enter__(self):
        return self

    def __exit__(self, *args):
        self.close()


# =============================================================================
# Convenience Functions
# =============================================================================

def create_client(
    api_url: str,
    token_url: str,
    client_id: str,
    client_secret: str,
    private_key: str,
    key_id: str,
    **kwargs
) -> ToolHubClient:
    """
    Create a client with the specified configuration.

    Args:
        api_url: Tool Hub API URL (facade endpoint)
        token_url: Cognito token endpoint URL
        client_id: OAuth2 client ID
        client_secret: OAuth2 client secret
        private_key: PEM-encoded RSA private key for signing
        key_id: Key ID for the signing key
        **kwargs: Additional ToolHubConfig options

    Returns:
        Configured ToolHubClient
    """
    config = ToolHubConfig(
        api_url=api_url,
        cognito_token_url=token_url,
        client_id=client_id,
        client_secret=client_secret,
        signing_private_key=private_key,
        signing_key_id=key_id,
        **kwargs
    )
    return ToolHubClient(config)


# =============================================================================
# Deprecated Aliases
# =============================================================================

# Backward compatibility — old names still work but emit a warning.
TenantConfig = ToolHubConfig
TenantToolHubClient = ToolHubClient
create_tenant_client = create_client
