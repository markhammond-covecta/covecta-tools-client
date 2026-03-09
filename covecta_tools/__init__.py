"""
Covecta Tools - Python SDK for the Tool Hub Service

All access is multi-tenant: every API call specifies a namespace.
The client manages Cognito token refresh and RS256 assertion signing.

    from covecta_tools import ToolHubClient, ToolHubConfig

    config = ToolHubConfig(...)
    client = ToolHubClient(config)
    tools = client.list_tools(namespace="AcmeCorp")
"""

from covecta_tools.client import (
    ToolHubClient,
    ToolHubConfig,
    TenantAssertionSigner,
    create_client,
    # Deprecated aliases (old names still importable)
    TenantConfig,
    TenantToolHubClient,
    create_tenant_client,
)
from covecta_tools.exceptions import (
    CovectaToolsException,
    CovectaToolsConnectionError,
    CovectaToolsNotFoundError,
    CovectaToolsValidationError,
    CovectaToolsServerError,
    CovectaToolsBadGatewayError,
    CovectaToolsTimeoutError,
)
from covecta_tools.models import (
    ToolSummary,
    ToolDetails,
    ToolFunction,
    FunctionParameter,
    InvokeToolRequest,
    TemplateSummary,
    NamespaceInfo,
)

__all__ = [
    # Client
    "ToolHubClient",
    "ToolHubConfig",
    "TenantAssertionSigner",
    "create_client",

    # Exceptions
    "CovectaToolsException",
    "CovectaToolsConnectionError",
    "CovectaToolsNotFoundError",
    "CovectaToolsValidationError",
    "CovectaToolsServerError",
    "CovectaToolsBadGatewayError",
    "CovectaToolsTimeoutError",

    # Models
    "ToolSummary",
    "ToolDetails",
    "ToolFunction",
    "FunctionParameter",
    "InvokeToolRequest",
    "TemplateSummary",
    "NamespaceInfo",

    # Deprecated aliases
    "TenantToolHubClient",
    "TenantConfig",
    "create_tenant_client",
]

__version__ = "3.0.0"
