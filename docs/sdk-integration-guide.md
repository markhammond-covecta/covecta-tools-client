# Covecta Tool Hub — Python SDK Integration Guide

A guide for core developers integrating tool calling into their applications using
the `covecta-tools` Python SDK.

---

## Overview

The SDK provides a single `ToolHubClient` class that handles authentication, tenant
assertion signing, and HTTP transport. Your application code calls high-level methods
(`list_tools`, `get_tool`, `invoke_tool`) without managing tokens or headers directly.

Before starting, complete the authentication setup described in
[Security & Access Control](security-and-access-control.md) — you will need a Cognito
App Client, an RSA signing key, and namespace authorization in place.

---

## Getting the SDK

Clone the client SDK repository and copy `covecta_tools/` into your project, or add
the cloned directory to your Python path:

```bash
git clone https://github.com/markhammond-covecta/covecta-tools-client.git
```

Then install the required dependencies:

```bash
pip install requests pydantic PyJWT cryptography
```

Or with the included requirements file:

```bash
pip install -r covecta-tools-client/requirements.txt
```

| Package | Purpose |
|---|---|
| `requests` | HTTP transport |
| `PyJWT` | Tenant assertion signing |
| `cryptography` | RSA key loading |
| `pydantic` | Response models |

---

## Configuration

All connection settings are supplied through a `ToolHubConfig` dataclass:

```python
from covecta_tools import ToolHubClient, ToolHubConfig

config = ToolHubConfig(
    # Tool Hub facade URL (from aws_endpoints.json or your admin)
    api_url="https://ccp11qppvc.execute-api.eu-west-1.amazonaws.com",

    # Cognito OAuth2 token endpoint
    cognito_token_url="https://toolhub-dev-025066243704.auth.eu-west-1.amazoncognito.com/oauth2/token",

    # OAuth2 client credentials (from Cognito App Client)
    client_id="your-cognito-client-id",
    client_secret="your-cognito-client-secret",

    # RSA private key for signing tenant assertions
    signing_private_key=open("my-app-private.pem").read(),
    signing_key_id="my-app-key-1",   # must match the kid registered in DynamoDB
)
```

### Optional config fields

| Field | Default | Description |
|---|---|---|
| `token_scopes` | `"covecta-api/tools.read covecta-api/tools.invoke"` | OAuth2 scopes to request |
| `request_timeout` | `30.0` | HTTP timeout in seconds |
| `assertion_validity_seconds` | `60` | How long each tenant assertion is valid |

### Loading credentials from the environment

Keep secrets out of source code by reading them at runtime:

```python
import os
from covecta_tools import ToolHubClient, ToolHubConfig

config = ToolHubConfig(
    api_url=os.environ["TOOLHUB_API_URL"],
    cognito_token_url=os.environ["COGNITO_TOKEN_URL"],
    client_id=os.environ["COGNITO_CLIENT_ID"],
    client_secret=os.environ["COGNITO_CLIENT_SECRET"],
    signing_private_key=os.environ["TOOLHUB_SIGNING_KEY"],   # PEM string
    signing_key_id=os.environ["TOOLHUB_KEY_ID"],
)
```

---

## Creating a Client

Use the client as a context manager so the HTTP session is closed on exit:

```python
with ToolHubClient(config) as client:
    # make calls here
    ...
```

Or manage the lifecycle manually:

```python
client = ToolHubClient(config)
try:
    # make calls here
    ...
finally:
    client.close()
```

The client is thread-safe for concurrent reads. Token refresh is handled internally.

---

## Listing Available Tools

`list_tools` returns every tool assigned to a namespace. The `user_id` argument is
optional but recommended — it appears in audit logs and consumption records.

```python
with ToolHubClient(config) as client:
    tools = client.list_tools(namespace="AcmeCorp", user_id="jane@acme.com")

    for tool in tools:
        print(f"{tool.tool_name}: {tool.description}")
```

**Returns:** `List[ToolSummary]`

```
ToolSummary(
    tool_name="company_data",
    service_url="https://...",
    description="UK Companies House data"
)
```

---

## Inspecting a Tool

`get_tool` returns the full function catalogue for a tool, including parameter
names, types, descriptions, and examples.

```python
with ToolHubClient(config) as client:
    tool = client.get_tool(
        tool_name="company_data",
        namespace="AcmeCorp",
        user_id="jane@acme.com",
    )

    print(f"Tool: {tool.tool_name}")
    for fn_name, fn in tool.functions.items():
        print(f"\n  {fn_name}: {fn.description}")
        for param_name, param in fn.parameters_schema.items():
            req = "required" if param.required else "optional"
            print(f"    - {param_name} ({param.type}, {req}): {param.description}")
```

**Returns:** `ToolDetails`

```
ToolDetails(
    tool_name="company_data",
    functions={
        "search_companies": ToolFunction(
            name="search_companies",
            description="Search for companies in UK Companies House",
            parameters=["query", "items_per_page", "start_index"],
            parameters_schema={
                "query": FunctionParameter(type="string", required=True, ...),
                ...
            }
        ),
        "fetch_company_profile": ToolFunction(...),
        ...
    }
)
```

---

## Invoking a Tool

`invoke_tool` calls a specific function on a tool and returns the result as a dict.

```python
with ToolHubClient(config) as client:
    result = client.invoke_tool(
        tool_name="company_data",
        function="search_companies",
        parameters={
            "query": "Acme Ltd",
            "items_per_page": 10,
            "start_index": 0,
        },
        namespace="AcmeCorp",
        user_id="jane@acme.com",
    )

print(result)
```

The `function` argument uses the Python function name with underscores. The facade
converts underscores to hyphens when routing to the tool. The `get_` prefix is also
stripped automatically. If `function` is omitted, the tool's default endpoint is called.

### Function name examples

| Tool | `function` argument | Calls endpoint |
|---|---|---|
| `company_data` | `"search_companies"` | `/search-companies` |
| `company_data` | `"fetch_company_profile"` | `/fetch-company-profile` |
| `accounting` | `"get_ratios"` | `/ratios` (strips `get_`) |
| `code_execution` | `"execute_python"` | `/execute-python` |
| `web_search` | `"search"` | `/search` |

---

## Worked Examples

### Example 1 — Search for a UK company

```python
from covecta_tools import ToolHubClient, ToolHubConfig

with ToolHubClient(config) as client:
    result = client.invoke_tool(
        tool_name="company_data",
        function="search_companies",
        parameters={
            "query": "OpenAI",
            "items_per_page": 5,
            "start_index": 0,
        },
        namespace="AcmeCorp",
        user_id="jane@acme.com",
    )

    for company in result.get("items", []):
        print(company["title"], company["company_number"])
```

### Example 2 — Fetch a company profile

```python
with ToolHubClient(config) as client:
    profile = client.invoke_tool(
        tool_name="company_data",
        function="fetch_company_profile",
        parameters={"company_number": "12345678"},
        namespace="AcmeCorp",
        user_id="jane@acme.com",
    )

    print(profile.get("company_name"))
    print(profile.get("registered_office_address"))
```

When the company number does not exist, the tool returns HTTP 200 with
`{"status": "Not found", "detail": "..."}` rather than raising an exception.
Always check the `status` field:

```python
if profile.get("status") == "Not found":
    print("Company not found")
else:
    print(profile.get("company_name"))
```

### Example 3 — Web search

```python
with ToolHubClient(config) as client:
    result = client.invoke_tool(
        tool_name="web_search",
        function="search",
        parameters={
            "query": "Python async best practices 2025",
            "num_results": 5,
        },
        namespace="AcmeCorp",
        user_id="jane@acme.com",
    )

    for item in result.get("items", []):
        print(item["title"])
        print(item["link"])
        print(item["snippet"])
        print()
```

### Example 4 — Execute Python in the sandbox

```python
with ToolHubClient(config) as client:
    result = client.invoke_tool(
        tool_name="code_execution",
        function="execute_python",
        parameters={
            "code": "import math\nprint(math.pi ** 2)",
        },
        namespace="AcmeCorp",
        user_id="jane@acme.com",
    )

    print(result.get("stdout"))   # "9.869604401089358\n"
    print(result.get("stderr"))
    print(result.get("exit_code"))
```

### Example 5 — Serving multiple tenants

A single client can serve different tenants. A fresh assertion is created
automatically for each call based on the `namespace` argument:

```python
with ToolHubClient(config) as client:
    acme_tools = client.list_tools(namespace="AcmeCorp", user_id="alice@acme.com")
    beta_tools  = client.list_tools(namespace="BetaCo",  user_id="bob@beta.com")
```

The client must be pre-authorized for every namespace it accesses
(see [Security & Access Control](security-and-access-control.md#managing-client-access)).

---

## Error Handling

All SDK errors are subclasses of `CovectaToolsException`. Import what you need:

```python
from covecta_tools.exceptions import (
    CovectaToolsException,
    CovectaToolsNotFoundError,
    CovectaToolsValidationError,
    CovectaToolsBadGatewayError,
    CovectaToolsTimeoutError,
    CovectaToolsServerError,
    CovectaToolsConnectionError,
)
```

### Exception hierarchy

| Exception | HTTP status | When raised |
|---|---|---|
| `CovectaToolsConnectionError` | — | Network unreachable, DNS failure |
| `CovectaToolsNotFoundError` | 404 | Tool or endpoint not found |
| `CovectaToolsValidationError` | 422 | Missing or invalid parameters |
| `CovectaToolsBadGatewayError` | 502 | Tool Lambda returned an error |
| `CovectaToolsTimeoutError` | 504 | Tool execution timed out |
| `CovectaToolsServerError` | 5xx | Unhandled server error |
| `CovectaToolsException` | any | Catch-all base class |

All exceptions expose:
- `exception.message` — human-readable description
- `exception.status_code` — HTTP status code (None for connection errors)
- `exception.detail` — raw response body as a dict

### Recommended error handling pattern

```python
from covecta_tools.exceptions import (
    CovectaToolsException,
    CovectaToolsBadGatewayError,
    CovectaToolsTimeoutError,
    CovectaToolsConnectionError,
)

with ToolHubClient(config) as client:
    try:
        result = client.invoke_tool(
            tool_name="company_data",
            function="fetch_company_profile",
            parameters={"company_number": "12345678"},
            namespace="AcmeCorp",
        )

        # Not-found is returned as HTTP 200 with status field
        if result.get("status") == "Not found":
            print("Record does not exist")
        else:
            process(result)

    except CovectaToolsConnectionError as e:
        # Retry later — Tool Hub is unreachable
        logger.error("Cannot reach Tool Hub: %s", e.message)

    except CovectaToolsTimeoutError as e:
        # The tool Lambda timed out
        logger.warning("Tool timed out: %s", e.message)

    except CovectaToolsBadGatewayError as e:
        # The downstream tool returned an error
        logger.error("Tool error: %s | detail: %s", e.message, e.detail)

    except CovectaToolsException as e:
        # Catch-all for unexpected errors
        logger.error("Tool Hub error %s: %s", e.status_code, e.message)
```

### Not-found results vs. exceptions

Tools return HTTP 200 with `{"status": "Not found"}` when a record simply does not
exist (e.g. an unknown company number). This is **not** an error. A
`CovectaToolsNotFoundError` (HTTP 404) means the tool or endpoint itself was not
found — it is not raised for missing records.

---

## Correlation and Idempotency

### Correlation ID

`correlation_id` (max 128 chars) is a caller-supplied trace ID. The facade echoes
it back in the `X-Correlation-ID` response header and stores it in every consumption
record, making it easy to find all logs for a given request across services.

```python
import uuid

with ToolHubClient(config) as client:
    result = client.invoke_tool(
        tool_name="web_search",
        function="search",
        parameters={"query": "Python asyncio"},
        namespace="AcmeCorp",
        user_id="jane@acme.com",
        correlation_id=str(uuid.uuid4()),
    )
```

Use your existing trace ID (e.g. from your web framework's request context) rather
than generating a new UUID, so the Tool Hub call is linked to the wider transaction.

### Idempotency key

`idempotency_key` (max 256 chars) deduplicates requests. If the facade receives
two calls with the same key and the same request body within 60 seconds, the second
call returns the cached result immediately without executing the tool again. The
response includes `X-Idempotent-Replay: true` to signal a replay.

This is safe to use when retrying on network errors — you will never double-execute
a tool call that already succeeded.

```python
from datetime import date

idem_key = f"fetch_company_profile:{company_number}:{date.today()}"

with ToolHubClient(config) as client:
    result = client.invoke_tool(
        tool_name="company_data",
        function="fetch_company_profile",
        parameters={"company_number": company_number},
        namespace="AcmeCorp",
        user_id="jane@acme.com",
        idempotency_key=idem_key,
    )
```

Key design guidance:
- Include all inputs that determine the result (tool, function, key parameters)
- Include a time component (e.g. today's date) to prevent stale replays
- Keep it human-readable so it appears usefully in logs
- Do **not** use a random UUID — a random key defeats the purpose

### Cache override

Pass `nocache=True` to bypass the response cache and force a fresh tool invocation.
Useful when you need the latest data and can tolerate the extra latency.

```python
with ToolHubClient(config) as client:
    result = client.invoke_tool(
        tool_name="company_data",
        function="fetch_company_profile",
        parameters={"company_number": "12345678"},
        namespace="AcmeCorp",
        nocache=True,
    )
```

---

## Production Checklist

- [ ] Credentials loaded from environment variables or Secrets Manager — not hardcoded
- [ ] `user_id` populated on every call for audit trail completeness
- [ ] `CovectaToolsConnectionError` and `CovectaToolsTimeoutError` handled with retry logic
- [ ] Not-found results (`status == "Not found"`) handled as a valid outcome, not an error
- [ ] `ToolHubClient` used as a context manager or `client.close()` called on shutdown
- [ ] One `ToolHubClient` instance reused across requests (connection pooling)
- [ ] `correlation_id` sourced from your own request trace ID on every `invoke_tool` call

---

## Quick Reference

```python
from covecta_tools import ToolHubClient, ToolHubConfig
from covecta_tools.exceptions import CovectaToolsException

config = ToolHubConfig(
    api_url="...",
    cognito_token_url="...",
    client_id="...",
    client_secret="...",
    signing_private_key="-----BEGIN RSA PRIVATE KEY-----\n...",
    signing_key_id="my-app-key-1",
)

with ToolHubClient(config) as client:

    # List tools in a namespace
    tools = client.list_tools(namespace="AcmeCorp", user_id="jane@acme.com")

    # Inspect a tool's functions and parameters
    tool = client.get_tool("company_data", namespace="AcmeCorp")

    # Invoke a tool function
    result = client.invoke_tool(
        tool_name="company_data",
        function="search_companies",
        parameters={"query": "Acme", "items_per_page": 10, "start_index": 0},
        namespace="AcmeCorp",
        user_id="jane@acme.com",
    )
```
