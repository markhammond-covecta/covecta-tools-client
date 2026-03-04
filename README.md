# Covecta Tools Client SDK

Python client library for integrating with the Covecta Tool Hub API.

---

## Getting started

Clone this repository and add `covecta_tools/` to your project:

```bash
git clone https://github.com/markhammond-covecta/covecta-tools-client.git
```

Copy the `covecta_tools/` directory into your project root, or add the cloned
directory to your Python path:

```python
import sys
sys.path.insert(0, "/path/to/covecta-tools-client")
from covecta_tools import ToolHubClient, ToolHubConfig
```

## Dependencies

Install the required packages:

```bash
pip install requests pydantic PyJWT cryptography
```

## Quick start

```python
from covecta_tools import ToolHubClient, ToolHubConfig

config = ToolHubConfig(
    api_url="https://<facade-api-gateway>.execute-api.eu-west-1.amazonaws.com",
    cognito_token_url="https://<pool>.auth.eu-west-1.amazoncognito.com/oauth2/token",
    client_id="your-cognito-client-id",
    client_secret="your-cognito-client-secret",
    signing_private_key=open("my-app-private.pem").read(),
    signing_key_id="my-app-key-1",
)

with ToolHubClient(config) as client:
    tools = client.list_tools(namespace="AcmeCorp", user_id="jane@acme.com")
    for tool in tools:
        print(tool.tool_name, tool.description)

    result = client.invoke_tool(
        tool_name="companies-house",
        function="search-companies",
        parameters={"query": "Acme Ltd", "items_per_page": 10, "start_index": 0},
        namespace="AcmeCorp",
        user_id="jane@acme.com",
    )
    print(result)
```

## Documentation

- [Authentication setup](docs/facade-auth-guide.md) — Cognito credentials, RSA key
  generation, namespace authorization
- [SDK integration guide](docs/sdk-integration-guide.md) — full API reference,
  worked examples, error handling

## Keeping up to date

This repository is automatically synchronized from the main Covecta Tool Hub
repository on every release. Pull the latest changes with:

```bash
git pull origin main
```

## Version

See `covecta_tools/__init__.py` for the current version number.
