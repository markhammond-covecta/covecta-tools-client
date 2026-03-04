# Covecta Tool Hub — Facade Authentication Guide

A guide for core developers integrating Covecta core with the Tool Hub facade API.

---

## Overview

Every request to the facade requires **two independent security credentials**:

| Credential | Transport | Purpose |
|---|---|---|
| Cognito OAuth2 access token | `Authorization: Bearer <token>` | Proves *application* identity |
| Tenant assertion JWT | `X-Tenant-Assertion: <jwt>` | Proves *namespace* binding |

Note: Namespaces are used in Tool Hub to segragate secrets and access to tools between tenants.
The namespace itself is simply a unique string, e.g `covecta.global.uk.metrobank.staging`. 

This two-layer model means that even if a Cognito token is compromised, an attacker cannot access a different tenant's data without also possessing the corresponding RS256 private signing key.

The namespace is **never** trusted from query parameters for external requests. It is always extracted from the cryptographically validated assertion.

---

## Authentication Flow

```
Your App                   Cognito                  Tool Hub Facade
    │                          │                           │
    │── POST /oauth2/token ───▶│                           │
    │   (client_id + secret)   │                           │
    │◀── access_token ─────────│                           │
    │                                                      │
    │── Sign assertion JWT with RS256 private key          │
    │                                                      │
    │── GET /tools ───────────────────────────────────────▶│
    │   Authorization: Bearer <access_token>               │
    │   X-Tenant-Assertion: <signed_jwt>                   │
    │                                                      │
    │             Facade validates Cognito token ──────────│
    │             Facade validates assertion signature ─────│
    │             Facade extracts namespace from assertion ─│
    │                                                      │
    │◀── tools list ───────────────────────────────────────│
```

---

## Step 1 — Prerequisites

Before writing any code, a Covecta administrator must complete the following:

### 1a. Create a Cognito App Client

The administrator creates an App Client in the Covecta User Pool with the
`client_credentials` grant and the required scopes:

- `covecta-api/tools.read`
- `covecta-api/tools.invoke`

The administrator provides you with:
- `COGNITO_CLIENT_ID` — e.g. `3abc1def2ghi3jkl4mno5pqr6s`
- `COGNITO_CLIENT_SECRET` — e.g. `abc123...`
- `COGNITO_TOKEN_URL` — e.g. `https://covecta-dev.auth.eu-west-1.amazoncognito.com/oauth2/token`

### 1b. Generate an RSA-2048 Key Pair

Run the key generation script (requires AWS credentials with DynamoDB write access):

```bash
python scripts/generate_client_keys.py \
    --client-id my-app \
    --key-id my-app-key-1 \
    --output my-app-private.pem
```

This generates a 2048-bit RSA key pair, stores the **public key** in the
`dev-covecta-client-keys` DynamoDB table, and writes the **private key PEM** to
`my-app-private.pem`.

**Keep the private key secret.** It should be stored in Secrets Manager or a secure
vault — never committed to source control.

For environments requiring extra security, encrypt the private key with a passphrase:

```bash
python scripts/generate_client_keys.py \
    --client-id my-app \
    --key-id my-app-key-1 \
    --passphrase \
    --output my-app-private.pem
```

### 1c. Authorize the Client for a Namespace

The administrator writes a record to the `dev-covecta-client-tenants` DynamoDB table
authorizing `my-app` to access the `AcmeCorp` namespace:

```python
import boto3, time

dynamodb = boto3.resource('dynamodb', region_name='eu-west-1')
table = dynamodb.Table('dev-covecta-client-tenants')

table.put_item(Item={
    'client_id': 'my-app',
    'tenant_id': 'AcmeCorp',
    'created_at': int(time.time()),
})
```

The client cannot access any namespace that does not appear in this table.

---

## Step 2 — Install Dependencies

```bash
pip install PyJWT cryptography requests
```

Or if using the Covecta SDK:

```bash
pip install covecta-tools
```

The SDK bundles everything and handles token refresh automatically.

---

## Step 3 — Obtain a Cognito Access Token

The facade sits behind API Gateway with a Cognito JWT authorizer. Every request
must include a valid `Authorization: Bearer` token obtained from the
OAuth2 client credentials endpoint.

### Using the SDK (recommended)

The `ToolHubClient` handles token acquisition and refresh automatically — you never
need to call the token endpoint yourself.

### Manual / raw HTTP

```python
import requests

response = requests.post(
    "https://covecta-dev.auth.eu-west-1.amazoncognito.com/oauth2/token",
    data={
        "grant_type": "client_credentials",
        "client_id": "3abc1def2ghi3jkl4mno5pqr6s",
        "client_secret": "abc123...",
        "scope": "covecta-api/tools.read covecta-api/tools.invoke",
    },
    headers={"Content-Type": "application/x-www-form-urlencoded"},
)
response.raise_for_status()
access_token = response.json()["access_token"]
```

Tokens are valid for **1 hour**. Request a new one before it expires; the SDK does
this automatically with a 60-second buffer.

---

## Step 4 — Create a Tenant Assertion

The tenant assertion is a short-lived RS256-signed JWT that cryptographically binds
a request to a specific namespace. The facade extracts the namespace **only** from
this validated assertion.

### Required JWT claims

| Claim | Type | Description |
|---|---|---|
| `iat` | integer | Issued at (Unix timestamp) |
| `exp` | integer | Expiry (Unix timestamp) — recommend `iat + 60` |
| `nbf` | integer | Not before (Unix timestamp) — set to `iat` |
| `jti` | string | Unique assertion ID — prevents replay attacks |
| `tenant_id` | string | The namespace to access, e.g. `"AcmeCorp"` |
| `client_id` | string | Your application identifier |
| `acting_user` | string | (Optional) End-user email for audit trail |
| `assertion_type` | string | (Optional) Set to `"tenant_context"` |

### Required JWT header fields

| Field | Value |
|---|---|
| `alg` | `RS256` |
| `typ` | `JWT` |
| `kid` | Your registered key ID, e.g. `"my-app-key-1"` |

The `kid` field is how the facade looks up your public key in DynamoDB. If it is
missing or does not match a registered key, the request will be rejected.

### Example — sign an assertion in Python

```python
import time
import secrets
import jwt
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.backends import default_backend

# Load the private key
with open("my-app-private.pem", "rb") as f:
    private_key = serialization.load_pem_private_key(
        f.read(), password=None, backend=default_backend()
    )

now = int(time.time())

payload = {
    "iat": now,
    "exp": now + 60,          # valid for 60 seconds
    "nbf": now,
    "jti": secrets.token_hex(16),   # unique per request
    "tenant_id": "AcmeCorp",
    "client_id": "my-app",
    "acting_user": "jane@acme.com",  # optional but useful for auditing
    "assertion_type": "tenant_context",
}

assertion = jwt.encode(
    payload,
    private_key,
    algorithm="RS256",
    headers={"kid": "my-app-key-1", "typ": "JWT"},
)
```

**Do not reuse assertions.** Each assertion has a unique `jti`. The facade records
every `jti` to prevent replay attacks — reusing one will result in a 401.

---

## Step 5 — Call the Facade

Combine the Cognito token and the tenant assertion in the same request:

```python
import requests

headers = {
    "Authorization": f"Bearer {access_token}",
    "X-Tenant-Assertion": assertion,
    "Content-Type": "application/json",
}

facade_url = "https://your-facade-api-gateway-url"

# List tools available to AcmeCorp
response = requests.get(f"{facade_url}/tools", headers=headers)
response.raise_for_status()
print(response.json())

# Invoke a tool
response = requests.post(
    f"{facade_url}/tools/companies-house/invoke",
    headers=headers,
    params={"method": "search-companies"},
    json={"parameters": {"company_name": "Acme Ltd"}},
)
response.raise_for_status()
print(response.json())
```

---

## Step 6 — Using the SDK (preferred)

The `ToolHubClient` wraps the entire auth flow. You supply the config once; it
generates a fresh assertion for every request and refreshes the Cognito token
automatically.

```python
from covecta_tools import ToolHubClient, ToolHubConfig

config = ToolHubConfig(
    api_url="https://your-facade-api-gateway-url",
    cognito_token_url="https://covecta-dev.auth.eu-west-1.amazoncognito.com/oauth2/token",
    client_id="3abc1def2ghi3jkl4mno5pqr6s",
    client_secret="abc123...",
    signing_private_key=open("my-app-private.pem").read(),
    signing_key_id="my-app-key-1",
)

with ToolHubClient(config) as client:
    # List tools for AcmeCorp
    tools = client.list_tools(namespace="AcmeCorp", user_id="jane@acme.com")
    for tool in tools:
        print(tool.name)

    # Invoke a tool
    result = client.invoke_tool(
        tool_name="companies-house",
        function="search-companies",
        parameters={"company_name": "Acme Ltd"},
        namespace="AcmeCorp",
        user_id="jane@acme.com",
    )
    print(result)
```

### Serving multiple tenants from one client

The same `ToolHubClient` instance can serve different tenants. The assertion is
created per-call based on the `namespace` argument:

```python
with ToolHubClient(config) as client:
    tools_a = client.list_tools(namespace="AcmeCorp", user_id="alice@acme.com")
    tools_b = client.list_tools(namespace="BetaCo", user_id="bob@beta.com")
```

Each call generates a separate signed assertion. The client must be pre-authorized
for both namespaces (Step 1c).

---

## Key Rotation

To rotate a signing key:

1. Generate a new key pair with a new `--key-id`:
   ```bash
   python scripts/generate_client_keys.py \
       --client-id my-app \
       --key-id my-app-key-2 \
       --output my-app-private-v2.pem
   ```

2. Update your application to use `my-app-key-2`.

3. Once all in-flight assertions signed with `my-app-key-1` have expired (after 60
   seconds), delete the old key from DynamoDB:
   ```python
   table.delete_item(Key={'client_id': 'my-app', 'key_id': 'my-app-key-1'})
   ```

The old key ID should **not** be deleted before the new key is deployed, or there
will be a gap where all requests fail.

---

## Troubleshooting

### `401 — Missing X-Tenant-Assertion header`

The `X-Tenant-Assertion` header was not sent. Ensure the header name is spelled
exactly (case-insensitive in HTTP, but spelled `X-Tenant-Assertion` in code).

### `401 — Unknown key ID: my-app-key-1`

The `kid` in the JWT header does not match any record in the `ClientKeys` table.
Confirm that `generate_client_keys.py` ran successfully and targeted the correct
table and region. Check with:

```bash
aws dynamodb get-item \
    --table-name dev-covecta-client-keys \
    --key '{"client_id": {"S": "my-app"}, "key_id": {"S": "my-app-key-1"}}' \
    --region eu-west-1
```

### `401 — Assertion has already been used (replay attack detected)`

The same `jti` was used twice. Ensure `jti` is generated fresh per request using
`secrets.token_hex(16)` or equivalent. Never cache and reuse an assertion.

### `401 — Client my-app is not authorized for tenant AcmeCorp`

The `ClientTenants` table has no record for this `(client_id, tenant_id)` pair.
Ask an administrator to add the authorization (Step 1c).

### `401 — Tenant assertion has expired`

The `exp` claim in the assertion is in the past. Assertions are short-lived by
design (60 seconds). Create a fresh assertion immediately before each request;
do not pre-build and cache them.

### `401 — Invalid tenant assertion: Signature verification failed`

The assertion was signed with a private key that does not match the registered
public key. Verify you are loading the correct `.pem` file and that the public key
in DynamoDB was registered from the same key pair.

### `403 — Forbidden` from API Gateway

The Cognito access token is missing, expired, or does not include the required
scopes (`covecta-api/tools.read`, `covecta-api/tools.invoke`). Re-check the
`scope` parameter in the token request and verify the App Client has those
resource server scopes enabled in Cognito.

### Clock skew errors

The facade allows 30 seconds of clock skew. If your server clock is further out of
sync, assertions may be rejected as expired or not-yet-valid. Sync the system clock
with NTP.

---

## Security Checklist

- [ ] Private key stored in Secrets Manager or equivalent vault — **never** in source code or `.env` files
- [ ] One key pair per application (not shared between services)
- [ ] `jti` generated fresh (using `secrets.token_hex(16)` or similar) for every request
- [ ] Assertion validity set to 60 seconds — do not increase beyond what is needed
- [ ] Cognito client secret treated as a secret — rotated on compromise
- [ ] Key rotation procedure documented and tested
- [ ] `acting_user` populated with the real end-user identity for audit trail

---

## Quick Reference

```
Endpoint:   https://<facade-api-gateway-id>.execute-api.eu-west-1.amazonaws.com/<stage>
Region:     eu-west-1

Required headers (every request):
  Authorization:      Bearer <cognito_access_token>
  X-Tenant-Assertion: <rs256_signed_jwt>

Assertion JWT claims:
  alg: RS256, kid: <your-key-id>
  iat, exp (now+60), nbf (now), jti (unique), tenant_id, client_id

DynamoDB tables:
  dev-covecta-client-keys    — public keys (client_id PK, key_id SK)
  dev-covecta-client-tenants — authorizations (client_id PK, tenant_id SK)
  dev-covecta-jti-replay     — replay prevention (jti PK, TTL = assertion exp)
```
