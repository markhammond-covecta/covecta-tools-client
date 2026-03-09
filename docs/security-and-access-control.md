# Covecta Tool Hub — Security & Access Control Guide

A comprehensive guide to authentication, authorization, namespace access management,
role-based permissions, and common security scenarios in Tool Hub.

---

## Table of Contents

1. [How Security Works — The Big Picture](#how-security-works--the-big-picture)
2. [The Five Security Layers](#the-five-security-layers)
3. [Namespaces — What They Are and Why They Matter](#namespaces--what-they-are-and-why-they-matter)
4. [Roles and Permissions](#roles-and-permissions)
5. [Managing Client Access](#managing-client-access)
6. [CLI Profiles — Multi-Identity Support](#cli-profiles--multi-identity-support)
7. [SDK Integration](#sdk-integration)
8. [Webapp (Manager UI)](#webapp-manager-ui)
9. [Cookbook — Security Scenarios](#cookbook--security-scenarios)
10. [Troubleshooting](#troubleshooting)
11. [Security Checklist](#security-checklist)

---

## How Security Works — The Big Picture

Tool Hub is a multi-tenant platform. Multiple organisations, teams, and applications
share the same infrastructure, but each one can only see and use the tools, secrets,
and data assigned to their **namespace**. Security ensures that these boundaries hold.

Every API request must answer three questions:

1. **Who are you?** — A Cognito OAuth2 access token proves the application's identity.
2. **Which namespace?** — An RS256-signed tenant assertion cryptographically binds the
   request to a specific namespace. The namespace is *never* trusted from query
   parameters.
3. **What can you do?** — A role-based permission system controls which operations
   the client is allowed to perform within that namespace.

```
┌─────────────────────────────────────────────────────────────────────┐
│                        API Gateway                                  │
│  ┌───────────────┐                                                  │
│  │ Cognito JWT   │  "Who are you?" — validates Bearer token         │
│  │ Authorizer    │  Rejects requests with missing/expired tokens    │
│  └───────┬───────┘                                                  │
│          ▼                                                          │
│  ┌───────────────┐                                                  │
│  │ Facade Lambda │                                                  │
│  │               │                                                  │
│  │  ┌─────────────────────┐                                         │
│  │  │ Tenant Assertion    │  "Which namespace?" — validates RS256   │
│  │  │ Validator           │  signature, extracts tenant_id          │
│  │  └────────┬────────────┘                                         │
│  │           ▼                                                      │
│  │  ┌─────────────────────┐                                         │
│  │  │ Permission Resolver │  "What can you do?" — looks up role,   │
│  │  │                     │  computes permission scopes, enforces   │
│  │  │                     │  require('tools:read') etc.             │
│  │  └────────┬────────────┘                                         │
│  │           ▼                                                      │
│  │  Route to tool / registry / vault                                │
│  └───────────────┘                                                  │
└─────────────────────────────────────────────────────────────────────┘
```

**Key principle:** The facade is the *only* externally accessible service. Registry,
vault, and individual tool Lambdas are behind IAM (SigV4) and are not directly
reachable from the internet. A consumer client that can only call the facade cannot
directly read secrets from the vault or modify tool registrations — those operations
require specific permission scopes that the facade enforces before proxying.

---

## The Five Security Layers

Tool Hub uses defence in depth — five independent layers, each stopping a different
class of attack.

### Layer 1: Cognito OAuth2 (Application Identity)

API Gateway validates the `Authorization: Bearer <token>` header before the request
even reaches the facade Lambda. If the token is missing, expired, or issued by a
different user pool, the request is rejected with `401`.

**What it proves:** The calling application is a registered Cognito client.

**How to get a token:**

```python
import requests

resp = requests.post(TOKEN_URL, data={
    "grant_type": "client_credentials",
    "client_id": COGNITO_CLIENT_ID,
    "client_secret": COGNITO_CLIENT_SECRET,
    "scope": "covecta-api/tools.read covecta-api/tools.invoke",
}, headers={"Content-Type": "application/x-www-form-urlencoded"})

access_token = resp.json()["access_token"]  # Valid for 1 hour
```

### Layer 2: Tenant Assertion (Namespace Binding)

The facade validates the `X-Tenant-Assertion` header — an RS256-signed JWT containing
the target namespace. The facade looks up the public key from DynamoDB using the `kid`
header, verifies the signature, checks expiry and replay (`jti`), and extracts the
`tenant_id` claim as the namespace.

**What it proves:** The caller possesses the private signing key for a registered
client, and that client is authorized for the requested namespace.

**Why not just use a query parameter?** Because anyone with a stolen Cognito token
could pass `?namespace=VictimCorp` and access another tenant's tools. The assertion
makes namespace binding *cryptographic* — you cannot forge it without the private key.

```python
import time, secrets, jwt
from cryptography.hazmat.primitives import serialization

private_key = serialization.load_pem_private_key(
    open("private.pem", "rb").read(), password=None
)

now = int(time.time())
assertion = jwt.encode(
    {
        "iat": now, "exp": now + 60, "nbf": now,
        "jti": secrets.token_hex(16),  # unique per request — prevents replay
        "tenant_id": "AcmeCorp",
        "assertion_type": "tenant_context",
    },
    private_key, algorithm="RS256",
    headers={"kid": "acmecorp-key-1", "typ": "JWT"},
)
```

### Layer 3: Role-Based Permissions (What You Can Do)

After validating the assertion, the facade looks up the client's **role** in the
`ClientTenantsTable` and resolves it to a set of permission scopes. Each facade
endpoint calls `tenant.require('scope')` before proceeding.

See [Roles and Permissions](#roles-and-permissions) for the full model.

### Layer 4: IAM / SigV4 (Service-to-Service)

Internal services (registry, vault, tool Lambdas) are only accessible via Lambda
Function URLs protected by IAM authentication. The facade signs requests with SigV4
before forwarding them. External clients cannot bypass the facade to reach these
services directly.

### Layer 5: Tool Context Tokens (Per-Invocation)

When the facade invokes a tool, it mints a short-lived HMAC-SHA256 "tool context
token" bound to the namespace. The tool validates this token to confirm the request
came from the facade and is authorized for the namespace. This prevents a compromised
tool Lambda from being used to access other namespaces.

---

## Namespaces — What They Are and Why They Matter

A namespace is a tenant boundary. Everything in Tool Hub is scoped to a namespace:

| Resource | How namespace applies |
|----------|---------------------|
| **Tools** | Each tool is assigned to one or more namespaces via the registry |
| **Secrets** | Stored at `{env}/covecta/{namespace}/{key}` in Secrets Manager |
| **Tool config** | Per-namespace base URLs and API keys in `config.json` |
| **Client access** | Each client is authorized per namespace, with a role |
| **Consumption** | Usage tracking and analytics are per-namespace |

Namespaces are just strings (e.g. `AcmeCorp`, `covecta.global.uk.metrobank.staging`).
They are explicitly created via the registry API or CLI, and each namespace has an
owner client created at provisioning time.

### Creating a namespace

```bash
# Via CLI
covecta registry create-namespace --namespace AcmeCorp --description "Acme Corporation"

# The response includes owner credentials (one-time display):
#   client_id:              AcmeCorp
#   cognito_client_id:      abc123...
#   cognito_client_secret:  xyz789...
#   signing_key_id:         AcmeCorp-key-1
#   signing_private_key:    -----BEGIN RSA PRIVATE KEY----- ...
```

When a namespace is created, the system automatically:
1. Creates an RSA-2048 key pair and stores the public key in DynamoDB
2. Creates a Cognito app client with the required scopes
3. Creates a client authorization record with `role=owner`
4. Returns the private key and Cognito credentials (shown once, never stored)

### What to do with your namespace credentials

The creation response displays five credentials. **This is the only time you will see
the private key and Cognito client secret.** If you lose them, you must rotate keys
or delete and recreate the namespace.

| Credential | What it is | Where to store it | Used for |
|-----------|-----------|------------------|---------|
| `client_id` | Your client identifier (e.g. `AcmeCorp`) | Config files, environment variables | Identifying your client in tenant assertions |
| `cognito_client_id` | OAuth2 client ID | Config files, environment variables | Requesting Cognito access tokens |
| `cognito_client_secret` | OAuth2 client secret | Secrets Manager, HashiCorp Vault, or equivalent | Requesting Cognito access tokens |
| `signing_key_id` | Public key identifier (e.g. `AcmeCorp-key-1`) | Config files, environment variables | The `kid` header in tenant assertion JWTs |
| `signing_private_key` | RSA-2048 private key (PEM) | Secrets Manager, encrypted file (chmod 0600), or secure vault — **never** in source control | Signing tenant assertion JWTs |

**Immediately after creation, do one of the following:**

**Option A — Save as a CLI profile (recommended for developers):**
```bash
# Re-run with --configure to auto-save credentials
covecta client grant --namespace AcmeCorp --name "My Profile" --role owner --configure
```
This writes the PEM to `~/.toolhub/keys/<client_id>.pem` (chmod 0600) and adds a
profile to `~/.toolhub/config.json`. You can then use the CLI and SDK without
manually handling credentials.

**Option B — Store manually (recommended for production services):**
1. Save the private key PEM to your secrets vault (e.g. AWS Secrets Manager)
2. Store `cognito_client_id`, `cognito_client_secret`, `signing_key_id`, and
   `client_id` as environment variables or in your application's secure config
3. Configure the SDK:
   ```python
   config = ToolHubConfig(
       api_url="<facade_url>",
       cognito_token_url="<cognito_token_url>",
       client_id="<cognito_client_id>",
       client_secret="<cognito_client_secret>",
       signing_private_key="<pem_contents>",
       signing_key_id="<signing_key_id>",
   )
   ```

**Option C — From the webapp:** Click **Download PEM** in the credentials modal to
save the private key file, then copy the other credentials using the copy buttons.
Store them as described in Option B.

---

## Roles and Permissions

### The Three Roles

| Role | Intended for | Summary |
|------|-------------|---------|
| **owner** | The namespace creator / administrator | Full control including deletion and client management |
| **admin** | Trusted team members or services | Everything except destructive namespace operations |
| **consumer** | External applications, bots, integrations | Can discover and invoke tools, nothing else |

### Permission Scopes

Each role maps to a set of permission scopes:

| Permission | Owner | Admin | Consumer | What it controls |
|-----------|:-----:|:-----:|:--------:|-----------------|
| `tools:read` | yes | yes | yes | `GET /tools`, `GET /tools/{name}` |
| `tools:invoke` | yes | yes | yes | `POST /tools/{name}/invoke` |
| `templates:read` | yes | yes | yes | List and inspect prompt templates |
| `templates:invoke` | yes | yes | yes | Execute prompt templates |
| `consumption:read` | yes | yes | | View cache metrics and usage analytics |
| `registry:read` | yes | yes | | List registered tools and configurations |
| `registry:write` | yes | yes | | Register, update, and assign tools |
| `secrets:read` | yes | yes | | Read secrets from the vault |
| `secrets:write` | yes | yes | | Write secrets to the vault |
| `clients:manage` | yes | | | Grant, revoke, and update client access |
| `namespace:delete` | yes | | | Delete the namespace and all its data |

### How Permissions Are Resolved

```
Client makes request with assertion
        │
        ▼
Facade extracts client_id + tenant_id from assertion
        │
        ▼
Look up authorization record in ClientTenantsTable
        │
        ├── Record has explicit `permissions` set?
        │       │
        │       ├── Yes (non-empty) → Use those permissions
        │       │                     (intersected with ALL_PERMISSIONS for safety)
        │       │
        │       └── No → Use role's default permission set
        │
        ▼
Facade calls tenant.require('tools:read') etc.
        │
        ├── Client has the scope → Request proceeds
        │
        └── Client lacks the scope → 403 Insufficient permissions
```

### Explicit Permission Overrides

By default, a client gets all the permissions for its role. But you can grant a client
a *subset* of its role's permissions for tighter control:

```bash
# Grant a consumer that can only read tools (not invoke them)
covecta client grant --namespace AcmeCorp \
    --name "Catalogue Bot" \
    --role consumer \
    --permissions tools:read,templates:read
```

This client will be able to list and inspect tools, but any attempt to invoke one
will return `403 Insufficient permissions. Required: tools:invoke`.

Explicit permissions can include scopes from *any* role — they are intersected with
the full `ALL_PERMISSIONS` set, not with the role's defaults. This means you could
theoretically grant a consumer `secrets:read` (though this is unusual and should be
done deliberately).

---

## Managing Client Access

### Granting access

Create a new client with access to a namespace:

```bash
covecta client grant \
    --namespace AcmeCorp \
    --name "Analytics Dashboard" \
    --role consumer
```

The response includes one-time credentials:

```
Client 'AcmeCorp-c2a8f3' granted access to namespace 'AcmeCorp' (role: consumer)

--- Credentials (ONE-TIME DISPLAY) ---
  client_id            : AcmeCorp-c2a8f3
  cognito_client_id    : 7abc2def3ghi...
  cognito_client_secret: secret123...
  signing_key_id       : AcmeCorp-c2a8f3-key-1
  signing_private_key  :
-----BEGIN RSA PRIVATE KEY-----
MIIEowIBAAK...
-----END RSA PRIVATE KEY-----

  WARNING: The private key cannot be retrieved again.
  TIP: Use --configure to auto-save credentials as a CLI profile.

  Permissions: tools:read, tools:invoke, templates:read, templates:invoke
```

**Important:** The private key is shown exactly once. If you lose it, the only
recovery is to rotate keys or revoke and re-grant.

#### What to do with the granted credentials

The grant response contains the same five credentials as namespace creation (see
[What to do with your namespace credentials](#what-to-do-with-your-namespace-credentials)
above). The steps are identical:

1. **For the person who will use these credentials:** Save the private key PEM to a
   secure location (Secrets Manager, vault, or local file with chmod 0600). Store the
   Cognito client ID, client secret, signing key ID, and client ID in your
   application's secure config or environment variables.

2. **If sharing with another team:** Copy all five values from the output and send
   them through a secure channel (not email or Slack). The receiving team needs all
   five to configure their SDK client or CLI profile.

3. **From the webapp:** The credentials modal has **Copy** buttons for each field and
   a **Download PEM** button for the private key. Use these to capture everything
   before closing the modal — it cannot be reopened.

#### Auto-configure a CLI profile

Add `--configure` to automatically save the credentials to your CLI config:

```bash
covecta client grant \
    --namespace AcmeCorp \
    --name "Alice" \
    --role admin \
    --configure
```

This saves the PEM key to `~/.toolhub/keys/AcmeCorp-xxxxxx.pem` and creates a named
profile in `~/.toolhub/config.json`. From that point on, `--namespace AcmeCorp`
automatically uses Alice's credentials.

### Listing clients

```bash
covecta client list --namespace AcmeCorp
```

```
  Client ID                      Name                      Role       Created
  ────────────────────────────── ───────────────────────── ────────── ────────────────────
  AcmeCorp                       AcmeCorp (owner)          owner      2026-03-01 10:00
  AcmeCorp-c2a8f3                Analytics Dashboard       consumer   2026-03-09 14:30
  AcmeCorp-b7e921                Alice                     admin      2026-03-09 15:00
```

### Updating a client

Change a client's role, name, or permissions:

```bash
# Promote to admin
covecta client update --namespace AcmeCorp --client-id AcmeCorp-c2a8f3 --role admin

# Restrict permissions
covecta client update --namespace AcmeCorp --client-id AcmeCorp-c2a8f3 \
    --permissions tools:read,tools:invoke

# Rename
covecta client update --namespace AcmeCorp --client-id AcmeCorp-c2a8f3 \
    --name "Analytics Dashboard v2"
```

**Constraint:** You cannot change the owner's role. The owner is the namespace
creator and always retains full control.

### Revoking access

```bash
covecta client revoke --namespace AcmeCorp --client-id AcmeCorp-c2a8f3
```

This:
- Deletes the signing keys from `ClientKeysTable`
- Deletes the Cognito app client
- Removes the authorization record from `ClientTenantsTable`
- Deletes the signing key secret from Secrets Manager

The client is immediately and permanently unable to access the namespace. In-flight
assertions signed with the old key will fail on the next request (assertions are
validated per-request, and the key lookup will return "Unknown key ID").

**Constraint:** You cannot revoke the owner. To destroy a namespace entirely, use
`covecta registry delete-namespace --namespace AcmeCorp`.

### Rotating keys

If a key is compromised or as part of routine rotation:

```bash
covecta client rotate-keys --namespace AcmeCorp --client-id AcmeCorp-c2a8f3
```

This generates a new RSA-2048 key pair, replaces the old public key in DynamoDB,
and returns the new private key. The old key is immediately invalidated — any
assertions signed with it will fail. Coordinate key rotation with your deployment
process to avoid downtime.

---

## CLI Profiles — Multi-Identity Support

When you work with multiple namespaces or identities, profiles let you switch
credentials automatically based on the namespace.

### How profiles work

Your `~/.toolhub/config.json` has a `profiles` section:

```json
{
  "api_url": "https://ccp11qppvc.execute-api.eu-west-1.amazonaws.com",
  "token_url": "https://toolhub-dev.auth.eu-west-1.amazoncognito.com/oauth2/token",
  "client_id": "default-cognito-client-id",
  "client_secret": "default-cognito-secret",
  "profiles": {
    "alice": {
      "namespaces": ["AcmeCorp"],
      "client_id": "7abc2def3ghi...",
      "client_secret": "secret123...",
      "assertion_client_id": "AcmeCorp-b7e921",
      "assertion_key_id": "AcmeCorp-b7e921-key-1",
      "assertion_key_file": "~/.toolhub/keys/AcmeCorp-b7e921.pem"
    },
    "bob": {
      "namespaces": ["BetaCo", "GammaTech"],
      "client_id": "8xyz9abc...",
      "client_secret": "secret456...",
      "assertion_client_id": "BetaCo-d4f567",
      "assertion_key_id": "BetaCo-d4f567-key-1",
      "assertion_key_file": "~/.toolhub/keys/BetaCo-d4f567.pem"
    }
  }
}
```

### Profile resolution

When you run a command with `--namespace`:

1. If `TOOLHUB_PROFILE` env var is set, use that profile by name
2. Otherwise, search profiles for one whose `namespaces` list contains the target
3. Fall back to the default (top-level) credentials

```bash
# Automatically uses "alice" profile (because AcmeCorp is in alice's namespaces)
covecta facade list --namespace AcmeCorp

# Automatically uses "bob" profile
covecta facade list --namespace BetaCo

# Force a specific profile
TOOLHUB_PROFILE=bob covecta facade list --namespace AcmeCorp
```

### Listing profiles

```bash
covecta auth profiles
```

```
  Profile                   Namespaces                     Key ID
  ───────────────────────── ────────────────────────────── ──────────────────────────────
  alice                     AcmeCorp                       AcmeCorp-b7e921-key-1
  bob                       BetaCo, GammaTech              BetaCo-d4f567-key-1
```

### Per-profile token caching

Each profile caches its Cognito token separately (`~/.toolhub/tokens-alice.json`,
`~/.toolhub/tokens-bob.json`), so switching between namespaces doesn't trigger
unnecessary re-authentication.

---

## SDK Integration

The Python SDK handles authentication automatically. Configure it with the client
credentials from `covecta client grant`:

```python
from covecta_tools import ToolHubClient, ToolHubConfig

config = ToolHubConfig(
    api_url="https://ccp11qppvc.execute-api.eu-west-1.amazonaws.com",
    cognito_token_url="https://toolhub-dev.auth.eu-west-1.amazoncognito.com/oauth2/token",
    client_id="7abc2def3ghi...",
    client_secret="secret123...",
    signing_private_key=open("private.pem").read(),
    signing_key_id="AcmeCorp-c2a8f3-key-1",
)

with ToolHubClient(config) as client:
    # List tools (requires tools:read)
    tools = client.list_tools(namespace="AcmeCorp", user_id="bot@acme.com")

    # Invoke a tool (requires tools:invoke)
    result = client.invoke_tool(
        tool_name="companies_house",
        function="search_companies",
        parameters={"query": "Acme Ltd"},
        namespace="AcmeCorp",
        user_id="bot@acme.com",
    )
```

### Managing clients from the SDK

```python
# List clients (owner/admin only — requires clients:manage for grant/revoke)
clients = client.list_clients(namespace="AcmeCorp")

# Grant access
new_client = client.grant_access(
    namespace="AcmeCorp",
    name="New Bot",
    role="consumer",
)
print(new_client["credentials"]["signing_private_key_pem"])

# Update
client.update_client(
    namespace="AcmeCorp",
    client_id="AcmeCorp-abc123",
    role="admin",
)

# Revoke
client.revoke_access(namespace="AcmeCorp", client_id="AcmeCorp-abc123")
```

---

## Webapp (Manager UI)

The Manager tab in the webapp (`https://<cloudfront-url>` → Manage) provides a
graphical interface for client management. When you select a namespace, a
**Clients & Access** panel shows all clients with their roles.

From the UI you can:
- View all clients for a namespace (role shown as a colour-coded badge)
- Grant a new client with a name and role
- Revoke a non-owner client
- See credentials for newly granted clients (one-time display in the modal)

**Handling credentials in the webapp:**

When you create a namespace or grant a client, a credentials modal appears with all
five credential values. This modal is your **only chance** to capture them:

1. Use the **Copy** button next to each field to copy it to your clipboard
2. Use the **Download PEM** button to save the private key as a `.pem` file
3. Do not close the modal until you have saved everything you need

If you close the modal without saving the private key, you will need to rotate keys
(`POST .../rotate-keys`) or revoke and re-grant the client to get new credentials.

The UI communicates with the registry Lambda via the webapp server, which signs
requests with SigV4.

---

## Cookbook — Security Scenarios

### Scenario 1: Onboarding a new SaaS customer

**Goal:** Create a namespace for "MegaBank" and give their integration team
read-only tool access.

```bash
# 1. Create the namespace (you are the platform owner)
covecta registry create-namespace \
    --namespace MegaBank \
    --description "MegaBank production"

# Save the owner credentials securely:
#   - Store the private key PEM in Secrets Manager or a vault
#   - Record cognito_client_id, cognito_client_secret, signing_key_id
#   - You'll need these for admin tasks on this namespace

# 2. Grant the integration team a consumer client
covecta client grant \
    --namespace MegaBank \
    --name "MegaBank Integration" \
    --role consumer \
    --configure

# 3. Assign tools to the namespace
covecta registry assign-tool --tool-name companies_house --namespace MegaBank
covecta registry assign-tool --tool-name epc --namespace MegaBank

# 4. Share the consumer credentials with the MegaBank team:
#    - Send via a secure channel (not email/Slack)
#    - They need: cognito_client_id, cognito_client_secret,
#      signing_key_id, client_id, and the PEM file
#    - They configure their SDK with these five values
```

**What MegaBank's integration team can do:**
- `GET /tools` — see companies_house and epc
- `GET /tools/companies_house` — inspect the tool schema
- `POST /tools/companies_house/invoke?method=search_companies` — search companies

**What they cannot do:**
- Register or deregister tools (no `registry:write`)
- Read or write secrets (no `secrets:read` / `secrets:write`)
- Grant access to other clients (no `clients:manage`)
- View consumption analytics (no `consumption:read`)
- Delete the namespace (no `namespace:delete`)

---

### Scenario 2: Principle of least privilege for a bot

**Goal:** Create a client that can only invoke one specific tool function, nothing else.

```bash
covecta client grant \
    --namespace AcmeCorp \
    --name "EPC Lookup Bot" \
    --role consumer \
    --permissions tools:invoke
```

This bot:
- Can invoke tools (`tools:invoke`) but cannot list them (`tools:read` not granted)
- Must know the tool name and function in advance (no discovery)
- Cannot access templates, secrets, registry, or anything else

If even this is too broad, you would enforce function-level restrictions in your
application layer (Tool Hub's permission model is scoped at the operation type level,
not the individual tool level).

---

### Scenario 3: Promoting a team member to admin

**Goal:** Alice was a consumer, now she needs to manage tools and secrets.

```bash
covecta client update \
    --namespace AcmeCorp \
    --client-id AcmeCorp-b7e921 \
    --role admin
```

Alice immediately gains: `consumption:read`, `registry:read`, `registry:write`,
`secrets:read`, `secrets:write` — in addition to the tool access she already had.

She still cannot manage other clients (`clients:manage`) or delete the namespace
(`namespace:delete`). Only the owner can do those.

---

### Scenario 4: Emergency key rotation after a leak

**Goal:** A private key was accidentally committed to a public repository.

```bash
# 1. Immediately rotate the compromised key
covecta client rotate-keys \
    --namespace AcmeCorp \
    --client-id AcmeCorp-c2a8f3 \
    --output-key /secure/path/new-key.pem

# 2. The old key is now invalid. Any assertion signed with it will fail
#    with "Unknown key ID" or "Signature verification failed".

# 3. Update the application to use the new key file

# 4. If the Cognito client secret was also exposed, revoke and re-grant:
covecta client revoke --namespace AcmeCorp --client-id AcmeCorp-c2a8f3
covecta client grant \
    --namespace AcmeCorp \
    --name "Analytics Dashboard" \
    --role consumer \
    --configure
```

**Timeline of exposure:**
- Before rotation: attacker can forge assertions and make API calls
- After rotation: attacker's assertions fail immediately (keys are validated
  per-request, no caching of old keys)
- Cognito tokens issued before revocation remain valid until they expire (up to
  1 hour), but the attacker also needs a valid assertion — which they can no longer
  forge

---

### Scenario 5: Auditing who accessed what

**Goal:** Trace which client performed a specific tool invocation.

Every facade request extracts three audit fields from the assertion:
- `client_id` — which application
- `acting_user` — which end-user (optional, set by the caller)
- `jti` — unique assertion ID

These are logged by the facade and stored in consumption records (if consumption
tracking is enabled). To trace a request:

```bash
# Check consumption records for a namespace
covecta facade consumption --namespace AcmeCorp --format json
```

Each record includes the `client_id`, timestamp, tool name, method, and latency.
The `acting_user` field allows multi-user applications to attribute calls to
individual users even though they share a single client identity.

---

### Scenario 6: Internal service calling the facade

**Goal:** The MCP server or another Lambda needs to call the facade without
Cognito/assertion overhead.

Internal services (MCP server, QoS worker) authenticate differently:
- They set a specific `User-Agent` header (`mcp-server/1.0` or `lambda-invoke/1.0`)
- They may use an HMAC-based internal service token
- The facade detects internal calls and grants `ALL_PERMISSIONS` automatically

This is safe because:
- These Lambdas are in the same AWS account and VPC
- Their calls are SigV4-signed (IAM authentication)
- The MCP server injects the namespace from its own configuration

External clients cannot impersonate internal services because API Gateway rejects
requests without valid Cognito tokens before they reach the facade.

---

### Scenario 7: Multi-tenant application serving several customers

**Goal:** Your SaaS app integrates with Tool Hub on behalf of multiple customers,
each with their own namespace.

```python
from covecta_tools import ToolHubClient, ToolHubConfig

# One SDK client can serve multiple namespaces
# (the client must be authorized for each one)
config = ToolHubConfig(
    api_url=FACADE_URL,
    cognito_token_url=TOKEN_URL,
    client_id=COGNITO_CLIENT_ID,
    client_secret=COGNITO_CLIENT_SECRET,
    signing_private_key=open("multi-tenant-app.pem").read(),
    signing_key_id="multi-tenant-app-key-1",
)

with ToolHubClient(config) as client:
    # Each call generates a separate assertion for the target namespace
    acme_tools = client.list_tools(namespace="AcmeCorp", user_id="alice@acme.com")
    beta_tools = client.list_tools(namespace="BetaCo", user_id="bob@beta.com")
```

For this to work, the multi-tenant app's `client_id` must be authorized in both
the `AcmeCorp` and `BetaCo` namespaces (via `covecta client grant` or direct
DynamoDB records).

---

### Scenario 8: Restricting a client to read-only secret access

**Goal:** A monitoring tool needs to verify secrets exist but should not be able
to change them.

```bash
covecta client grant \
    --namespace AcmeCorp \
    --name "Secret Monitor" \
    --role admin \
    --permissions secrets:read,tools:read
```

This client can:
- Read secrets (`secrets:read`)
- List tools (`tools:read`)

It cannot write secrets, invoke tools, modify the registry, or do anything else —
even though its base role is `admin`. The explicit `--permissions` flag overrides
the role defaults.

---

### Scenario 9: Decommissioning a namespace

**Goal:** "OldProject" is no longer needed. Remove it completely.

```bash
# 1. List all clients to understand who will be affected
covecta client list --namespace OldProject

# 2. Revoke non-owner clients first (optional but clean)
covecta client revoke --namespace OldProject --client-id OldProject-abc123
covecta client revoke --namespace OldProject --client-id OldProject-def456

# 3. Delete the namespace (cascade-deletes all remaining artifacts)
covecta registry delete-namespace --namespace OldProject
```

Cascade deletion removes:
- All tool assignments (namespace-tool mappings)
- All client authorization records
- All signing keys
- All Cognito app clients
- All secrets under the namespace prefix
- The namespace record itself

---

### Scenario 10: Debugging "403 Insufficient permissions"

**Goal:** A client is getting `403 Insufficient permissions. Required: tools:invoke`
and you need to figure out why.

```bash
# 1. Check the client's current role and permissions
covecta client list --namespace AcmeCorp --format json | python -m json.tool
```

Look for:
- `role` — is it `consumer` (has `tools:invoke` by default) or something unexpected?
- `permissions` — if non-empty, this *overrides* the role defaults. Does it include
  `tools:invoke`?

```bash
# 2. If the role is correct but explicit permissions are too narrow, fix them:
covecta client update --namespace AcmeCorp --client-id AcmeCorp-c2a8f3 \
    --permissions tools:read,tools:invoke,templates:read,templates:invoke

# Or remove the explicit override entirely to use role defaults:
covecta client update --namespace AcmeCorp --client-id AcmeCorp-c2a8f3 \
    --permissions ""
```

---

## Troubleshooting

### Error: `401 — Missing X-Tenant-Assertion header`

The assertion header was not sent. Check that your HTTP client includes the
`X-Tenant-Assertion` header (case-insensitive in HTTP).

### Error: `401 — Unknown key ID: xyz`

The `kid` in your JWT header does not match any key in the `ClientKeysTable`. Verify:
- The key was registered (`covecta client list --namespace NS` shows a `signing_key_id`)
- You're using the correct key ID string
- The key hasn't been rotated (check if `rotate-keys` was called recently)

### Error: `401 — Assertion has already been used (replay attack detected)`

Each assertion needs a unique `jti` claim. If you're reusing assertions or caching
them, generate a fresh one per request using `secrets.token_hex(16)`.

### Error: `401 — Client X is not authorized for tenant Y`

The `ClientTenantsTable` has no record for this `(client_id, tenant_id)` pair. The
client needs to be granted access via `covecta client grant` or the registry API.

### Error: `401 — Tenant assertion has expired`

Assertions have a 60-second validity window. Create them immediately before each
request. Do not pre-build or cache them. The validator allows 30 seconds of clock
skew.

### Error: `403 — Insufficient permissions. Required: X`

The client's role does not include the required scope. See
[Scenario 10](#scenario-10-debugging-403-insufficient-permissions) above.

### Error: `409 — Cannot change role of the namespace owner`

The owner client's role is immutable. This protects against accidentally locking
yourself out of a namespace.

### Error: `409 — Cannot revoke the namespace owner`

The owner cannot be revoked. To destroy a namespace entirely, use
`delete-namespace` which cascade-deletes everything.

### Error: `422 — role must be one of {'owner', 'admin', 'consumer'}`

You passed an invalid role name. The only valid roles are `owner`, `admin`, and
`consumer`.

---

## Security Checklist

### For namespace owners

- [ ] Owner credentials stored in a secure vault (never in source control)
- [ ] Private keys stored with `chmod 600` permissions
- [ ] Cognito client secrets treated as sensitive (rotated on suspected compromise)
- [ ] Non-owner clients granted with the minimum necessary role
- [ ] Explicit permissions used when role defaults are too broad
- [ ] Unused clients revoked promptly
- [ ] Key rotation performed periodically or after any suspected exposure

### For client application developers

- [ ] Private key loaded from a secure location (Secrets Manager, vault, encrypted file)
- [ ] `jti` generated fresh per request (no assertion reuse)
- [ ] Assertion validity set to 60 seconds (do not increase)
- [ ] `acting_user` populated for audit trail in multi-user applications
- [ ] Cognito token refreshed before expiry (SDK does this automatically)
- [ ] Error handling for 401 (re-authenticate) and 403 (insufficient permissions)

### For platform operators

- [ ] `ClientKeysTable` and `ClientTenantsTable` have encryption at rest enabled
- [ ] DynamoDB backup/PITR enabled for auth tables
- [ ] CloudWatch alarms on elevated 401/403 rates
- [ ] Lambda function URLs are IAM-protected (not publicly accessible)
- [ ] API Gateway has Cognito authorizer enabled on all routes
- [ ] Migration script run after deployment to backfill legacy records
- [ ] Regular audit of client access lists across all namespaces

---

## API Reference

### Registry Endpoints (SigV4-authenticated)

| Method | Path | Description |
|--------|------|-------------|
| `GET` | `/namespaces/{ns}/clients` | List all clients for a namespace |
| `POST` | `/namespaces/{ns}/clients` | Grant a new client access |
| `PATCH` | `/namespaces/{ns}/clients/{id}` | Update role, permissions, or name |
| `DELETE` | `/namespaces/{ns}/clients/{id}` | Revoke client access |
| `POST` | `/namespaces/{ns}/clients/{id}/rotate-keys` | Rotate signing keys |

### Grant Request Body

```json
{
  "name": "Display name for the client",
  "role": "consumer",
  "permissions": ["tools:read", "tools:invoke"]
}
```

- `name` (required) — human-readable label
- `role` (optional, default `consumer`) — one of `owner`, `admin`, `consumer`
- `permissions` (optional) — explicit permission list; if provided, overrides role defaults

### Update Request Body

```json
{
  "role": "admin",
  "name": "New display name",
  "permissions": ["tools:read", "tools:invoke", "secrets:read"]
}
```

All fields are optional. Only provided fields are updated.

### Grant Response

```json
{
  "client_id": "AcmeCorp-c2a8f3",
  "name": "Analytics Dashboard",
  "role": "consumer",
  "permissions": ["templates:invoke", "templates:read", "tools:invoke", "tools:read"],
  "credentials": {
    "signing_key_id": "AcmeCorp-c2a8f3-key-1",
    "signing_private_key_pem": "-----BEGIN RSA PRIVATE KEY-----\n...",
    "cognito_client_id": "7abc2def3ghi...",
    "cognito_client_secret": "secret123..."
  }
}
```

The `credentials` object is only returned on grant and rotate-keys. The private key
is never stored by Tool Hub and cannot be retrieved later.
