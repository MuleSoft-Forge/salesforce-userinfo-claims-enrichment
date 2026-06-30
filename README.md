# Salesforce UserInfo Claims Enrichment Policy

A [MuleSoft Flex Gateway PDK](https://docs.mulesoft.com/pdk/latest/) custom policy that enriches the Authentication principal with per-user attributes from Salesforce UserInfo endpoint.

## Overview

**What it does (3 steps):**
1. **Extract bearer token** from `Authorization` header
2. **Call Salesforce UserInfo** endpoint with that token  
3. **Map response to Authentication** - Write `custom_attributes` into `principal.properties`

**Why this is needed:** Salesforce custom permissions and user attributes are **not in JWT access tokens** - they're only available at the Salesforce UserInfo endpoint.

**Key features:**
- Generic attribute enrichment (works with any Salesforce custom attribute)
- Smart caching (TTL bounded by token expiry)
- Fail-safe error handling (never silent)
- Detailed observability (structured logging at every step)

**Common use cases:**
- Per-user authorization (MCP tool access, API permissions)
- Multi-tenant routing (route by org/user attributes)
- Conditional policies (rate limits, logging verbosity by user tier)
- Feature flags (enable/disable per Salesforce permission set)

## When and Why to Use

### What This Policy Actually Requires

**Minimum requirements:**
- ✅ Request has `Authorization: Bearer <token>` header
- ✅ Token is accepted by Salesforce UserInfo endpoint
- ✅ Salesforce org has custom attributes configured

**Common misconceptions:**
- ❌ Does NOT require JWT Validation policy (recommended but optional)
- ❌ Does NOT require token to be JWT format (works with any bearer token)
- ❌ Does NOT validate the token itself (Salesforce UserInfo does that)

**How it actually works:**
1. Extracts bearer token from `Authorization` header (any format)
2. Optionally parses as JWT for cache TTL optimization (not required)
3. Calls Salesforce UserInfo endpoint with the token
4. Salesforce validates the token and returns custom attributes
5. Policy enriches `principal.properties` with the response

**Why JWT Validation is still recommended:**
- **Fails fast** - Rejects invalid tokens before calling Salesforce (saves latency)
- **Sets principal** - Establishes `principal`, `client_id`, `client_name` that this policy preserves
- **Better errors** - JWT Validation gives clear 401 errors vs. this policy's 503 on UserInfo failure

**This policy is generic:**
- Works with Salesforce access tokens, OAuth2 tokens, or any bearer token Salesforce accepts
- Not MCP-specific (just enriches Authentication properties for any downstream use)
- Not ABAC-specific (downstream policies decide what to do with the attributes)

### Typical Use Cases

1. **Per-user authorization** (any downstream policy/ABAC)
   - MCP tool access control (read vs. write tools)
   - API operation permissions
   - Resource-level access control

2. **Multi-tenant routing** - Route by Salesforce org/user attributes

3. **Conditional rate limiting** - Different quotas per user tier

4. **Feature flags** - Enable/disable per Salesforce permission set

5. **Audit enrichment** - Log user attributes for compliance

## Why This Policy Exists

**The core problem:** Salesforce custom permissions and user attributes are **not in access tokens**. They're only available at the UserInfo endpoint.

**Why not alternatives?**
- ❌ **Token claims** - Salesforce doesn't put custom attributes in access tokens
- ❌ **Token introspection** - Salesforce rejects JWT token introspection
- ❌ **Client-side enrichment** - Not trusted, requires client changes
- ✅ **Gateway-side UserInfo call** - Only path that works

**This policy is the scalable solution:** Call UserInfo once per token, cache the result, enrich the principal for all downstream policies to use.

## Prerequisites - Salesforce Setup

Before applying this policy, a Salesforce admin must:

1. **Enable OAuth** on the Connected App / External Client App
2. **Add `openid` scope** to the app configuration
3. **Enable Custom Attributes**:
   - Go to app's ID Token settings
   - Enable "Configure ID Token" → "Include Custom Attributes"
4. **Create a Custom Attribute** (e.g., `mcp_access_level`):
   - Define as a formula that resolves from a Custom Permission or other per-user data
   - Example: `IF($Permission.MCP_Write_Access, "full", "readonly")`
5. **Assign Permission Sets** to users as needed

The attribute name and values are entirely up to the admin. The policy is generic.

## Configuration

| Property | Type | Required | Default | Description |
|---|---|---|---|---|
| `userinfoService` | Service | ✅ | — | Flex Gateway service pointing to Salesforce UserInfo host (e.g., `login.salesforce.com`) |
| `userinfoPath` | String | | `/services/oauth2/userinfo` | Path of the UserInfo endpoint |
| `propertiesKey` | String | | `custom_attributes` | Nested key written under `principal.properties` holding the full pair-set |
| `attributeAllowList` | Array<String> | | `[]` | When non-empty, only relay these custom_attributes keys |
| `attributeName` | String | | — | Optional: single attribute to project flat for simple Cedar rules |
| `propertyName` | String | | = `attributeName` | Optional: flat property name for single-attribute projection |
| `timeoutMs` | Integer | | `5000` | UserInfo HTTP request timeout (1000-30000ms) |
| `cacheEnabled` | Boolean | | `true` | Cache results per token |
| `cacheTtlMinutes` | Integer | | `5` | Cache TTL in minutes (0-60, effective TTL bounded by token lifetime) |
| `maxCacheEntries` | Integer | | `1000` | Max cache entries (memory bound) |
| `cacheBackend` | Enum | | `local` | `local` (single-replica) or `remote` (multi-replica, v1.0 logs intent only) |
| `onEnrichmentError` | Enum | | `denyClosed` | `denyClosed` (empty attrs), `failRequest` (503), or `allowOpen` (permissive, discouraged) |
| `statusProperty` | String | | `mcp_enrichment_status` | Property carrying `ok`/`error`/`unauthenticated` status |

## Example Policy Configuration

```yaml
- policyRef:
    name: salesforce-userinfo-claims-enrichment-flex-v1-0
  config:
    userinfoService: login.salesforce.com
    propertiesKey: custom_attributes
    attributeAllowList:
      - mcp_access_level
      - org_id
    timeoutMs: 5000
    cacheEnabled: true
    cacheTtlMinutes: 5
    onEnrichmentError: denyClosed
```

## ABAC Integration - Example Cedar Rules

After this policy runs, `principal.properties.<propertiesKey>.<attribute>` contains the Salesforce custom attributes.

**Example:** Attribute is `mcp_access_level` with values `"full"` or `"readonly"`

```yaml
rules:
  # Read tools: open to all authenticated principals
  - 'permit(principal, action == Action::"tools/call", resource) when {
       [ Tool::"getRecord", Tool::"listRecords", Tool::"search" ].contains(resource)
     };'
  
  # Write tools: only principals with mcp_access_level == "full"
  - 'permit(principal, action == Action::"tools/call", resource) when {
       [ Tool::"createRecord", Tool::"updateRecord" ].contains(resource)
       && principal has properties
       && principal.properties has custom_attributes
       && principal.properties.custom_attributes has mcp_access_level
       && principal.properties.custom_attributes.mcp_access_level == "full"
     };'
authType: Other
```

**Hardened variant** (also require successful enrichment status):

```yaml
  - 'permit(principal, action == Action::"tools/call", resource) when {
       [ Tool::"createRecord", Tool::"updateRecord" ].contains(resource)
       && principal has properties
       && principal.properties has mcp_enrichment_status
       && principal.properties.mcp_enrichment_status == "ok"
       && principal.properties has custom_attributes
       && principal.properties.custom_attributes has mcp_access_level
       && principal.properties.custom_attributes.mcp_access_level == "full"
     };'
```

## Policy Order

Apply policies in this sequence (client → upstream):

1. **JWT Validation** — validates access token, sets principal
2. **Header Removal** — removes `Accept-Encoding` (MCP requirement)
3. **salesforce-userinfo-claims-enrichment** (this policy) — enriches principal
4. **MCP Global Access** — blocks `^delete` operations
5. **MCP ABAC** — per-user Cedar rules reading `principal.properties`
6. **MCP Support** — observability/diagnostics

## How It Works

```
Request with Bearer token
   ↓
JWT Validation Policy → validates token, sets principal
   ↓
This Policy:
   1. Extract Authorization: Bearer <token>
   2. Hash token as cache key, parse exp claim
   3. Check cache (hit → skip network call)
   4. On miss: GET /services/oauth2/userinfo with bearer token
   5. Parse custom_attributes from JSON response
   6. Cache result (TTL = min(config.ttl, token.exp))
   7. Write principal.properties.<propertiesKey> = custom_attributes
   8. Write principal.properties.<statusProperty> = "ok"|"error"|"unauthenticated"
   ↓
MCP ABAC Policy → Cedar rules evaluate principal.properties
```

## Caching

- **Cache key:** Hash of bearer token
- **Effective TTL:** `min(configured_ttl_minutes, token_remaining_lifetime)`
- **Negative caching:** Yes — empty attributes are also cached (determinate)
- **Multi-replica:** v1.0 uses local cache (single-replica). Set `cacheBackend: remote` to log intent for future versions

**Cache safety:** Never caches past token expiry, so revoked tokens don't persist stale permissions.

## Error Handling

This policy follows **NO SILENT FAILING** and **OVER-ENGINEERED LOGGING** principles:

- Every error path logs explicitly
- Every error generates a PolicyViolation (visible in Anypoint Monitoring)
- Status always written to `principal.properties.<statusProperty>`

**Three failure modes:**

1. **`denyClosed` (default, recommended):** Inject empty pair-set `{}`. Cedar rules looking for specific attributes naturally deny. Safe default.
2. **`failRequest`:** Return HTTP 503 with JSON-RPC error `-32603`. Short-circuits the request. Use when enrichment is critical.
3. **`allowOpen` (discouraged):** Inject permissive value (e.g., `{"mcp_access_level": "full"}`). Fully logged. Only for debugging.

## Observability

All major steps log at INFO level with structured key-value pairs:

```
[sf-userinfo-enrichment] STEP 1: extract_token status=found
[sf-userinfo-enrichment] STEP 2: cache_lookup key_hash=abc123 result=miss
[sf-userinfo-enrichment] STEP 3: userinfo_call url=https://... duration_ms=123 status=200
[sf-userinfo-enrichment] STEP 4: parse_response attrs_count=2 filtered_count=2
[sf-userinfo-enrichment] STEP 5: cache_store key_hash=abc123 ttl_secs=300
[sf-userinfo-enrichment] STEP 6: write_auth status=ok propertiesKey=custom_attributes
```

Search logs for `[sf-userinfo-enrichment]` to trace policy behavior.

## Build from Source

```bash
# Prerequisites
make setup      # Install cargo-anypoint v1.9.0

# Build
make build      # Compile to WASM + generate YAMLs

# Test (requires Docker)
make test

# Publish to Anypoint Exchange
make publish    # Dev version with timestamp
make release    # Release version
```

## Technical Details

- **PDK Version:** 1.9.0+
- **Rust Version:** 1.88.0+
- **Target:** `wasm32-wasip1`
- **WASM Size:** ~800KB (optimized)
- **License:** Apache 2.0

## Security Considerations

- Token is hashed for cache key (not stored plaintext)
- Attribute VALUES are not logged (PII safety)
- Only attribute NAMES and COUNTS appear in logs
- Cache TTL never exceeds token expiry
- No UserInfo call if bearer token missing (fast fail)

## License

Copyright 2026 Salesforce, Inc. All rights reserved.

Licensed under the Apache License, Version 2.0. See LICENSE file for details.

## Support

- **Issues:** [GitHub Issues](https://github.com/YOUR-ORG/salesforce-userinfo-claims-enrichment/issues)
- **Docs:** [MuleSoft PDK Documentation](https://docs.mulesoft.com/pdk/latest/)
- **P4A Platform:** [https://www.p4a.ai](https://www.p4a.ai)

---

**Version:** 1.0.0  
**Status:** Production Ready  
**Submitted to:** P4A (Policies for Agents)
