# Configuration Reference

## Required Fields

### userinfoService
- **Type:** Service URL
- **Required:** Yes
- **Description:** Full Salesforce URL for UserInfo API calls. ⚠️ **MUST include `https://` protocol**
- **Examples:** 
  - `https://login.salesforce.com` (standard production)
  - `https://test.salesforce.com` (sandbox)
  - `https://trailsignup-0275fda3e77265.my.salesforce.com` (custom domain)
- **Note:** This is a Flex Gateway service URL, must be a complete URL with protocol

## Optional Fields

### userinfoPath
- **Type:** String
- **Default:** `/services/oauth2/userinfo`
- **Description:** API endpoint path on the Salesforce server
- **When to change:** Only if your org uses a custom domain with different path
- **Example:** `/services/oauth2/userinfo` (standard)

### propertiesKey
- **Type:** String
- **Default:** `custom_attributes`
- **Description:** Nested key under `principal.properties` where attributes are stored
- **ABAC access pattern:** `principal.properties.<propertiesKey>.<attributeName>`
- **Example:** If `propertiesKey = "custom_attributes"`, ABAC reads `principal.properties.custom_attributes.mcp_access_level`

### attributeAllowList
- **Type:** Array of strings
- **Default:** `[]` (empty = relay all attributes)
- **Description:** When non-empty, only relay attributes that appear in this list
- **Use case:** Security - prevent exposing sensitive Salesforce attributes
- **Example:** `["mcp_access_level", "org_id"]` - only these 2 pass through

### timeoutMs
- **Type:** Integer
- **Default:** `5000` (5 seconds)
- **Range:** 1000 - 30000 milliseconds
- **Description:** Max time to wait for Salesforce UserInfo response before treating as failure
- **When to adjust:** If your Salesforce org is slow or has latency

### cacheEnabled
- **Type:** Boolean
- **Default:** `true`
- **Description:** Cache UserInfo results per token to reduce Salesforce API calls
- **Performance impact:** Disabling causes a UserInfo call on EVERY request

### cacheTtlMinutes
- **Type:** Integer
- **Default:** `5` minutes
- **Range:** 0 - 60 minutes
- **Description:** How long to cache results
- **Smart behavior:** Never caches longer than token expiry (bounded by token lifetime)
- **Special:** Set to `0` for no time-based expiry (cache only until token expires)

### maxCacheEntries
- **Type:** Integer
- **Default:** `1000`
- **Minimum:** 1
- **Description:** Maximum number of cached tokens held in memory
- **Memory protection:** Prevents unbounded cache growth

### statusProperty
- **Type:** String
- **Default:** `mcp_enrichment_status`
- **Description:** Key written to `principal.properties.<statusProperty>` with status value
- **Possible values:**
  - `ok` - UserInfo succeeded
  - `error` - UserInfo failed (timeout, non-200, unparseable)
  - `unauthenticated` - No bearer token present
- **Use case:** ABAC rules can check if enrichment succeeded before evaluating attributes

## Hardcoded Behavior (Not Configurable)

### Cache Backend
- **Value:** `local` (in-memory, single-replica)
- **Why:** Multi-replica `remote` cache not yet implemented
- **Future:** May add Redis/external cache support

### Error Handling Mode
- **Value:** `denyClosed` (safe default)
- **Behavior:** On UserInfo failure, write empty attributes `{}` and continue
- **Effect:** ABAC rules checking for specific values will deny (fail-safe)
- **Why:** Prevents security holes from allowing open access on errors

### Format
- **Value:** Nested only (no flat projection)
- **Behavior:** Attributes always written to `principal.properties.<propertiesKey>.<attributeName>`
- **Why:** Simpler configuration, clearer ABAC rules

## Example Configuration

### Minimal (defaults)
```yaml
- policyRef:
    name: salesforce-userinfo-claims-enrichment-flex-v1-0
  config:
    userinfoService: https://trailsignup-0275fda3e77265.my.salesforce.com
```

### With attribute filtering
```yaml
- policyRef:
    name: salesforce-userinfo-claims-enrichment-flex-v1-0
  config:
    userinfoService: https://login.salesforce.com
    attributeAllowList:
      - mcp_access_level
      - org_id
```

### Custom caching
```yaml
- policyRef:
    name: salesforce-userinfo-claims-enrichment-flex-v1-0
  config:
    userinfoService: https://trailsignup-0275fda3e77265.my.salesforce.com
    propertiesKey: sf_attrs
    cacheEnabled: true
    cacheTtlMinutes: 10
    maxCacheEntries: 5000
```

### High-latency org
```yaml
- policyRef:
    name: salesforce-userinfo-claims-enrichment-flex-v1-0
  config:
    userinfoService: https://login.salesforce.com
    timeoutMs: 10000  # 10 seconds for slow org
```
