// Copyright 2026 Salesforce, Inc. All rights reserved.
mod generated;

use std::collections::hash_map::DefaultHasher;
use std::hash::{Hash, Hasher};
use std::time::{Duration, SystemTime, UNIX_EPOCH};

use anyhow::{anyhow, Result};
use serde_json::{json, Value as JsonValue};

use pdk::authentication::{Authentication, AuthenticationData, AuthenticationHandler};
use pdk::data_storage::{DataStorage, DataStorageBuilder, StoreMode};
use pdk::hl::*;
use pdk::jwt::JWTClaimsParser;
use pdk::logger;
use pdk::policy_violation::PolicyViolations;

use crate::generated::config::Config;

// Status values written to statusProperty.
const STATUS_OK: &str = "ok";
const STATUS_ERROR: &str = "error";
const STATUS_UNAUTHENTICATED: &str = "unauthenticated";

// Defaults for Optional config fields — mirrors definition/gcl.yaml declarations.
const DEFAULT_USERINFO_PATH: &str = "/services/oauth2/userinfo";
const DEFAULT_TIMEOUT_MS: i64 = 5000;
const DEFAULT_CACHE_ENABLED: bool = true;
const DEFAULT_CACHE_TTL_MINUTES: i64 = 5;
const DEFAULT_MAX_CACHE_ENTRIES: i64 = 1000;
const DEFAULT_STATUS_PROPERTY: &str = "mcp_enrichment_status";
const DEFAULT_PROPERTIES_KEY: &str = "custom_attributes";

/// Compute a stable cache key from the raw bearer token.
fn cache_key(token: &str) -> String {
    let mut hasher = DefaultHasher::new();
    token.hash(&mut hasher);
    format!("sf-ui-{:x}", hasher.finish())
}

/// Current Unix timestamp in seconds.
fn now_secs() -> u64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap_or_default()
        .as_secs()
}

/// Wrap the attrs pair-set with an explicit expiry timestamp for TTL-bounded local cache.
///
/// PDK `DataStorageBuilder::local()` has no per-entry TTL — `StoreMode::Always` stores
/// indefinitely. We therefore store `{"exp": epoch_secs, "v": attrs}` and validate `exp`
/// on every read. A stale entry (exp <= now) is treated as a miss and discarded.
fn cache_wrap(attrs: &JsonValue, expiry_secs: u64) -> String {
    let entry = json!({"exp": expiry_secs, "v": attrs});
    serde_json::to_string(&entry).unwrap_or_else(|_| "{}".to_string())
}

/// Read a cached entry, returning `None` if absent or expired.
fn cache_unwrap(raw: &str) -> Option<JsonValue> {
    let entry: JsonValue = serde_json::from_str(raw).ok()?;
    let exp = entry.get("exp").and_then(|v| v.as_u64()).unwrap_or(0);
    let now = now_secs();
    if exp == 0 || now >= exp {
        logger::debug!(
            "[sf-userinfo-enrichment] STEP 3: cache entry expired (exp={} now={}) — discarding",
            exp,
            now
        );
        return None;
    }
    entry.get("v").cloned()
}

/// Write the enriched principal into the Authentication injectable.
///
/// `attrs` is the whole `custom_attributes` pair-set as a `serde_json::Value::Object`
/// (e.g. `{"mcp_access_level":"full","other_attr":"value"}`).
///
/// The pair-set is relayed as a nested record under `config.properties_key`
/// (default `custom_attributes`) — mirroring how JWT Validation nests the full claim
/// set under `principal.properties.claims`.
///
/// `serde_json::Value` implements PDK's `IntoValue` trait, so passing it directly
/// to `AuthenticationData::new` produces a proper `pdk::script::Value::Object(HashMap)`
/// that downstream policies can deserialise as a map.
fn write_auth(authentication: &Authentication, config: &Config, attrs: &JsonValue, status: &str) {
    let properties_key = config
        .properties_key
        .as_deref()
        .unwrap_or(DEFAULT_PROPERTIES_KEY);
    let status_property = config
        .status_property
        .as_deref()
        .unwrap_or(DEFAULT_STATUS_PROPERTY);

    let existing = authentication.authentication();

    // Build the properties object:
    // 1. Nested pair-set: props[propertiesKey] = attrs
    // 2. Optional flat projection: props[propertyName] = attrs[attributeName]
    // 3. Status: props[statusProperty] = "ok"|"error"|"unauthenticated"
    let mut props_map = serde_json::Map::new();

    // 1. Nested pair-set
    props_map.insert(properties_key.to_string(), attrs.clone());

    // 2. Status
    props_map.insert(
        status_property.to_string(),
        JsonValue::String(status.to_string()),
    );

    // Pass serde_json::Value::Object directly — IntoValue converts it to
    // pdk::script::Value::Object(HashMap), which downstream policies can deserialise.
    let props = JsonValue::Object(props_map);

    let new_auth = if let Some(ref auth) = existing {
        AuthenticationData::new(
            auth.principal.clone(),
            auth.client_id.clone(),
            auth.client_name.clone(),
            props,
        )
    } else {
        AuthenticationData::new(None, None, None, props)
    };

    authentication.set_authentication(Some(&new_auth));
}

/// Handle indeterminate outcomes — log, policy violation, onEnrichmentError dispatch.
/// Never a silent pass-through.
fn handle_failure(
    config: &Config,
    authentication: &Authentication,
    policy_violations: &PolicyViolations,
    reason: &str,
) -> Flow<()> {
    logger::error!(
        "[sf-userinfo-enrichment] INDETERMINATE: reason={} — raising policy violation",
        reason
    );
    policy_violations.generate_policy_violation();

    // Error handling is hardcoded to "denyClosed" mode (safe default):
    // Inject empty pair-set so ABAC rules fail to find required attributes and naturally deny.
    logger::warn!(
        "[sf-userinfo-enrichment] denyClosed: injecting empty pair-set for reason={}",
        reason
    );
    write_auth(authentication, config, &json!({}), STATUS_ERROR);
    Flow::Continue(())
}

/// Per-request enrichment: extract bearer token, check cache, call UserInfo, relay pair-set.
async fn enrich(
    request_state: RequestState,
    config: &Config,
    client: HttpClient,
    storage: &impl DataStorage,
    policy_violations: &PolicyViolations,
    authentication: Authentication,
) -> Flow<()> {
    let headers_state = request_state.into_headers_state().await;
    let handler = headers_state.handler();

    let cache_enabled = config.cache_enabled.unwrap_or(DEFAULT_CACHE_ENABLED);
    let timeout_ms = config.timeout_ms.unwrap_or(DEFAULT_TIMEOUT_MS);
    let cache_ttl_minutes = config
        .cache_ttl_minutes
        .unwrap_or(DEFAULT_CACHE_TTL_MINUTES);
    let userinfo_path = config
        .userinfo_path
        .as_deref()
        .unwrap_or(DEFAULT_USERINFO_PATH);

    // ── 1. Extract bearer token ────────────────────────────────────────────
    let auth_header = handler.header("authorization").unwrap_or_default();
    let token: String =
        if auth_header.len() > 7 && auth_header[..7].eq_ignore_ascii_case("bearer ") {
            auth_header[7..].trim().to_string()
        } else {
            String::new()
        };

    if token.is_empty() {
        logger::warn!("[sf-userinfo-enrichment] STEP 1: no bearer token — marking unauthenticated");
        write_auth(&authentication, config, &json!({}), STATUS_UNAUTHENTICATED);
        return Flow::Continue(());
    }

    // ── 2. Parse token for cache key + remaining lifetime ──────────────────
    let key = cache_key(&token);

    let token_exp_secs: Option<u64> = JWTClaimsParser::parse(token.clone())
        .ok()
        .and_then(|claims| claims.get_claim("exp"))
        .and_then(|v: serde_json::Value| v.as_u64());

    if token_exp_secs.is_none() {
        logger::warn!(
            "[sf-userinfo-enrichment] STEP 2: token exp unparseable — TTL bounding disabled"
        );
    }

    let secs_remaining: Option<u64> = token_exp_secs.and_then(|exp| {
        let now = now_secs();
        if exp > now {
            Some(exp - now)
        } else {
            None
        }
    });

    // ── 3. Cache fast-path ────────────────────────────────────────────────
    // Cache entries are stored as {"exp": epoch_secs, "v": attrs}.
    // PDK local() storage has no per-entry TTL, so we enforce expiry manually
    // via cache_wrap/cache_unwrap. A stale entry is discarded and triggers a
    // live UserInfo call instead of silently serving an outdated value.
    if cache_enabled {
        match storage.get::<String>(&key).await {
            Ok(Some((cached_raw, _version))) => {
                match cache_unwrap(&cached_raw) {
                    Some(cached_attrs) => {
                        logger::debug!(
                            "[sf-userinfo-enrichment] STEP 3 HIT: serving from cache attrs={}",
                            cached_attrs
                        );
                        write_auth(&authentication, config, &cached_attrs, STATUS_OK);
                        return Flow::Continue(());
                    }
                    None => {
                        // cache_unwrap already logged the expiry reason.
                        logger::debug!(
                            "[sf-userinfo-enrichment] STEP 3 EXPIRED: proceeding to live UserInfo call"
                        );
                    }
                }
            }
            Ok(None) => {
                logger::debug!(
                    "[sf-userinfo-enrichment] STEP 3 MISS: no cache entry — proceeding to live UserInfo call"
                );
            }
            Err(e) => {
                logger::warn!(
                    "[sf-userinfo-enrichment] STEP 3 ERROR: cache get failed [{}] — falling back to live UserInfo",
                    e
                );
            }
        }
    } else {
        logger::debug!(
            "[sf-userinfo-enrichment] STEP 3: cache disabled — skipping to live UserInfo call"
        );
    }

    // ── 4. Live UserInfo call ─────────────────────────────────────────────
    logger::debug!(
        "[sf-userinfo-enrichment] STEP 4: calling UserInfo path={} timeout={}ms",
        userinfo_path,
        timeout_ms
    );

    let bearer_value = format!("Bearer {}", token);
    let response_result = client
        .request(&config.userinfo_service)
        .path(userinfo_path)
        .headers(vec![
            ("authorization", bearer_value.as_str()),
            ("accept", "application/json"),
        ])
        .timeout(Duration::from_millis(timeout_ms as u64))
        .get()
        .await;

    let response = match response_result {
        Ok(r) => {
            logger::debug!(
                "[sf-userinfo-enrichment] STEP 4 OK: UserInfo HTTP {}",
                r.status_code()
            );
            r
        }
        Err(e) => {
            logger::error!(
                "[sf-userinfo-enrichment] STEP 4 FAIL: transport/timeout error — {}",
                e
            );
            return handle_failure(
                config,
                &authentication,
                policy_violations,
                "userinfo_unreachable",
            );
        }
    };

    // ── 5. Validate HTTP status ───────────────────────────────────────────
    let http_status = response.status_code();
    if http_status != 200 {
        logger::error!(
            "[sf-userinfo-enrichment] STEP 5 FAIL: UserInfo returned HTTP {} (expected 200)",
            http_status
        );
        return handle_failure(
            config,
            &authentication,
            policy_violations,
            &format!("userinfo_status_{}", http_status),
        );
    }

    // ── 6. Parse JSON body ────────────────────────────────────────────────
    let body_bytes = response.body();

    let body_str = match std::str::from_utf8(body_bytes) {
        Ok(s) => s,
        Err(_) => {
            logger::error!(
                "[sf-userinfo-enrichment] STEP 6 FAIL: UserInfo body not valid UTF-8 (len={})",
                body_bytes.len()
            );
            return handle_failure(
                config,
                &authentication,
                policy_violations,
                "userinfo_unparseable",
            );
        }
    };

    // Log the first 300 chars of the response body at DEBUG level only — the
    // UserInfo response contains PII (name, email, org ID) and attribute values
    // that must not appear in production INFO logs.
    logger::debug!(
        "[sf-userinfo-enrichment] STEP 6: body_len={} body_preview={}",
        body_str.len(),
        &body_str[..body_str.len().min(300)]
    );

    let body_json: JsonValue = match serde_json::from_str(body_str) {
        Ok(v) => v,
        Err(e) => {
            logger::error!(
                "[sf-userinfo-enrichment] STEP 6 FAIL: UserInfo body not valid JSON — {}",
                e
            );
            return handle_failure(
                config,
                &authentication,
                policy_violations,
                "userinfo_unparseable",
            );
        }
    };

    if !body_json.is_object() {
        logger::error!("[sf-userinfo-enrichment] STEP 6 FAIL: UserInfo JSON root is not an object");
        return handle_failure(
            config,
            &authentication,
            policy_violations,
            "userinfo_unparseable",
        );
    }

    // ── 7. Relay the whole custom_attributes pair-set ─────────────────────
    // A missing or empty custom_attributes is DETERMINATE (user has nothing configured).
    // ABAC rules checking for a specific value will simply not match and deny writes.
    let raw_attrs = body_json
        .get("custom_attributes")
        .and_then(|v| if v.is_object() { Some(v.clone()) } else { None })
        .unwrap_or_else(|| json!({}));

    logger::debug!(
        "[sf-userinfo-enrichment] STEP 7: custom_attributes from UserInfo = {}",
        raw_attrs
    );

    // Apply allow-list filter if configured.
    let attrs: JsonValue = match &config.attribute_allow_list {
        Some(allow_list) if !allow_list.is_empty() => {
            let filtered: serde_json::Map<String, JsonValue> = raw_attrs
                .as_object()
                .map(|m| {
                    m.iter()
                        .filter(|(k, _)| allow_list.contains(k))
                        .map(|(k, v)| (k.clone(), v.clone()))
                        .collect()
                })
                .unwrap_or_default();
            logger::debug!(
                "[sf-userinfo-enrichment] STEP 7: allow-list filter: {} keys before, {} after",
                raw_attrs.as_object().map(|m| m.len()).unwrap_or(0),
                filtered.len()
            );
            JsonValue::Object(filtered)
        }
        _ => raw_attrs,
    };

    // ── 8. Cache the determinate result ───────────────────────────────────
    // Effective TTL = min(configured TTL, remaining token lifetime).
    // We wrap the value with an explicit expiry epoch so local storage can be
    // TTL-bounded despite having no native per-entry expiry.
    if cache_enabled {
        let configured_secs = (cache_ttl_minutes as u64) * 60;
        let effective_ttl_secs = match secs_remaining {
            Some(secs) if secs > 0 => {
                if configured_secs > 0 {
                    configured_secs.min(secs)
                } else {
                    secs
                }
            }
            _ => configured_secs,
        };

        if effective_ttl_secs > 0 {
            let expiry = now_secs() + effective_ttl_secs;
            let cache_str = cache_wrap(&attrs, expiry);
            logger::debug!(
                "[sf-userinfo-enrichment] STEP 8: caching key={} expiry_secs={} effective_ttl_secs={}",
                key,
                expiry,
                effective_ttl_secs
            );
            match storage.store(&key, &StoreMode::Always, &cache_str).await {
                Ok(_) => {}
                Err(e) => logger::warn!(
                    "[sf-userinfo-enrichment] STEP 8 WARN: cache store failed [{}] — continuing",
                    e
                ),
            }
        } else {
            logger::debug!("[sf-userinfo-enrichment] STEP 8: effective TTL=0 — not caching");
        }
    }

    // ── 9. Write to Authentication injectable ─────────────────────────────
    logger::debug!(
        "[sf-userinfo-enrichment] STEP 9: writing attrs={} status={}",
        attrs,
        STATUS_OK
    );
    write_auth(&authentication, config, &attrs, STATUS_OK);
    Flow::Continue(())
}

#[entrypoint]
async fn configure(
    launcher: Launcher,
    Configuration(bytes): Configuration,
    store_builder: DataStorageBuilder,
    policy_violations: PolicyViolations,
) -> Result<()> {
    let config: Config = serde_json::from_slice(&bytes).map_err(|err| {
        anyhow!(
            "salesforce-userinfo-claims-enrichment: failed to parse configuration '{}'. Cause: {}",
            String::from_utf8_lossy(&bytes),
            err
        )
    })?;

    // Validate at apply time — loud failure, not silent runtime surprise.
    let ttl = config
        .cache_ttl_minutes
        .unwrap_or(DEFAULT_CACHE_TTL_MINUTES);
    if ttl < 0 {
        return Err(anyhow!(
            "salesforce-userinfo-claims-enrichment: cacheTtlMinutes must be >= 0, got {}",
            ttl
        ));
    }
    let max_entries = config
        .max_cache_entries
        .unwrap_or(DEFAULT_MAX_CACHE_ENTRIES);
    if max_entries < 1 {
        return Err(anyhow!(
            "salesforce-userinfo-claims-enrichment: maxCacheEntries must be >= 1, got {}",
            max_entries
        ));
    }

    // Build cache storage backend based on configuration.
    // Cache backend is hardcoded to local (in-process memory, single-replica only)
    let storage = store_builder.local("sf-userinfo-claims");

    logger::info!(
        "[sf-userinfo-enrichment] policy loaded ✓ — propertiesKey={} cacheEnabled={} ttlMin={}",
        config.properties_key.as_deref().unwrap_or(DEFAULT_PROPERTIES_KEY),
        config.cache_enabled.unwrap_or(DEFAULT_CACHE_ENABLED),
        ttl
    );

    let filter = on_request(
        |rs, (client, authentication): (HttpClient, Authentication)| {
            enrich(
                rs,
                &config,
                client,
                &storage,
                &policy_violations,
                authentication,
            )
        },
    );

    launcher.launch(filter).await?;
    Ok(())
}
