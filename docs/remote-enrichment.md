# Explicit remote enrichment

Measurements run independently of metadata. Nothing contacts an enrichment
provider unless `--enrich-provider` is supplied. Enrichment runs **after** probes
and transfers, collecting unique target and responding-hop addresses. Existing
`--enrichment-file` exact-IP records take precedence, so those addresses are not
sent to a remote provider. A lookup failure never discards measurements.

Enabling a provider discloses each requested IP and the connecting client's public
source IP to that provider. No probe statistics or report are uploaded. Nonpublic
addresses are skipped by a conservative local policy (including private, loopback,
link-local, documentation, multicast and shared-address space). This policy is not
a complete global routing registry. `--enrich-private` explicitly permits those
lookups only for the custom JSON adapter. Remote enrichment requires JSON output
so per-IP status and attribution are retained; it is not accepted with list-only
mode or CSV output.

## IPinfo Lite

```sh
# Set IPINFO_TOKEN in the environment using your normal secret management.
tcp-bench-rs --target YOUR_TARGET_IP --count 3 --budget 30 \
  --enrich-provider ipinfo-lite --enrich-max-requests 10
```

The endpoint is `https://api.ipinfo.io/lite/IP`. `IPINFO_TOKEN` is required, or
select another environment variable with `--enrich-token-env NAME`. The token is
sent only as an HTTPS Bearer header. It is never placed in the URL, report or
cache, and redirects are disabled. Certificate verification remains mandatory.
An explicit `--enrich-url` can override the base URL; credentials then go to that
chosen origin, so use only a provider endpoint you trust.

The adapter maps `asn: "AS<number>"` to an integer, `as_name` to organization,
and `country` (falling back to `country_code`) to location. This is country-level
information, not city coordinates or router ownership/path classification. The
response IP must match the requested IP; a bogon response means no metadata.
Attribution `IPinfo — https://ipinfo.io` is retained with remote and cached results.

Use your own account and comply with provider usage, retention and attribution
terms. Public API access is not permission to redistribute its dataset. No
provider dataset is bundled. Optional caching is a mechanism, not a grant of
retention rights. Public displays of provider data must retain required attribution.
Sources: [Lite schema](https://ipinfo.io/developers/lite-api),
[authentication](https://ipinfo.io/developers),
[Lite usage and attribution](https://support.ipinfo.io/hc/en-us/articles/34121895556242-Legacy-Free-API-vs-IPinfo-Lite),
and [terms](https://ipinfo.io/terms-of-service).

## Custom JSON provider

```sh
tcp-bench-rs --target 127.0.0.1 --iperf3 --max-bytes 65536 --budget 10 \
  --enrich-provider json --enrich-url http://127.0.0.1:8080/lookup \
  --enrich-private --allow-http
```

GET requests append `/IP` to the configured base URL. The response is an object
such as `{"ip":"127.0.0.1","asn":64500,"organization":"Lab","location":"Local"}`.
`ip` is required and must match. All other fields may be null/missing; ASN must be
a positive u32 and text fields at most 512 bytes without control characters.
An all-null record or HTTP 404 means not found. IPv6 addresses are appended as
plain colon-separated path text, not bracketed authorities. URL credentials,
query parameters and fragments are refused. An optional token uses the same
Bearer mechanism; even `--allow-http` never permits plaintext authentication.

## Bounds, cache and reporting

Requests are sequential and globally paced at `--enrich-rate` (default 2/s,
1–10/s), with `--enrich-max-requests` (default 128, maximum 4096) per run. Cache
hits, local records and skipped addresses consume no requests. Each lookup has
`--enrich-timeout` (default 5 seconds, maximum 30), including DNS, connect, TLS,
headers and body. Responses are limited to 16 KiB. There are no automatic retries.
HTTP 401/403/429 stops further remote requests in that pass. The overall
`--budget` can cancel enrichment; local/cached data remains usable after cancellation.

No persistent cache is created by default. `--enrich-cache PATH` opts into storing
validated metadata with provider/base-URL identity and fetch timestamps.
`--enrich-cache-ttl` defaults to 3600 seconds, maximum 86400; zero disables hits.
Expired, future-dated, malformed, oversized or mismatched cache contents are
ignored and never served as stale data on network failure. The cache is bounded
to 4096 records/8 MiB and written by temporary file plus atomic rename. It contains
requested IPs and normalized metadata, never credentials or raw responses.

JSON v1 adds `enrichment_lookups` alongside the existing `enrichment` metadata map.
Each IP records `status`, `provider`, `attribution`, `fetched_unix_seconds` and
optional `error`. Status is `local`, `remote`, `cache`, `not_found`,
`skipped_nonpublic`, `request_limit`, `cancelled`, `timeout`, `rate_limited`,
`unauthorized`, `provider_unavailable` or `error`. Cache write failures are retained
separately in `enrichment_cache_error`. Authentication/rate/transport/parse failures
and cache write errors cause exit 1 after emitting the report. Missing/skipped
metadata and the explicit request limit are not measurement failures.

Tests use local HTTP/TLS servers and independent provider fixtures, covering
response binding, cache identity/expiry, cancellation, limits, authentication,
and explicit CLI opt-in. No live IPinfo account or public endpoint was exercised.
