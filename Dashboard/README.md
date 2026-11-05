# Adaptive IPS framework dashboard

index.html is a dependency-free same-origin browser client shared by the site collector, legacy passive observer and retained Ryu lab. It is not the policy-management UI: policy_http.py serves the separate read-only workbench on loopback 8082.

For current collection use the home collector and its loopback/tunnel instructions in docs-site/deployment/home-collection.mdx. The UI reads status, metrics, alerts, collection/schema and shadow-policy information where the selected backend supports them. Missing endpoints and empty block lists must not be interpreted as a safe-network verdict.

Ryu additionally exposes block/unblock routes. Neither home_sensor.py nor passive_ids.py grants those writes; the read-only handler rejects unsupported HTTP methods. Any displayed legacy action state is not independent switch acknowledgment or actual containment evidence. Keep runtime-specific claims in docs-site/operations/dashboard.mdx and the corresponding OpenAPI contract.

The shared HTTP implementation is Controller/http_dashboard.py; the browser asset requires no npm/React build. Do not open the HTML as a local file and assume it can reach a collector with same-origin semantics. Use the served dashboard and keep private device data out of public examples.
