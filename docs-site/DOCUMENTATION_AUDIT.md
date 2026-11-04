# Source audit

- REST success may precede confirmation at the datapath. A protected MAC can cause the installer to skip while its REST caller records success.
- The dashboard timeline comes from Snort. Host firewall records are separate from the REST and tier block list.
- Models are fixed during runtime. Device profiles are in memory and scored flow rows are capped.
- The home collector implements a limited G11–G17 subset in the separate site-v3.0 schema, plus shadow device policy and reviewed descriptive profiles. It does not score site-v3 models or invoke automatic firewall writes.
- Full WAF inspection and the enterprise firewall-policy services are planned. The final-service matrix maps all 70 specification capabilities to current evidence and delivery phases; a roadmap entry is not delivered functionality.
