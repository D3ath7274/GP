# Source audit

- REST success may precede confirmation at the datapath. A protected MAC can cause the installer to skip while its REST caller records success.
- The dashboard timeline comes from Snort. Host firewall records are separate from the REST and tier block list.
- Models are fixed during runtime. Device profiles are in memory and scored flow rows are capped.
- The WAF, firewall auditor and v3 feature schema are proposals.
