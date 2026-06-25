# Standalone Snort/Ryu File Manifest

Use these files for the standalone Snort 3 + Ryu IPS integration:

- `ryu_ips_app.py`
- `snort_ryu_bridge.py`
- `snort_alert_reader.py`
- `snort3/sdn_ips.lua`
- `snort3/sdn_ips_local.rules`
- `scripts/install_snort3_ips_config.sh`
- `scripts/start_snort3_json.sh`
- `scripts/start_snort_ryu_ips.sh`

The three Python files above are copied from `~/Desktop/sdn-ips-project`.

Do not use these older/team-integrated Snort files for the standalone VM flow:

- `Controller.py`
- `snort_monitor.py`
- `snort_setup.sh`
- `SNORT_IDS_README.md`

Those files belong to the teammates' integrated ML/dataset controller path. As of
the schema upgrade, that path now drives Snort 3 with the **same**
`/etc/snort/sdn_ips.lua` + `sdn_ips_local.rules` and parses **`alert_json`** — the
difference is that the team path adds ML/dataset capture and the UDP 9999 control
channel, and blocks in-process via `Controller.py` (OpenFlow DROP) instead of the
standalone `snort_ryu_bridge.py` + `snort_alert_reader.py` (REST/iptables). Run one
flow or the other, not both against the same alert file. (`snort_setup.sh` installs
the legacy Snort 2.x ruleset and is superseded by
`scripts/install_snort3_ips_config.sh` for detection rules.)
