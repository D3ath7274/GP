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

Those files belong to the teammates' integrated ML/dataset controller path and
may start Snort with `/etc/snort/snort.lua` plus `alert_fast`, not this
standalone `alert_json` flow.
