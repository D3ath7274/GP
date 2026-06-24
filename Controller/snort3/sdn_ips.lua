-- Snort 3 config for the standalone Snort -> bridge -> Ryu IPS flow.
-- Install with: sudo Controller/scripts/install_snort3_ips_config.sh

HOME_NET = '10.0.0.0/8'
EXTERNAL_NET = '!$HOME_NET'
RULE_PATH = '/etc/snort/rules'

ips =
{
    variables =
    {
        nets =
        {
            HOME_NET = HOME_NET,
            EXTERNAL_NET = EXTERNAL_NET,
        },
    },
    enable_builtin_rules = true,
    include = RULE_PATH .. '/sdn_ips_local.rules',
}

stream = { }
stream_tcp = { }
stream_udp = { }
stream_icmp = { }
normalizer = { tcp = { ips = true } }

alert_json =
{
    file = true,
    fields = 'timestamp pkt_num proto src_ap dst_ap src_addr src_port dst_addr dst_port rule sid msg priority action',
    limit = 0,
}

alert_fast =
{
    file = true,
    packet = false,
}
