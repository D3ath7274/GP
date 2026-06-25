-- Snort 3 config — shared by BOTH flows:
--   * standalone Snort -> bridge -> Ryu IPS (snort_alert_reader.py), and
--   * the team integrated controller (snort_monitor.py drives Snort with this
--     config and parses its alert_json output).
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

-- ARP spoofing detection (session 6). The arp_spoof inspector emits built-in
-- GID 112 alerts; in particular 112:2 fires when an ARP reply maps a known IP to
-- a DIFFERENT MAC than configured here — exactly what arpspoof does. Requires
-- enable_builtin_rules = true (set above). snort_monitor.classify_attack() maps
-- the inspector's "arp cache overwrite"/"arp mismatch" messages to "ARP Spoofing".
--
-- Bindings below are the STATIC ones from SDN Topology/topology.py. Mininet
-- assigns h1/h2 and the IoT hosts dynamic MACs at runtime — append them here
-- (read from the controller's frozen DAI baseline / `mininet> nodes`) so their
-- IPs are protected too. The controller DAI tier remains the authoritative ARP
-- detector; this inspector is the Snort-side corroboration.
arp_spoof =
{
    hosts =
    {
        { ip = '10.0.0.1', mac = '42:00:00:00:00:00' },   -- sta1
        { ip = '10.0.0.2', mac = '42:00:00:00:01:00' },   -- sta2
        -- { ip = '10.0.0.3', mac = '<h1-mac>' },          -- TODO: fill from runtime
        -- { ip = '10.0.0.4', mac = '<h2-mac>' },          -- TODO: fill from runtime
        -- { ip = '10.0.0.5', mac = '<TempSensor-mac>' },  -- TODO: fill from runtime
        -- { ip = '10.0.0.6', mac = '<Cam-mac>' },         -- TODO: fill from runtime
    },
}

-- Nmap port-scan detection (session 5). The port_scan inspector flags a source
-- that touches many destination ports — which a SYN flood (single port) does
-- NOT trigger, so it cleanly separates the scan from the SYN flood. Emits
-- built-in GID 122 alerts ("...portscan..."); snort_monitor.classify_attack()
-- maps those to "Port Scan". Requires enable_builtin_rules = true (set above).
-- If this block fails `snort -c sdn_ips.lua -T` on your build, comment it out
-- and use the fallback rule in sdn_ips_local.rules (SID 1000005).
port_scan =
{
    protos = 'tcp',
    scan_types = 'all',
}

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
