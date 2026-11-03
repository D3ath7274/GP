# Feature Groups v3 — Covering the Blind Spots

Design for new feature groups that close the system's detection blind spots (reconnaissance,
web-application abuse, slow attacks, command-and-control, spoofing). They also build the
evidence base the firewall-audit direction needs: you can't audit whether a firewall stops
reconnaissance until you can measure reconnaissance yourself.

---

## 1. Ground rules

**1.1 Append, never edit.** New columns go *after* the 102 v2 columns, behind
`IPS_V3_FEATURES=1`. Both shipped models select their inputs by name: the RF reindexes to its
trained column list (`ml_inference.py:97`), and the AE builds its vector from `features` in
its bundle. So v3 rows run on the v2 models unchanged, and the new columns stay unused until
you retrain. The one exception is the `device_new_dst_ratio` bug fix (§4), which changes an
existing column on purpose.

**1.2 Three privacy levels, each behind an explicit switch.** The system's "never reads
payload" property is a selling point, so every feature declares what it reads:

| Level | Reads | Switch | Privacy property |
|---|---|---|---|
| **H — header** | IP/TCP/UDP/ICMP headers and payload *length* | on with v3 | ✅ kept |
| **M — protocol metadata** | DNS query names, TLS ClientHello fields (SNI, cipher list) — cleartext handshake metadata | `IPS_META_INSPECT=1` | ◐ partly given up (names of sites visited) |
| **C — content** | HTTP request line / URI | `IPS_CONTENT_INSPECT=1` | ❌ given up |

**1.3 Know which engine each attack belongs to.** Statistical features on flows can't see a
single malicious request. One `GET /item?id=1' OR '1'='1` is statistically identical to a
benign `GET`, so content attacks (SQLi, XSS, RCE payloads) are signature work for **Tier 1**
(Snort `http_inspect` plus the community rules), not feature work. Features *can* catch the
**behavioural** side of web attacks — brute force, directory enumeration, scanners, slow
denial-of-service — because those change volume, timing, and response-size patterns.

---

## 2. Coverage map — which blind spot, which group, which engine

| Blind spot | Group | Level | Engine that decides |
|---|---|---|---|
| Stealth scans (NULL / FIN / XMAS / ACK), UDP scans | G11 Recon technique | H | Rate counters + RF |
| Host sweeps (one port, many hosts), ping sweeps | G11 | H | Rate counters + RF |
| Low-and-slow scans (`nmap -T1`) | G13 Long-horizon memory | H | Rate counters on the 10-min/1-h window |
| IP spoofing, device impersonation, fragmentation evasion | G12 Header fingerprint | H | AE (deviation) + rate counters |
| C2 beaconing (periodic check-ins) | G13 | H | AE + RF |
| Slow DoS (Slowloris, slow POST) | G13 | H | Rate counters + RF |
| Web/SSH brute force, directory enumeration, scanners (nikto, gobuster) | G14 Service-behaviour | H | RF + AE |
| Data exfiltration (upload-heavy) | G14 | H | AE (device deviation) |
| DNS tunnelling, DGA malware, DNS-based C2 | G15 DNS metadata | M | RF + AE |
| Malware / unknown clients over TLS | G16 TLS metadata | M | AE (fingerprint novelty) |
| SQLi, XSS, path traversal, RCE payloads | — (signatures) | C | **Snort `http_inspect` + rules** |
| URI-level anomalies that complement the signatures | G17 HTTP lexical | C | AE |

---

## 3. The feature groups

Each row is one CSV column computed per flow (or per source) per 5 s window, unless stated
otherwise.

### G11 — Reconnaissance technique (level H, ~12 columns)
Needs URG/ECE/CWR flag parsing, plus correlating replies that come back to the source.

| Column | Computation | Catches |
|---|---|---|
| `null_flag_count` | TCP packets with no flags set | NULL scan (`nmap -sN`) |
| `xmas_flag_count` | FIN + PSH + URG together | XMAS scan (`-sX`) |
| `fin_only_count` | FIN without ACK | FIN scan (`-sF`) |
| `ack_no_session_count` | ACK with no SYN ever seen on that flow | ACK scan / firewall mapping (`-sA`) |
| `rst_reply_ratio` | RSTs coming back ÷ SYNs sent | Probing closed ports — scans "fail loudly" |
| `icmp_unreach_reply_count` | ICMP type 3 code 3 returned to the source | UDP scan (`-sU`) |
| `src_dst_ip_fanout` | Distinct destination IPs this source contacted on the same port | Horizontal sweep (one port, many hosts) |
| `src_dst_port_fanout` | Distinct (destination, port) pairs per source | Vertical vs. mixed scans |
| `icmp_echo_fanout` | Distinct hosts that received an echo request from this source | Ping sweep |
| `unanswered_probe_ratio` | (destination, port) pairs that got no reply ÷ pairs probed | Scanning, whatever the scan technique |
| `syn_options_uniform` | Share of SYNs with identical TCP option layouts | Tool-crafted SYNs (nmap and masscan use fixed option sets) |
| `probe_payload_zero_ratio` | Probe packets carrying no payload | Pure probing as opposed to real sessions |

### G12 — Header fingerprint and evasion (level H, ~9 columns)
| Column | Computation | Catches |
|---|---|---|
| `ttl_mean`, `ttl_std` | TTL statistics for the flow | Spoofed floods (TTLs vary); the OS family |
| `ttl_deviation_from_device` | Current TTL vs. the device's baseline TTL | **Impersonation** — a different OS behind a familiar IP or MAC |
| `tcp_window_mean`, `tcp_window_std` | TCP window sizes | Tool traffic (fixed windows); zero-window slow attacks |
| `zero_window_count` | Packets advertising window = 0 | Sockstress-type and slow-read attacks |
| `frag_count`, `tiny_frag_count` | IP fragments, and fragments under 64 bytes | Fragmentation evasion, Teardrop-family attacks |
| `ip_id_sequential_score` | How monotonic the IP ID field is | Idle/zombie scan, crafted traffic |

### G13 — Long-horizon memory (level H, ~8 columns)
The 5 s window is the system's biggest structural blind spot: anything slower than a window
looks innocent in every window. This group adds per-source and per-pair state that lasts
across windows, each piece with an explicit horizon.

| Column | Computation | Horizon | Catches |
|---|---|---|---|
| `src_distinct_dst_ports_10m` | Distinct destination ports, rolling | 10 min | Slow vertical scan |
| `src_distinct_dst_ips_1h` | Distinct destination IPs, rolling | 1 h | Slow sweep, worm spread |
| `pair_contact_count_1h` | Windows in which this (src, dst) pair talked | 1 h | Persistent check-ins |
| `pair_interval_cv` | Coefficient of variation of the intervals between contacts | 1 h | **Beaconing** (low CV = clockwork regular) |
| `pair_interval_mean` | Mean interval between contacts | 1 h | Beacon period |
| `long_open_conn_count` | TCP connections open > 60 s that move < 50 B/s | rolling | **Slowloris / slow POST** |
| `half_open_age_max` | Oldest unanswered SYN for this source | rolling | Slow SYN exhaustion |
| `src_bytes_out_1h` | Total upload, rolling | 1 h | Slow exfiltration |

Memory has to be bounded: cap the number of tracked pairs (LRU), age entries out by horizon,
and make the horizons tunable via `IPS_V3_HORIZONS`.

### G14 — Service-behaviour (level H, ~10 columns)
Computed only for flows to service ports: web (80, 443, 8080, 8443), auth (22, 23, 3389, 445,
21), and IoT management (1883, 8883, 554). Uses payload **length** only, never content.

| Column | Computation | Catches |
|---|---|---|
| `svc_class` | web / auth / iot-mgmt / other (one-hot) | Context for the model |
| `new_conn_rate` | New TCP sessions per second to that service | Brute force, scanners, HTTP floods |
| `short_session_ratio` | Sessions shorter than 2 s ÷ all sessions | Login failures, enumeration |
| `req_size_cv` | Coefficient of variation of client→server payload lengths | Scripted requests (identical sizes) |
| `resp_size_entropy` | Entropy of server→client response lengths | **Directory enumeration**: many "404"s with the same size → low entropy at high volume |
| `resp_size_mode_ratio` | Share of responses with the single most common size | Repeated failed logins (identical "wrong password" pages) |
| `bytes_up_down_ratio` | Client bytes ÷ server bytes | Upload-heavy exfiltration vs. normal downloads |
| `conn_reuse_ratio` | Requests per TCP session (keep-alive) | Browsers reuse connections; many tools don't |
| `auth_port_session_count` | Sessions to auth ports this window | SSH/RDP/Telnet brute force (Mirai-style) |
| `tls_fail_ratio` | TLS sessions closed before 1 KB of data | Failed handshakes, TLS scanners |

### G15 — DNS metadata (level M, ~8 columns)
| Column | Computation | Catches |
|---|---|---|
| `dns_query_rate` | Queries per second for this source | Tunnelling, DGA bursts |
| `dns_qname_len_mean` | Mean query-name length | Tunnelling (long encoded labels) |
| `dns_qname_entropy` | Character entropy of query names | **DGA domains** (random-looking names) |
| `dns_unique_domains` | Distinct registered domains | DGA churn |
| `dns_nxdomain_ratio` | NXDOMAIN answers ÷ queries | DGA (most generated names don't exist) |
| `dns_txt_null_ratio` | TXT/NULL record queries ÷ all | DNS tunnelling tools (iodine, dnscat2) |
| `dns_new_domain_ratio` | Domains never seen before for this device | Compromised IoT contacting new infrastructure |
| `dns_external_resolver` | 1 if the source bypasses the LAN resolver | Malware with a hardcoded DNS server |

### G16 — TLS handshake metadata (level M, ~6 columns)
| Column | Computation | Catches |
|---|---|---|
| `tls_version_min` | Lowest TLS version offered | Legacy or malware TLS stacks |
| `tls_sni_missing_ratio` | ClientHellos without SNI | Malware, raw-IP C2 |
| `tls_fp_new_for_device` | 1 if this client fingerprint (JA4-style hash of ClientHello fields) is new for the device | **A new piece of software** running on a known device |
| `tls_fp_rarity` | How rarely this fingerprint has been seen across the network | Unknown clients |
| `tls_cert_selfsigned` | Server certificate is self-signed (TLS 1.2 only; 1.3 encrypts certificates) | C2 servers, MITM proxies |
| `tls_sni_entropy` | Character entropy of the SNI | DGA over TLS |

### G17 — HTTP lexical (level C, opt-in, ~6 columns; cleartext HTTP only)
Complements the Snort signatures; it doesn't replace them.
`uri_len_mean`, `uri_entropy`, `uri_special_char_ratio` (`'"<>%;()`), `uri_encoded_ratio`
(`%xx` density), `http_method_rare_ratio` (methods other than GET/POST), `ua_new_for_device`.
These catch obfuscated payloads and scanners whose wording isn't in any signature yet.

---

## 4. Fix included in v3: `device_new_dst_ratio`

Today it computes `recent − (all − recent)`, which equals `recent`, so the ratio only ever
takes the values 0 and 1 (verified on 33,180 rows). In v3 it records whether a destination is
new *before* adding it to `all_dst_ips`. The fix ships with the schema bump on purpose: v3
data has to be collected and retrained anyway, so this is the one moment when changing what
a column means costs nothing extra.

---

## 5. Engines and labels

- **New attack classes for the RF.** Recon is split into sweep / stealth / slow, plus web
  brute force, directory enumeration, slow DoS, DNS tunnelling, and beaconing. A new class
  can't be detected by the RF until labelled examples exist.
- **AE.** It needs no labels — it learns the v3 normal and flags deviation. The architecture
  must grow, though: the input layer goes from 60 to ~110, so this is a full weight retrain,
  not just a threshold recalibration.
- **Rate counters (Tier 2).** Add rules for the features that are unambiguous on their own:
  stealth flag combinations, `unanswered_probe_ratio`, `src_distinct_dst_ports_10m`,
  `long_open_conn_count`. Deterministic rules are easier to explain and to audit than ML.
- **Snort.** Enable `http_inspect`, `ssl`, and `dns`, and load the community ruleset, behind
  the level C / M switches.

---

## 6. Validation set — your own lab, your own devices

Each group needs labelled captures from an authorized attacker box against your own targets.
Include a deliberately vulnerable web app as the web target (DVWA or OWASP Juice Shop in a
container), so nothing real is attacked.

| Group | Tools / scenarios |
|---|---|
| G11 | `nmap -sN/-sF/-sX/-sA/-sU`, `nmap -sn` sweep, `masscan` at a low rate |
| G12 | `hping3` with random source + random TTL, `nmap -f` (fragments), idle scan |
| G13 | `nmap -T1` over hours, a scripted beacon (`curl` every 60 s ± jitter), `slowhttptest` |
| G14 | `hydra` (SSH and HTTP form) against your own test credentials, `gobuster` / `nikto` against DVWA |
| G15 | `iodine` / `dnscat2` between two lab hosts, a DGA-name generator script |
| G16 | A self-signed test server, unusual clients (`openssl s_client` with old versions) |

**Score every group the same way:** detection rate per class, false positives at rest on
real home traffic, and time to detect. Then **ablate**: drop the group and retrain. If the
detection rate doesn't move, the group isn't earning its CPU cost.

---

## 7. Cost on the t530

- **H-level fields come almost free**, because Ryu already parses the IP and TCP headers.
- **G13 memory** is the real cost. It's bounded by the LRU cap; measure RAM over 24 h.
- **M/C parsing** (DNS, TLS, HTTP) runs per packet in Python, so expect a visible throughput
  drop. Measure it with the Phase 2 completeness test in
  [`home_network_test_plan.md`](home_network_test_plan.md) before and after.

## 8. Build order (value per effort)

1. **G11 + G12 + the bug fix.** Header-only, cheap, and the biggest recon gain.
2. **G13.** Closes the 5-second-window blind spot (slow scans, beaconing, slow DoS).
3. **G14.** Behavioural web and auth attacks with no payload.
4. **Snort `http_inspect` + community rules.** Content attacks via signatures.
5. **G15 → G16 → G17**, each behind its privacy switch and each validated before the next.

## 9. Why this serves the firewall-audit goal

An auditor needs a measured answer to "what got through?" The new groups provide it:

- **G11** shows which ports and hosts were *reachable* from where — measured exposure,
  compared against what the firewall rule base claims.
- **G13 / G14 / G15** show behaviour that the firewall **permitted**: beacons, brute force,
  tunnelling. That's direct evidence of policy gaps, beyond what reading the configuration
  alone can show.
- **G16** fingerprints tell you which software is talking out, which App-ID-style rules
  assume but rarely verify.
