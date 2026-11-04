"""Bounded packet summaries for site-v3 collection. All observations are unverified."""

from collections import Counter, OrderedDict, deque
from dataclasses import dataclass, field
import hashlib
import math
import re
import statistics
import struct

from scapy.layers.dns import DNS
from scapy.layers.inet import ICMP, IP, TCP, UDP
from scapy.layers.inet6 import IPv6, IPv6ExtHdrFragment
from scapy.layers.l2 import ARP, Dot1Q, Ether


SCHEMA_VERSION = "site-v3.0"
CARDINALITY_LIMIT = 128


def entropy(values):
    counts = Counter(values)
    total = sum(counts.values())
    return -sum((n / total) * math.log2(n / total) for n in counts.values()) if total else 0.0


@dataclass
class Moments:
    count: int = 0
    mean: float = 0.0
    m2: float = 0.0

    def add(self, value):
        self.count += 1
        delta = value - self.mean
        self.mean += delta / self.count
        self.m2 += delta * (value - self.mean)

    def summary(self):
        std = math.sqrt(max(0, self.m2 / (self.count - 1))) if self.count > 1 else None
        return self.mean if self.count else None, std


def bounded_add(values, value, health):
    if value in values:
        return
    if len(values) >= CARDINALITY_LIMIT:
        health["cardinality_overflows"] += 1
        return
    values.add(value)


def client_hello(payload):
    """Parse a complete ClientHello contained in the first TCP segment only."""
    if len(payload) < 9 or payload[0] != 22 or payload[5] != 1:
        return None
    record_length = int.from_bytes(payload[3:5], "big")
    hello_length = int.from_bytes(payload[6:9], "big")
    if record_length > len(payload) - 5 or hello_length > record_length - 4:
        raise ValueError("incomplete TLS record")
    data = payload[9:9 + hello_length]
    if len(data) < 35:
        raise ValueError("short ClientHello")
    position = 34

    def vector(width):
        nonlocal position
        if position + width > len(data):
            raise ValueError("short TLS vector length")
        length = int.from_bytes(data[position:position + width], "big")
        position += width
        value = data[position:position + length]
        if len(value) != length:
            raise ValueError("short TLS vector")
        position += length
        return value

    vector(1)  # Session ID
    ciphers = vector(2)
    if len(ciphers) % 2:
        raise ValueError("odd cipher list")
    vector(1)  # Compression methods
    extensions = vector(2) if position < len(data) else b""
    names = []
    extension_ids = []
    cursor = 0
    while cursor < len(extensions):
        if cursor + 4 > len(extensions):
            raise ValueError("short TLS extension")
        kind, length = struct.unpack("!HH", extensions[cursor:cursor + 4])
        cursor += 4
        value = extensions[cursor:cursor + length]
        if len(value) != length:
            raise ValueError("short TLS extension body")
        cursor += length
        extension_ids.append(kind)
        if kind == 0:
            if len(value) < 2 or int.from_bytes(value[:2], "big") != len(value) - 2:
                raise ValueError("invalid SNI list")
            offset = 2
            while offset < len(value):
                if offset + 3 > len(value):
                    raise ValueError("short SNI")
                size = int.from_bytes(value[offset + 1:offset + 3], "big")
                name = value[offset + 3:offset + 3 + size]
                if len(name) != size:
                    raise ValueError("short SNI name")
                if value[offset] == 0:
                    names.append(name)
                offset += 3 + size
    fingerprint = hashlib.sha256(data[:2] + ciphers + repr(extension_ids).encode()).hexdigest()[:24]
    return dict(fingerprint=fingerprint, sni_entropy=entropy(b"".join(names)),
                sni_present=bool(names), ech=65037 in extension_ids)


def decode(frame, metadata=False, content=False):
    """Return normalized outer Ethernet/IP evidence without retaining payloads."""
    if not isinstance(frame, Ether):
        return None
    layer = frame.payload
    vlans = []
    while isinstance(layer, Dot1Q):
        vlans.append(int(layer.vlan))
        layer = layer.payload
    packet = dict(timestamp=float(frame.time), size=len(frame), mac=frame.src,
                  vlan=".".join(map(str, vlans)) or "untagged", protocol="OTHER",
                  sport=0, dport=0, flags=None, ttl=None, tcp_window=None,
                  fragment=False, payload_length=0, dns=None, tls=None, http=None)
    if isinstance(layer, ARP):
        packet.update(src=layer.psrc, dst=layer.pdst, protocol="ARP")
        return packet
    if isinstance(layer, IP):
        packet.update(src=layer.src, dst=layer.dst, ttl=int(layer.ttl),
                      fragment=bool(layer.frag or layer.flags.MF))
    elif isinstance(layer, IPv6):
        packet.update(src=layer.src, dst=layer.dst, ttl=int(layer.hlim),
                      fragment=frame.haslayer(IPv6ExtHdrFragment))
    else:
        return None
    declared_length = layer.len if isinstance(layer, IP) else 40 + layer.plen if layer.plen is not None else None
    packet["capture_truncated"] = declared_length is not None and len(bytes(layer)) < declared_length
    if isinstance(layer, IPv6) and layer.plen == 0 and len(bytes(layer)) > 40:
        packet["unsupported_jumbogram"] = True
        return packet
    transport = layer.payload
    # Walk IPv6 extension headers, without interpreting a quoted inner IP as outer traffic.
    for _ in range(8):
        if not isinstance(layer, IPv6) or not transport.__class__.__name__.startswith("IPv6ExtHdr"):
            break
        transport = transport.payload
    if packet["fragment"]:
        return packet
    if isinstance(transport, (TCP, UDP)):
        captured_transport = len(bytes(transport))
        network_size = (layer.len if isinstance(layer, IP) else
                        40 + layer.plen if layer.plen is not None else None)
        if network_size is None:
            network_size = len(bytes(layer))
        transport_offset = len(bytes(layer)) - captured_transport
        declared_transport = max(0, network_size - transport_offset)
        header_size = (int(transport.dataofs or 5) * 4 if isinstance(transport, TCP) else 8)
        if isinstance(transport, UDP) and transport.len is not None:
            declared_transport = min(declared_transport, int(transport.len))
        payload = bytes(transport.payload)[:max(0, min(captured_transport, declared_transport) - header_size)]
        packet.update(protocol="TCP" if isinstance(transport, TCP) else "UDP",
                      sport=int(transport.sport), dport=int(transport.dport),
                      payload_length=len(payload))
    elif isinstance(transport, ICMP):
        packet.update(protocol="ICMP", icmp_type=int(transport.type), icmp_code=int(transport.code))
    elif transport.__class__.__name__.startswith("ICMPv6"):
        packet.update(protocol="ICMPv6", icmp_type=int(transport.type), icmp_code=int(transport.code))
    if isinstance(transport, TCP):
        packet.update(flags=int(transport.flags), tcp_window=int(transport.window))
    if metadata and isinstance(transport, UDP) and (packet["sport"] == 53 or packet["dport"] == 53):
        try:
            dns = DNS(payload)
            if dns.qdcount != 1 or not dns.qd:
                raise ValueError("unsupported DNS question count")
            qname = bytes(dns.qd[0].qname).rstrip(b".")
            packet["dns"] = dict(query=not bool(dns.qr), nxdomain=int(dns.rcode) == 3,
                                 name_hash=hashlib.sha256(qname.lower()).hexdigest()[:24],
                                 length=len(qname), entropy=entropy(qname),
                                 txt_null=int(dns.qd[0].qtype) in (10, 16))
        except (ValueError, IndexError, AttributeError, struct.error):
            packet["dns_error"] = True
    if metadata and isinstance(transport, TCP):
        payload = payload[:65535]
        try:
            packet["tls"] = client_hello(payload)
        except ValueError:
            packet["tls_error"] = True
    if content and isinstance(transport, TCP):
        payload = payload[:8192]
        if re.match(rb"[A-Z]{3,12} ", payload):
            if b"\r\n\r\n" not in payload:
                packet["http_error"] = True
            else:
                request = payload.split(b"\r\n", 1)[0].split(b" ")
                if len(request) == 3 and request[2].startswith(b"HTTP/1."):
                    method, uri, _ = request
                    packet["http"] = dict(length=len(uri), entropy=entropy(uri),
                        encoded_ratio=len(re.findall(rb"%[0-9a-fA-F]{2}", uri)) / max(1, len(uri)),
                        special_ratio=sum(c in b"'\"<>%;()" for c in uri) / max(1, len(uri)),
                        rare=method not in (b"GET", b"POST"))
    return packet


@dataclass
class DeviceWindow:
    out_packets: int = 0
    in_packets: int = 0
    out_bytes: int = 0
    in_bytes: int = 0
    payload_bytes: int = 0
    syn: int = 0
    null: int = 0
    xmas: int = 0
    fin: int = 0
    resets_in: int = 0
    unreach_in: int = 0
    zero_window: int = 0
    fragments: int = 0
    tiny_fragments: int = 0
    auth_syn: int = 0
    peers: set = field(default_factory=set)
    ports: set = field(default_factory=set)
    edges: set = field(default_factory=set)
    # Shadow policy checks connection initiations, never TCP response destinations.
    tcp_initiations: set = field(default_factory=set)
    macs: set = field(default_factory=set)
    dns_names: set = field(default_factory=set)
    fingerprints: set = field(default_factory=set)
    ttl: Moments = field(default_factory=Moments)
    tcp_window: Moments = field(default_factory=Moments)
    sizes: Moments = field(default_factory=Moments)
    intervals: Moments = field(default_factory=Moments)
    dns_lengths: Moments = field(default_factory=Moments)
    dns_entropy: Moments = field(default_factory=Moments)
    uri_lengths: Moments = field(default_factory=Moments)
    uri_entropy: Moments = field(default_factory=Moments)
    encoded: Moments = field(default_factory=Moments)
    special: Moments = field(default_factory=Moments)
    counts: Counter = field(default_factory=Counter)
    last_out: float = None

    def observe(self, packet, outbound, health):
        if not outbound:
            self.in_packets += 1
            self.in_bytes += packet["size"]
            self.resets_in += bool((packet["flags"] or 0) & 4)
            self.unreach_in += packet.get("icmp_type") == 3 and packet.get("icmp_code") == 3
        else:
            self.out_packets += 1
            self.out_bytes += packet["size"]
            self.payload_bytes += packet["payload_length"]
            self.sizes.add(packet["size"])
            if self.last_out is not None and packet["timestamp"] < self.last_out:
                health["timestamp_reorders"] += 1
            elif self.last_out is not None:
                self.intervals.add(max(0, packet["timestamp"] - self.last_out))
            self.last_out = max(self.last_out or packet["timestamp"], packet["timestamp"])
            bounded_add(self.peers, packet["dst"], health)
            bounded_add(self.edges, (packet["dst"], packet["dport"], packet["protocol"]), health)
            bounded_add(self.macs, packet["mac"], health)
            if packet["dport"]:
                bounded_add(self.ports, packet["dport"], health)
            if packet["ttl"] is not None:
                self.ttl.add(packet["ttl"])
            if packet["tcp_window"] is not None:
                self.tcp_window.add(packet["tcp_window"])
                flags = packet["flags"]
                self.syn += bool(flags & 2 and not flags & 16)
                if flags & 2 and not flags & 16:
                    bounded_add(self.tcp_initiations,
                                (packet["dst"], packet["dport"], packet["protocol"]), health)
                self.null += flags == 0
                self.xmas += flags & 41 == 41
                self.fin += bool(flags & 1 and not flags & 16)
                self.zero_window += packet["tcp_window"] == 0
                self.auth_syn += bool(flags & 2 and not flags & 16 and packet["dport"] in (21, 22, 23, 445, 3389))
            self.fragments += bool(packet["fragment"])
            self.tiny_fragments += bool(packet["fragment"] and packet["size"] < 64)
        dns = packet["dns"]
        if dns:
            if outbound and dns["query"]:
                self.counts["dns_queries"] += 1
                self.counts["dns_txt_null"] += dns["txt_null"]
                self.dns_lengths.add(dns["length"])
                self.dns_entropy.add(dns["entropy"])
                bounded_add(self.dns_names, dns["name_hash"], health)
            elif not outbound and not dns["query"]:
                self.counts["dns_responses"] += 1
                self.counts["dns_nxdomain"] += dns["nxdomain"]
        tls = packet["tls"]
        if outbound and tls:
            self.counts["tls_hellos"] += 1
            self.counts["tls_no_sni"] += not tls["sni_present"]
            self.counts["tls_ech"] += tls["ech"]
            bounded_add(self.fingerprints, tls["fingerprint"], health)
        http = packet["http"]
        if outbound and http:
            self.counts["http_requests"] += 1
            self.counts["http_rare"] += http["rare"]
            self.uri_lengths.add(http["length"])
            self.uri_entropy.add(http["entropy"])
            self.encoded.add(http["encoded_ratio"])
            self.special.add(http["special_ratio"])


class FeatureHistory:
    def __init__(self, max_sources=128):
        self.max_sources = max_sources
        self.sources = OrderedDict()
        self.buckets = OrderedDict()
        self.contacts = OrderedDict()

    def features(self, key, window, timestamp, duration, health):
        if key not in self.sources:
            if len(self.sources) >= self.max_sources:
                evicted, _ = self.sources.popitem(last=False)
                self.buckets.pop(evicted, None)
                self.contacts.pop(evicted, None)
                health["history_evictions"] += 1
            self.sources[key] = {"peers": [], "ttl_mean": None, "windows": 0}
        self.sources.move_to_end(key)
        profile = self.sources[key]
        pairs = self.contacts.setdefault(key, OrderedDict())
        for peer in sorted(window.peers):
            if peer not in pairs:
                if len(pairs) >= 32:
                    pairs.popitem(last=False)
                    health["pair_history_evictions"] += 1
                pairs[peer] = deque(maxlen=64)
            pairs.move_to_end(peer)
            pairs[peer].append(timestamp)
        cvs = []
        for contacts in pairs.values():
            while contacts and contacts[0] <= timestamp - 3600:
                contacts.popleft()
            intervals = [b - a for a, b in zip(contacts, list(contacts)[1:])]
            if len(intervals) >= 3 and statistics.mean(intervals) > 0:
                cvs.append(statistics.stdev(intervals) / statistics.mean(intervals))
        old_peers = set(profile["peers"])
        novelty = len(window.peers - old_peers) / len(window.peers) if window.peers else None
        minutes = self.buckets.setdefault(key, OrderedDict())
        for minute in list(minutes):
            if minute <= int(timestamp // 60) - 60:
                del minutes[minute]
        bucket = minutes.setdefault(int(timestamp // 60), {"peers": set(), "ports": set(), "bytes": 0, "windows": 0})
        bucket["bytes"] += window.out_bytes
        bucket["windows"] += 1
        for peer in window.peers:
            bounded_add(bucket["peers"], peer, health)
        for port in window.ports:
            bounded_add(bucket["ports"], port, health)
        peers_hour = set().union(*(b["peers"] for b in minutes.values()))
        ports_10m = set().union(*(b["ports"] for m, b in minutes.items() if m > int(timestamp // 60) - 10))
        ttl_mean, ttl_std = window.ttl.summary()
        window_mean, window_std = window.tcp_window.summary()
        size_mean, size_std = window.sizes.summary()
        iat_mean, iat_std = window.intervals.summary()
        result = dict(out_packets=window.out_packets, in_packets=window.in_packets,
            out_bytes=window.out_bytes, in_bytes=window.in_bytes,
            out_pps=window.out_packets / duration, out_bytes_per_second=window.out_bytes / duration,
            packet_size_mean=size_mean, packet_size_std=size_std,
            inter_arrival_mean=iat_mean, inter_arrival_std=iat_std,
            inter_arrival_cv=iat_std / iat_mean if iat_std is not None and iat_mean else None,
            device_new_dst_ratio=novelty, device_macs_observed=len(window.macs),
            profile_windows_before=profile["windows"],
            g11_null_flag_count=window.null, g11_xmas_flag_count=window.xmas,
            g11_fin_no_ack_count=window.fin, g11_syn_count=window.syn,
            g11_rst_in_count=window.resets_in, g11_icmp_port_unreachable_in=window.unreach_in,
            g11_dst_ip_count=len(window.peers), g11_dst_port_count=len(window.ports),
            g11_service_edge_count=len(window.edges),
            g12_ttl_mean=ttl_mean, g12_ttl_std=ttl_std,
            g12_ttl_residual=ttl_mean - profile["ttl_mean"] if ttl_mean is not None and profile["ttl_mean"] is not None else None,
            g12_tcp_window_mean=window_mean, g12_tcp_window_std=window_std,
            g12_zero_window_count=window.zero_window, g12_fragment_count=window.fragments,
            g12_tiny_fragment_count=window.tiny_fragments,
            g13_dst_ips_hour_bucketed=len(peers_hour), g13_dst_ports_10m_bucketed=len(ports_10m),
            g13_out_bytes_hour_bucketed=sum(b["bytes"] for b in minutes.values()),
            g13_window_contacts_hour_bucketed=sum(b["windows"] for b in minutes.values()),
            g13_pair_interval_cv_mean=statistics.mean(cvs) if cvs else None,
            g13_pair_interval_supported_pairs=len(cvs),
            g14_new_syn_rate=window.syn / duration, g14_auth_syn_count=window.auth_syn,
            g14_out_in_bytes_ratio=window.out_bytes / window.in_bytes if window.in_bytes else None,
            g14_out_payload_bytes=window.payload_bytes,
            g15_query_count=window.counts["dns_queries"], g15_response_count=window.counts["dns_responses"],
            g15_nxdomain_response_ratio=window.counts["dns_nxdomain"] / window.counts["dns_responses"] if window.counts["dns_responses"] else None,
            g15_qname_length_mean=window.dns_lengths.summary()[0], g15_qname_entropy_mean=window.dns_entropy.summary()[0],
            g15_distinct_qname_hashes=len(window.dns_names), g15_txt_null_query_count=window.counts["dns_txt_null"],
            g16_complete_clienthello_count=window.counts["tls_hellos"],
            g16_no_sni_count=window.counts["tls_no_sni"], g16_ech_count=window.counts["tls_ech"],
            g16_distinct_custom_fingerprints=len(window.fingerprints),
            g17_complete_http_requests=window.counts["http_requests"],
            g17_rare_method_count=window.counts["http_rare"],
            g17_uri_length_mean=window.uri_lengths.summary()[0],
            g17_uri_entropy_mean=window.uri_entropy.summary()[0],
            g17_uri_encoded_ratio_mean=window.encoded.summary()[0],
            g17_uri_special_ratio_mean=window.special.summary()[0])
        # Update empirical history only after computing the current features.
        for peer in sorted(window.peers):
            if peer not in profile["peers"]:
                profile["peers"].append(peer)
        if len(profile["peers"]) > 1024:
            health["destination_history_evictions"] += len(profile["peers"]) - 1024
            profile["peers"] = profile["peers"][-1024:]
        if ttl_mean is not None:
            profile["ttl_mean"] = ttl_mean if profile["ttl_mean"] is None else .9 * profile["ttl_mean"] + .1 * ttl_mean
        profile["windows"] += 1
        return result
