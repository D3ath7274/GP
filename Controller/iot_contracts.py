"""
IoT Behavioral Contracts — Device-Class Policy Enforcement
============================================================
Defines per-device-class behavioral constraints and enforces them
at the flow level. Any violation triggers automatic quarantine via
the controller's block_attacker() method.

Device classes are mapped from the IoT registration system:
  REGISTER:IOT:IOT:TempSensor → class "temperature_sensor"
  REGISTER:IOT:IOT:Cam        → class "camera"

Violation Types:
  - UNAUTHORIZED_PROTOCOL: Flow uses a protocol not in the allowed list
  - UNAUTHORIZED_PORT: Flow targets a port not in the allowed list
  - EXCESSIVE_PORTS: Too many unique destination ports in one window
  - EXCESSIVE_DESTINATIONS: Too many unique destination IPs in one window
"""

import time
from datetime import datetime


# =============================================================================
# Behavioral Contract Definitions
# =============================================================================

IOT_CONTRACTS = {
    "camera": {
        "allowed_protocols": ["TCP", "UDP", "ICMP"],
        "allowed_dst_ports": [80, 443, 554, 8080, 8554, 8883, 1883],
        "max_unique_dst_ports_per_window": 5,
        "max_dst_ips_per_window": 3,
        "description": "IP camera — streams video over RTSP/HTTP, MQTT telemetry",
    },
    "temperature_sensor": {
        "allowed_protocols": ["TCP", "UDP"],
        "allowed_dst_ports": [1883, 8883, 443, 5683, 80],
        "max_unique_dst_ports_per_window": 3,
        "max_dst_ips_per_window": 2,
        "description": "Temperature sensor — MQTT/CoAP telemetry only",
    },
    "smart_plug": {
        "allowed_protocols": ["TCP", "UDP"],
        "allowed_dst_ports": [80, 443, 1883, 8883, 9999],
        "max_unique_dst_ports_per_window": 4,
        "max_dst_ips_per_window": 2,
        "description": "Smart plug — cloud control and MQTT",
    },
    "door_lock": {
        "allowed_protocols": ["TCP"],
        "allowed_dst_ports": [443, 8883],
        "max_unique_dst_ports_per_window": 2,
        "max_dst_ips_per_window": 1,
        "description": "Smart door lock — TLS-only cloud communication",
    },
    "motion_sensor": {
        "allowed_protocols": ["TCP", "UDP"],
        "allowed_dst_ports": [1883, 8883, 443, 5683],
        "max_unique_dst_ports_per_window": 3,
        "max_dst_ips_per_window": 2,
        "description": "Motion sensor — MQTT/CoAP events",
    },
    "generic_iot": {
        "allowed_protocols": ["TCP", "UDP", "ICMP"],
        "allowed_dst_ports": [80, 443, 1883, 8883, 5683, 8080],
        "max_unique_dst_ports_per_window": 6,
        "max_dst_ips_per_window": 4,
        "description": "Generic IoT — permissive baseline for unknown types",
    },
}

# Map device registration names to contract classes
DEVICE_NAME_TO_CLASS = {
    'cam': 'camera',
    'camera': 'camera',
    'ipcam': 'camera',
    'tempsensor': 'temperature_sensor',
    'temp': 'temperature_sensor',
    'temperature': 'temperature_sensor',
    'smartplug': 'smart_plug',
    'plug': 'smart_plug',
    'doorlock': 'door_lock',
    'lock': 'door_lock',
    'motion': 'motion_sensor',
    'motionsensor': 'motion_sensor',
}


# =============================================================================
# Contract Violation
# =============================================================================

class ContractViolation:
    """Represents a single behavioral contract violation."""

    def __init__(self, device_ip, device_name, device_class,
                 violation_type, details, flow_key=None):
        self.timestamp = datetime.now().isoformat()
        self.device_ip = device_ip
        self.device_name = device_name
        self.device_class = device_class
        self.violation_type = violation_type
        self.details = details
        self.flow_key = flow_key

    def to_dict(self):
        return {
            'timestamp': self.timestamp,
            'device_ip': self.device_ip,
            'device_name': self.device_name,
            'device_class': self.device_class,
            'violation_type': self.violation_type,
            'details': self.details,
        }

    def __repr__(self):
        return (f"ContractViolation({self.device_ip}, {self.violation_type}: "
                f"{self.details})")


# =============================================================================
# Contract Checking
# =============================================================================

def get_device_class(device_name):
    """
    Map a device registration name to a contract class.
    Returns 'generic_iot' if the name is not recognized.
    """
    if not device_name:
        return None

    name_lower = device_name.lower().replace('_', '').replace('-', '').replace(' ', '')
    return DEVICE_NAME_TO_CLASS.get(name_lower, 'generic_iot')


def check_contract(device_ip, device_name, device_class, flow_features):
    """
    Check a single flow against the device's behavioral contract.

    Args:
        device_ip: The device's IP address.
        device_name: Human-readable device name.
        device_class: Contract class (e.g., 'camera', 'temperature_sensor').
        flow_features: Dict of flow features from the current row.

    Returns:
        List of ContractViolation objects (empty if no violations).
    """
    if device_class not in IOT_CONTRACTS:
        return []

    contract = IOT_CONTRACTS[device_class]
    violations = []

    # Check 1: Protocol
    protocol = flow_features.get('protocol', '')
    if protocol and protocol not in contract['allowed_protocols']:
        violations.append(ContractViolation(
            device_ip, device_name, device_class,
            'UNAUTHORIZED_PROTOCOL',
            f"Protocol '{protocol}' not in allowed list: {contract['allowed_protocols']}"
        ))

    # Check 2: Destination port
    dst_port = flow_features.get('dst_port', 0)
    if dst_port and dst_port not in contract['allowed_dst_ports']:
        # Only flag well-known ports (< 49152) — ephemeral ports are normal
        if dst_port < 49152:
            violations.append(ContractViolation(
                device_ip, device_name, device_class,
                'UNAUTHORIZED_PORT',
                f"Destination port {dst_port} not in allowed list: {contract['allowed_dst_ports']}"
            ))

    # Check 3: Port diversity (per-window)
    unique_ports = flow_features.get('device_unique_dst_ports', 0)
    max_ports = contract['max_unique_dst_ports_per_window']
    if unique_ports > max_ports:
        violations.append(ContractViolation(
            device_ip, device_name, device_class,
            'EXCESSIVE_PORTS',
            f"{unique_ports} unique dst ports (max allowed: {max_ports})"
        ))

    # Check 4: Destination diversity (per-window)
    unique_dsts = flow_features.get('device_unique_dst_ips', 0)
    max_dsts = contract['max_dst_ips_per_window']
    if unique_dsts > max_dsts:
        violations.append(ContractViolation(
            device_ip, device_name, device_class,
            'EXCESSIVE_DESTINATIONS',
            f"{unique_dsts} unique dst IPs (max allowed: {max_dsts})"
        ))

    return violations


def check_contracts_for_window(iot_device_map, flow_rows, discovered_names=None):
    """
    Check behavioral contracts for all IoT devices in a window.

    Args:
        iot_device_map: Dict of {mac: device_type} from the controller.
        flow_rows: List of flow feature dicts from _flush_flows().
        discovered_names: Dict of {ip: name} from controller._discovered_names.

    Returns:
        List of ContractViolation objects for the entire window.
    """
    all_violations = []
    if not iot_device_map:
        return all_violations

    # Build IP → device class mapping from discovered names
    ip_to_class = {}
    ip_to_name = {}
    if discovered_names:
        for ip, name in discovered_names.items():
            device_class = get_device_class(name)
            if device_class:
                ip_to_class[ip] = device_class
                ip_to_name[ip] = name

    # Check each flow from an IoT device
    for row in flow_rows:
        src_ip = row.get('src_ip', '')
        if src_ip in ip_to_class:
            violations = check_contract(
                src_ip,
                ip_to_name.get(src_ip, 'unknown'),
                ip_to_class[src_ip],
                row
            )
            all_violations.extend(violations)

    return all_violations


# =============================================================================
# Self-Test
# =============================================================================

if __name__ == '__main__':
    print("=" * 60)
    print("  IoT Behavioral Contracts — Self-Test")
    print("=" * 60)

    # Test 1: Camera sending SSH (port 22) — should violate
    violations = check_contract(
        '10.0.0.6', 'Cam', 'camera',
        {'protocol': 'TCP', 'dst_port': 22,
         'device_unique_dst_ports': 2, 'device_unique_dst_ips': 1}
    )
    assert len(violations) == 1
    assert violations[0].violation_type == 'UNAUTHORIZED_PORT'
    print(f"\n  Camera SSH test: {violations[0]} ✅")

    # Test 2: TempSensor normal MQTT — no violation
    violations2 = check_contract(
        '10.0.0.5', 'TempSensor', 'temperature_sensor',
        {'protocol': 'TCP', 'dst_port': 1883,
         'device_unique_dst_ports': 1, 'device_unique_dst_ips': 1}
    )
    assert len(violations2) == 0
    print(f"  TempSensor MQTT test: no violations ✅")

    # Test 3: TempSensor scanning (many ports) — should violate
    violations3 = check_contract(
        '10.0.0.5', 'TempSensor', 'temperature_sensor',
        {'protocol': 'TCP', 'dst_port': 80,
         'device_unique_dst_ports': 10, 'device_unique_dst_ips': 5}
    )
    assert len(violations3) == 2  # EXCESSIVE_PORTS + EXCESSIVE_DESTINATIONS
    print(f"  TempSensor scanning test: {len(violations3)} violations ✅")

    # Test 4: Device name mapping
    assert get_device_class('TempSensor') == 'temperature_sensor'
    assert get_device_class('Cam') == 'camera'
    assert get_device_class('unknown_device') == 'generic_iot'
    assert get_device_class(None) is None
    print(f"  Device class mapping: ✅")

    # Test 5: Window-level check
    rows = [
        {'src_ip': '10.0.0.5', 'protocol': 'TCP', 'dst_port': 22,
         'device_unique_dst_ports': 1, 'device_unique_dst_ips': 1},
        {'src_ip': '10.0.0.3', 'protocol': 'TCP', 'dst_port': 80,
         'device_unique_dst_ports': 1, 'device_unique_dst_ips': 1},
    ]
    window_violations = check_contracts_for_window(
        {}, rows, discovered_names={'10.0.0.5': 'TempSensor'}
    )
    assert len(window_violations) == 1  # Only TempSensor SSH violation
    print(f"  Window-level check: {len(window_violations)} violation(s) ✅")

    print(f"\n  All tests passed ✅")
    print("=" * 60)
