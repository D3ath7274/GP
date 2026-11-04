import ipaddress
from pathlib import Path
import sys
import unittest
from unittest.mock import patch

sys.path.insert(0, str(Path(__file__).resolve().parents[1] / "Controller"))
import nft_quarantine as quarantine


class QuarantineTests(unittest.TestCase):
    scope = ipaddress.IPv4Network("192.0.2.0/24")
    protected = [ipaddress.IPv4Network("192.0.2.1/32")]

    def test_add_and_verify(self):
        with patch.object(quarantine, "read_set", side_effect=[
            {}, {"elem": [{"elem": {"val": "192.0.2.10", "expires": 20}}]}
        ]), patch.object(quarantine, "nft") as call:
            result = quarantine.change("add", "192.0.2.10", self.scope, self.protected, 30)
            self.assertTrue(result["set_member"])
            self.assertIn("30s", call.call_args.args)

    def test_protected_and_out_of_scope(self):
        with patch.object(quarantine, "nft") as call:
            for address in ("192.0.2.1", "198.51.100.10"):
                with self.assertRaises(ValueError):
                    quarantine.change("add", address, self.scope, self.protected)
            call.assert_not_called()

    def test_remove_only_owned_element(self):
        with patch.object(quarantine, "read_set", side_effect=[
            {"elem": ["192.0.2.10"]}, {}
        ]), patch.object(quarantine, "nft") as call:
            self.assertFalse(quarantine.change("remove", "192.0.2.10")["set_member"])
            call.assert_called_once_with("delete", "element", "inet",
                                         quarantine.TABLE, quarantine.SET,
                                         "{", "192.0.2.10", "}")

    def test_failed_readback_is_not_success(self):
        with patch.object(quarantine, "read_set", return_value={}), patch.object(quarantine, "nft"):
            with self.assertRaisesRegex(ValueError, "Read-back"):
                quarantine.change("add", "192.0.2.10", self.scope, self.protected)

    def test_existing_entry_does_not_extend_ttl(self):
        with patch.object(quarantine, "read_set", return_value={
            "elem": ["192.0.2.10"]
        }), patch.object(quarantine, "nft") as call:
            self.assertFalse(quarantine.change("add", "192.0.2.10", self.scope)["changed"])
            call.assert_not_called()
