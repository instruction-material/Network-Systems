"""Keep passive countdowns separate from actual host configuration changes."""
import copy
import importlib.util
import json
from pathlib import Path
import unittest

ROOT = Path(__file__).resolve().parents[1]
spec = importlib.util.spec_from_file_location("firewall_runtime_under_test",
    ROOT / "NS3-UFW-Web-Server-Policy/solution/firewall_runtime.py")
runtime = importlib.util.module_from_spec(spec)
spec.loader.exec_module(runtime)

class AddressConfigurationTests(unittest.TestCase):
    def setUp(self):
        self.rows = [{"ifname": "owned0", "flags": ["UP"], "addr_info": [{
            "family": "inet", "local": "192.0.2.4", "prefixlen": 24, "scope": "global",
            "dynamic": True, "valid_life_time": 800, "preferred_life_time": 800}]}]

    def normalized(self, rows):
        return runtime.address_configuration(json.dumps(rows))

    def test_passive_countdown_preserves_raw_input(self):
        raw = json.dumps(self.rows)
        changed = copy.deepcopy(self.rows)
        changed[0]["addr_info"][0]["valid_life_time"] -= 3
        changed[0]["addr_info"][0]["preferred_life_time"] -= 3
        self.assertEqual(self.normalized(self.rows), self.normalized(changed))
        self.assertEqual(json.dumps(self.rows), raw)

    def test_actual_properties_still_differ(self):
        for field, value in [("local", "192.0.2.5"), ("prefixlen", 25),
                             ("scope", "link"), ("family", "inet6"), ("dynamic", False)]:
            changed = copy.deepcopy(self.rows)
            changed[0]["addr_info"][0][field] = value
            with self.subTest(field=field):
                self.assertNotEqual(self.normalized(self.rows), self.normalized(changed))
        changed = copy.deepcopy(self.rows)
        changed[0]["ifname"] = "other0"
        self.assertNotEqual(self.normalized(self.rows), self.normalized(changed))

    def test_lifetime_classes_remain_distinct(self):
        values = []
        for seconds in [30, 0, 4294967295]:
            changed = copy.deepcopy(self.rows)
            changed[0]["addr_info"][0]["preferred_life_time"] = seconds
            values.append(self.normalized(changed))
        self.assertEqual(len(set(values)), 3)

    def test_unrecognized_lifetime_refused(self):
        for seconds in [-1, "unknown", 0.5, None, False, True]:
            changed = copy.deepcopy(self.rows)
            changed[0]["addr_info"][0]["valid_life_time"] = seconds
            with self.subTest(seconds=seconds):
                with self.assertRaises(ValueError):
                    self.normalized(changed)

if __name__ == "__main__":
    unittest.main()
