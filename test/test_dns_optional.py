import importlib.util
from pathlib import Path
import unittest

ROOT = Path(__file__).resolve().parents[1]
PACKS = ["NS-11-unit-5-dns-and-name-resolution-supplemental-2",
         "NS-12-unit-5-dns-and-name-resolution-supplemental-3"]

class DNSResultTests(unittest.TestCase):
    def setUp(self):
        location = ROOT / PACKS[0] / "starter/dns_probe.py"
        spec = importlib.util.spec_from_file_location("probe", location)
        self.probe = importlib.util.module_from_spec(spec)
        spec.loader.exec_module(self.probe)

    def test_typed_alias_and_address_records(self):
        text = (";; ->>HEADER<<- opcode: QUERY, status: NOERROR, id: 51\n"
                "alias.course.test. 0 IN CNAME dual.course.test.\n"
                "dual.course.test. 0 IN AAAA ::1\n")
        result = self.probe.parse_result(text, 0)
        self.assertEqual(result["classification"], "answer")
        self.assertEqual([r["type"] for r in result["records"]], ["CNAME", "AAAA"])
        self.assertEqual(result["records"][1]["data"], "::1")

    def test_successful_no_data_is_distinct_from_name_and_transport_failure(self):
        cases = [
            ("NOERROR", 0, False, "no_data"),
            ("NXDOMAIN", 0, False, "negative_name"),
            ("SERVFAIL", 0, False, "dns_error"),
            ("REFUSED", 0, False, "dns_error"),
            ("NXDOMAIN", 9, False, "transport_failure"),
            ("NOERROR", 0, True, "transport_failure"),
            ("NOERROR", 2, False, "tool_failure"),
        ]
        for status, code, timeout, expected in cases:
            with self.subTest(status=status, code=code, timeout=timeout):
                text = ";; ->>HEADER<<- opcode: QUERY, status: " + status + ", id: 3\n"
                self.assertEqual(self.probe.parse_result(text, code, timeout)["classification"],
                                 expected)

    def test_missing_header_is_preserved_as_unrecognized(self):
        self.assertEqual(self.probe.parse_result("", 0)["classification"],
                         "unrecognized_result")

    def test_case_shape_and_types_refuse_ambiguous_or_external_inputs(self):
        bad = [None, [], {"question": []}, {"question": "example.com"},
               {"question": "alias.course.test", "extra": True}]
        for case in bad:
            with self.subTest(case=case):
                with self.assertRaises(ValueError):
                    self.probe.validate_case("alias-transfer", case)
        for case in [{"stoppedClaim": []}, {"stoppedClaim": True}, {"stoppedClaim": "answer"}]:
            with self.assertRaises(ValueError):
                self.probe.validate_case("negative-vs-transport", case)

    def test_case_data_is_the_only_role_runtime_difference(self):
        runtimes = [(ROOT / pack / role / "dns_probe.py").read_bytes()
                    for pack in PACKS for role in ["starter", "solution"]]
        self.assertTrue(all(body == runtimes[0] for body in runtimes))

if __name__ == "__main__":
    unittest.main()
