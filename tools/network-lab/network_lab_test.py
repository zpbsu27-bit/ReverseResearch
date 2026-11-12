"""Pure observation contracts; real namespaces are covered by the Agent matrix."""
import types
import unittest

from network_lab import Lab


class ObservedMappingContracts(unittest.TestCase):
    forward = "ipv4 2 udp 17 29 src=10.231.1.2 dst=198.18.0.1 sport=40001 dport=56809 src=198.18.0.1 dst=198.18.10.2 sport=56809 dport=40001 mark=0 use=1"
    reverse = "ipv4 2 udp 17 29 src=198.18.0.1 dst=198.18.20.2 sport=56809 dport=40002 src=10.231.2.2 dst=198.18.0.1 sport=40002 dport=56809 mark=0 use=1"

    def lab(self, raw):
        lab = object.__new__(Lab)
        lab.profile = {"nat": "single"}
        lab.assert_owned = lambda role: self.assertIn(role, ("na", "nb"))
        lab.run = lambda argv, role: types.SimpleNamespace(stdout=raw)
        return lab

    def test_original_outbound_tuple(self):
        observed = self.lab(self.forward).observe_udp_endpoint("na", "10.231.1.2", 40001, 56809)
        self.assertEqual((observed["mappedIP"], observed["mappedPort"]), ("198.18.10.2", 40001))
        self.assertEqual(observed["actualConntrack"], self.forward)

    def test_relay_first_reverse_tuple(self):
        observed = self.lab(self.reverse).observe_udp_endpoint("nb", "10.231.2.2", 40002, 56809)
        self.assertEqual((observed["mappedIP"], observed["mappedPort"]), ("198.18.20.2", 40002))
        self.assertEqual(observed["actualConntrack"], self.reverse)

    def test_uses_actual_mapped_port(self):
        raw = self.reverse.replace("dst=198.18.20.2 sport=56809 dport=40002", "dst=198.18.20.2 sport=56809 dport=41552")
        self.assertEqual(self.lab(raw).observe_udp_endpoint("nb", "10.231.2.2", 40002, 56809)["mappedPort"], 41552)

    def test_duplicate_exact_tuples_are_rejected(self):
        with self.assertRaisesRegex(RuntimeError, "EXACT_OUTBOUND"):
            self.lab(self.reverse+"\n"+self.reverse).observe_udp_endpoint("nb", "10.231.2.2", 40002, 56809)

    def test_other_peer_or_relay_port_is_rejected(self):
        for raw in (self.reverse.replace("src=198.18.0.1", "src=198.18.10.2"), self.reverse.replace("sport=56809", "sport=56810")):
            with self.subTest(raw=raw), self.assertRaisesRegex(RuntimeError, "EXACT_OUTBOUND"):
                self.lab(raw).observe_udp_endpoint("nb", "10.231.2.2", 40002, 56809)

    def test_wrong_public_address_is_rejected(self):
        with self.assertRaisesRegex(RuntimeError, "PUBLIC_SCOPE"):
            self.lab(self.reverse.replace("dst=198.18.20.2", "dst=198.18.10.2")).observe_udp_endpoint("nb", "10.231.2.2", 40002, 56809)

    def test_source_and_numeric_scope_remain_strict(self):
        with self.assertRaises(ValueError):
            self.lab(self.reverse).observe_udp_endpoint("nb", "10.231.1.2", 40002, 56809)
        with self.assertRaises(ValueError):
            self.lab(self.reverse).observe_udp_endpoint("nb", "10.231.2.2", True, 56809)
        with self.assertRaisesRegex(RuntimeError, "EXACT_OUTBOUND"):
            self.lab("").observe_udp_endpoint("nb", "10.231.2.2", 40002, 56809)


if __name__ == "__main__":
    unittest.main()
