from pathlib import Path
import unittest


ROOT = Path(__file__).resolve().parents[1]


class Ap1IngressConfigurationTest(unittest.TestCase):
    def setUp(self):
        self.compose = (ROOT / "compose.yaml").read_text(encoding="utf-8")
        self.nginx = (ROOT / "nginx" / "nginx.conf").read_text(encoding="utf-8")

    def test_ap1_service_has_only_its_read_only_flag_volume_and_no_port(self):
        service = self.compose.split("  challenge-next-ap1:\n", 1)[1].split("\n  referee:", 1)[0]
        self.assertIn('      - "3000"', service)
        self.assertNotIn("ports:", service)
        self.assertIn("volumes:", service)
        self.assertIn(":ro", service)
        self.assertEqual(service.count("k3df-ctf-flag-"), 1)
        self.assertNotIn("k3df-ctf-flag-2", service)
        self.assertNotIn("k3df-ctf-flag-3", service)
        self.assertNotIn("k3df-referee-state", service)
        self.assertIn("cap_drop:", service)
        self.assertIn("no-new-privileges:true", service)

    def test_ap1_forwards_the_bypass_header_only_on_its_route(self):
        ap1 = self.nginx.split("        location /ap1/ {\n", 1)[1].split("\n        }", 1)[0]
        web = self.nginx.split("        location / {\n", 1)[1].split("\n        }", 1)[0]
        self.assertIn("proxy_pass http://challenge_next_ap1/;", ap1)
        self.assertIn("proxy_set_header x-middleware-subrequest $http_x_middleware_subrequest;", ap1)
        self.assertIn('proxy_set_header x-middleware-subrequest "";', web)


if __name__ == "__main__":
    unittest.main()
