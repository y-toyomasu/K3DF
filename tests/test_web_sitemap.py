import unittest
from xml.etree import ElementTree

from web.app import app


class WebSitemapTest(unittest.TestCase):
    def setUp(self):
        self.client = app.test_client()

    def test_sitemap_is_valid_xml_and_lists_ap1(self):
        response = self.client.get("/sitemap.xml")

        self.assertEqual(response.status_code, 200)
        self.assertEqual(response.content_type, "application/xml")
        root = ElementTree.fromstring(response.data)
        namespace = "{http://www.sitemaps.org/schemas/sitemap/0.9}"
        self.assertEqual(root.tag, f"{namespace}urlset")
        self.assertEqual(
            [location.text for location in root.findall(f"{namespace}url/{namespace}loc")],
            ["/ap1/"],
        )

    def test_sitemap_does_not_disclose_bypass_or_secret_material(self):
        body = self.client.get("/sitemap.xml").get_data(as_text=True).lower()

        for prohibited in ("x-middleware-subrequest", "flag", "credential", "secret", "password"):
            self.assertNotIn(prohibited, body)


if __name__ == "__main__":
    unittest.main()
