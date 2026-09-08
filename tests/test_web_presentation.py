"""Static checks for the public presentation, without running the scanner."""
from html.parser import HTMLParser
from pathlib import Path
import unittest
from urllib.parse import unquote, urlsplit


WEB = Path(__file__).resolve().parents[1] / "docs" / "web"


class Page(HTMLParser):
    def __init__(self, text):
        super().__init__()
        self.elements = []
        self.ids = []
        self.feed(text)

    def handle_starttag(self, tag, attrs):
        values = dict(attrs)
        self.elements.append((tag, values))
        if "id" in values:
            self.ids.append(values["id"])


class PublicWebsiteTests(unittest.TestCase):
    def test_only_public_static_files_are_packaged(self):
        allowed = {".html", ".css", ".js", ".svg", ".png", ".xml", ".txt"}
        for path in WEB.rglob("*"):
            self.assertFalse(path.is_symlink(), path.name)
            if not path.is_file():
                continue
            self.assertTrue(path.suffix in allowed or path.name in {".nojekyll", "LICENSE"}, path.name)
            self.assertLess(path.stat().st_size, 1_000_000, path.name)
        index = (WEB / "index.html").read_text(encoding="utf-8")
        self.assertIn('href="https://rogerf5-security.github.io/Scan-Titan/"', index)

    def test_assets_and_local_links_resolve_inside_website(self):
        for path in WEB.glob("*.html"):
            page = Page(path.read_text(encoding="utf-8"))
            self.assertEqual(len(page.ids), len(set(page.ids)), path.name)
            for tag, attrs in page.elements:
                value = attrs.get("href") or attrs.get("src")
                if not value:
                    continue
                url = urlsplit(value)
                if url.scheme or url.netloc:
                    self.assertEqual(url.scheme, "https", value)
                    continue
                if not url.path and url.fragment:
                    self.assertIn(url.fragment, page.ids, value)
                    continue
                destination = (path.parent / unquote(url.path)).resolve()
                self.assertTrue(destination.is_relative_to(WEB.resolve()), value)
                self.assertTrue(destination.is_file(), value)

    def test_tab_contract_and_images(self):
        page = Page((WEB / "index.html").read_text(encoding="utf-8"))
        for tag, attrs in page.elements:
            if attrs.get("role") == "tab":
                self.assertIn(attrs["aria-controls"], page.ids)
                self.assertIn(attrs["aria-selected"], {"true", "false"})
            if tag == "img":
                self.assertIn("alt", attrs)
                self.assertIn("width", attrs)
                self.assertIn("height", attrs)

    def test_no_remote_runtime_or_private_audit_data(self):
        for path in WEB.rglob("*"):
            if path.suffix not in {".html", ".css", ".js", ".txt", ".xml"}:
                continue
            content = path.read_text(encoding="utf-8")
            for private_marker in ("claro.com.gt", "boipseg", "10.254.", "C:\\Users\\", "ghp_", "github_pat_"):
                self.assertNotIn(private_marker, content, path.name)
            if path.suffix == ".html":
                for tag, attrs in Page(content).elements:
                    if tag in {"script", "iframe", "form"}:
                        self.assertNotIn(tag, {"iframe", "form"})
                        self.assertFalse(urlsplit(attrs.get("src", "")).scheme)
        index = (WEB / "index.html").read_text(encoding="utf-8")
        self.assertIn('lang="es"', index)
        self.assertIn("DATOS FICTICIOS", index)
        self.assertIn("connect-src 'none'", index)


if __name__ == "__main__":
    unittest.main()
