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
                    if url.scheme == "data":
                        self.assertEqual(tag, "link", value)
                        self.assertEqual(attrs.get("rel"), "icon", value)
                    else:
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

    def test_single_file_landing_contains_requested_sections_and_motion(self):
        index = (WEB / "index.html").read_text(encoding="utf-8")
        self.assertIn("<style>", index)
        self.assertIn("<script>", index)
        self.assertNotIn('rel="stylesheet"', index)
        self.assertNotIn('src="app.js"', index)
        for section_id in ("inicio", "motor", "capacidades", "operar", "origen", "futuro", "comunidad"):
            self.assertIn(f'id="{section_id}"', index)
        for phrase in ("Vulnerability Scanner", "Open Source", "Nmap", "Nuclei", "Daily Dashboard", "Scan Ragnarok", "Pull Request"):
            self.assertIn(phrase.casefold(), index.casefold())
        self.assertIn("IntersectionObserver", index)
        self.assertIn("prefers-reduced-motion", index)
        for output in ("Daily_vulns_report.html", "Formal_Audit_Report_Latest.html", "Recon_Matrix.xlsx", "External_Tools_Observability.html"):
            self.assertIn(output, index)
        for command in ("python main.py --health-check", "python main.py --full", "python main.py --monitor", "python main.py --dashboard"):
            self.assertIn(command, index)

    def test_toolchain_and_wordlist_inventory_are_visible(self):
        index = (WEB / "index.html").read_text(encoding="utf-8")
        for tool in ("Nmap", "Nuclei", "ffuf", "WhatWeb", "Subfinder", "wafw00f", "OWASP ZAP"):
            self.assertIn(tool.casefold(), index.casefold())

        wordlists = WEB.parents[1] / "wordlists"
        expected = {
            "403bypass.txt", "command_injection.txt", "lfi.txt", "passwords.txt",
            "rutas.txt", "sqli.txt", "ssrf.txt", "ssti.txt", "subdomains.txt",
            "users.txt", "xss.txt",
        }
        for filename in expected:
            values = []
            seen = set()
            for line in (wordlists / filename).read_text(encoding="utf-8", errors="ignore").splitlines():
                value = line.strip()
                key = value.casefold()
                if not value or value.startswith("#") or key in seen:
                    continue
                seen.add(key)
                values.append(value)
            self.assertIn(filename, index)
            self.assertIn(f"{len(values):,}".replace(",", "."), index)

    def test_no_remote_runtime_or_private_audit_data(self):
        for path in WEB.rglob("*"):
            if path.suffix not in {".html", ".css", ".js", ".txt", ".xml"}:
                continue
            content = path.read_text(encoding="utf-8")
            for private_marker in ("C:\\Users\\", "ghp_", "github_pat_", "BEGIN PRIVATE KEY"):
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
