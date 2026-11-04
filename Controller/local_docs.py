"""Serve a lightweight reader of the checked-out Mintlify sources on the sensor."""

import html
from pathlib import Path
import re
from urllib.parse import unquote


DOCS = Path(__file__).resolve().parent.parent / "docs-site"


def document(path):
    relative = unquote(path.removeprefix("/docs")).lstrip("/") or "index"
    target = (DOCS / relative).resolve()
    if not target.is_relative_to(DOCS.resolve()):
        return 404, "text/plain", b"Unknown documentation page"
    if target.suffix == "":
        target = target.with_suffix(".mdx")
    if target.suffix not in (".mdx", ".md", ".json") or not target.is_file():
        return 404, "text/plain", b"Unknown documentation page"
    content = target.read_text(encoding="utf-8")
    if target.suffix == ".json":
        return 200, "application/json", content.encode()
    title = target.stem.replace("-", " ").title()
    if content.startswith("---"):
        _, frontmatter, content = content.split("---", 2)
        match = re.search(r'^title:\s*"(.*)"', frontmatter, re.MULTILINE)
        if match:
            title = match[1]
    # Translate the small set of native components used by this site's Markdown pages.
    content = re.sub(r'<Step title="([^"]+)">', r"\n### \1\n", content)
    content = re.sub(r'<Card title="([^"]+)" href="([^"]+)">(.*?)</Card>',
                     r"[\1](\2) — \3", content, flags=re.DOTALL)
    content = re.sub(r'</?(?:Steps|Step|CardGroup|Note|Tip|Info|Warning)(?:\s[^>]*)?>', "", content)
    try:
        import markdown
        body = markdown.markdown(content, extensions=["fenced_code", "tables"])
        body = re.sub(r'href="/(?!docs/)', 'href="/docs/', body)
    except ImportError:
        body = "<p>Install Markdown for formatted pages.</p><pre>" + html.escape(content) + "</pre>"
    links = []
    for page in sorted(DOCS.rglob("*.mdx")):
        route = page.relative_to(DOCS).with_suffix("").as_posix()
        label = html.escape(route.replace("-", " "))
        links.append(f'<li><a href="/docs/{route}">{label}</a></li>')
    page = f'''<!doctype html><html lang="en"><meta charset="utf-8">
<meta name="viewport" content="width=device-width, initial-scale=1"><title>{html.escape(title)}</title>
<style>body{{font:16px/1.6 system-ui;margin:0;background:#101317;color:#e5e7eb}}a{{color:#5eead4}}
nav{{padding:20px;max-width:290px}}main{{padding:30px;min-width:0;max-width:1000px}}
.layout{{display:flex}}pre{{overflow:auto;padding:16px;background:#20252c}}table{{border-collapse:collapse}}
td,th{{padding:10px;border:1px solid #59616c}}@media(max-width:750px){{.layout{{display:block}}}}</style>
<div class="layout"><nav><a href="/">Dashboard</a><p>Documentation from this checkout</p>
<ul>{''.join(links)}</ul></nav><main><h1>{html.escape(title)}</h1>{body}</main></div></html>'''
    return 200, "text/html; charset=utf-8", page.encode()
