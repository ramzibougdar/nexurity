"""Copy PROMPT.md into the installation guide (index.html), between the PROMPT markers."""
import html
import pathlib
import re
import sys

root = pathlib.Path(__file__).resolve().parents[2]
guide = root / "index.html"
prompt = (root / "PROMPT.md").read_text(encoding="utf-8").rstrip("\n")

page = guide.read_text(encoding="utf-8")
pattern = re.compile(r"(<!-- PROMPT:START -->).*?(<!-- PROMPT:END -->)", re.S)
if not pattern.search(page):
    sys.exit("index.html: PROMPT markers not found")
page = pattern.sub(lambda m: m.group(1) + html.escape(prompt, quote=False) + m.group(2), page, count=1)
guide.write_text(page, encoding="utf-8")
