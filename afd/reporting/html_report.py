"""HTML report: render the report context with the Jinja2 template in templates/.

The page is self-contained (no external CSS or scripts), so it opens offline and
prints cleanly from a browser ("Save as PDF" also works).
"""
from pathlib import Path

from jinja2 import Environment, FileSystemLoader, select_autoescape

TEMPLATE_DIR = Path(__file__).parent / "templates"

_env = Environment(
    loader=FileSystemLoader(TEMPLATE_DIR),
    autoescape=select_autoescape(["html", "j2"]),   # file names and log text are escaped
)


def render_html(context: dict) -> str:
    return _env.get_template("report.html.j2").render(**context)
