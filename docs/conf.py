"""Sphinx configuration for conda-advise documentation."""

from __future__ import annotations

import re
from pathlib import Path

from docutils import nodes

PROJECT_ROOT = Path(__file__).resolve().parents[1]

project = html_title = "conda-advise"
copyright = "2026, Jannis Leidel"
author = "Jannis Leidel"

extensions = [
    "myst_parser",
    "sphinx.ext.autodoc",
    "sphinx.ext.autosummary",
    "sphinx.ext.napoleon",
    "sphinx.ext.viewcode",
    "sphinx_copybutton",
    "sphinx_design",
    "sphinx_reredirects",
    "sphinx_sitemap",
    "sphinxarg.ext",
]

myst_enable_extensions = ["colon_fence", "deflist", "fieldlist", "tasklist"]
myst_url_schemes = {
    "http": None,
    "https": None,
    "mailto": None,
    "ftp": None,
}

GITHUB_REF_RE = re.compile(r"(?<![\w/])#([0-9]+)\b")
GITHUB_ISSUE_URL = "https://github.com/jezdez/conda-advise/issues/"


def link_changelog_github_refs(
    app,
    doctree: nodes.document,
    docname: str,
) -> None:
    """Link bare issue references while rendering the included changelog."""
    if docname != "changelog":
        return

    for text_node in list(doctree.findall(nodes.Text)):
        parent = text_node.parent
        while parent is not None:
            if isinstance(
                parent,
                (nodes.reference, nodes.literal, nodes.literal_block, nodes.raw),
            ):
                break
            parent = parent.parent
        else:
            text = text_node.astext()
            matches = list(GITHUB_REF_RE.finditer(text))
            if not matches:
                continue

            replacements: list[nodes.Node] = []
            cursor = 0
            for match in matches:
                if match.start() > cursor:
                    replacements.append(nodes.Text(text[cursor : match.start()]))
                reference = match.group(0)
                replacements.append(
                    nodes.reference(
                        "",
                        reference,
                        refuri=f"{GITHUB_ISSUE_URL}{match.group(1)}",
                        classes=["github"],
                    )
                )
                cursor = match.end()
            if cursor < len(text):
                replacements.append(nodes.Text(text[cursor:]))
            text_node.parent.replace(text_node, replacements)


html_theme = "conda_sphinx_theme"
html_theme_options = {
    "use_edit_page_button": True,
    "icon_links": [
        {
            "name": "GitHub",
            "url": "https://github.com/jezdez/conda-advise",
            "icon": "fa-brands fa-square-github",
            "type": "fontawesome",
        },
    ],
}
html_context = {
    "github_user": "jezdez",
    "github_repo": "conda-advise",
    "github_version": "main",
    "doc_path": "docs",
}
html_static_path = ["_static"]
html_extra_path = ["robots.txt", "../demos", "../schema"]
html_css_files = ["css/custom.css"]
html_baseurl = "https://jezdez.github.io/conda-advise/"
exclude_patterns = ["_build"]
linkcheck_anchors = False
linkcheck_ignore = [r"http://127\.0\.0\.1(?::\d+)?/.*"]


def setup(app) -> None:
    """Register local documentation transforms."""
    app.connect("doctree-resolved", link_changelog_github_refs)
