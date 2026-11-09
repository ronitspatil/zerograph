import textwrap

import pytest

from zerograph.scan import scan


@pytest.fixture
def scan_files(tmp_path):
    """Write {relative path: text} into a temp dir and scan it."""

    def run(files: dict[str, str]):
        for rel, text in files.items():
            path = tmp_path / rel
            path.parent.mkdir(parents=True, exist_ok=True)
            path.write_text(textwrap.dedent(text))
        return scan(str(tmp_path))

    return run


def edges(g, src):
    return {(e.dst, e.rel) for e in g.edges if e.src == src}


def targets(g, src):
    return {e.dst for e in g.edges if e.src == src}
