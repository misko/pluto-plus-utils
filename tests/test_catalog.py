from __future__ import annotations

from pluto_plus.catalog import Catalog


def test_empty_catalog_is_queryable(tmp_path) -> None:
    catalog = Catalog(tmp_path / "catalog.sqlite3")
    assert catalog.list_artifacts() == []
    assert catalog.list_analyses() == []
    assert catalog.get_artifact("missing") is None
    assert catalog.get_analysis("missing") is None
