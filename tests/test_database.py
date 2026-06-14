from pathlib import Path

from homeops_ai.database import open_database, run_smoke_test


def test_in_memory_smoke() -> None:
    assert run_smoke_test() == [["cozo", 1]]


def test_rocksdb_persists_across_reopen(tmp_path: Path) -> None:
    database = tmp_path / "homeops.db"

    assert run_smoke_test(database) == [["cozo", 1]]
    assert run_smoke_test(database) == [["cozo", 1]]

    with open_database(database) as client:
        result = client.run("?[name, value] := *smoke{name, value}")

    assert result["rows"] == [["cozo", 1]]
