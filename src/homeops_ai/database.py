from contextlib import contextmanager
from pathlib import Path
from typing import Iterator

from pycozo.client import Client


@contextmanager
def open_database(path: Path | None = None) -> Iterator[Client]:
    """Open an embedded in-memory or persistent RocksDB-backed Cozo database."""
    client = (
        Client(dataframe=False)
        if path is None
        else Client("rocksdb", str(path), dataframe=False)
    )
    try:
        yield client
    finally:
        client.close()


def run_smoke_test(path: Path | None = None) -> list[list[object]]:
    """Create, query, and return a minimal relation."""
    with open_database(path) as client:
        relations = client.run("::relations")
        if not any(row[0] == "smoke" for row in relations["rows"]):
            client.run(":create smoke {name: String => value: Int}")
        client.run(
            "?[name, value] <- [[$name, $value]] :put smoke {name => value}",
            {"name": "cozo", "value": 1},
        )
        result = client.run("?[name, value] := *smoke{name, value}")

    return result["rows"]
