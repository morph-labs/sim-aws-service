from __future__ import annotations

import contextlib
import sqlite3
from dataclasses import dataclass
from pathlib import Path
from typing import Any, Iterable, Iterator


def _sqlite_path_from_url(db_url: str) -> tuple[str, bool]:
    if db_url == "sqlite://:memory:":
        return ":memory:", False
    if db_url.startswith("sqlite:///"):
        return db_url[len("sqlite:///") :], False
    if db_url.startswith("sqlite://"):
        return db_url[len("sqlite://") :], True
    raise ValueError(f"Unsupported db_url (expected sqlite://...): {db_url}")


@dataclass(frozen=True)
class Database:
    db_url: str

    def connect(self) -> sqlite3.Connection:
        path, is_uri = _sqlite_path_from_url(self.db_url)
        if path not in (":memory:", ""):
            Path(path).parent.mkdir(parents=True, exist_ok=True)
        conn = sqlite3.connect(path, uri=is_uri, check_same_thread=False)
        conn.row_factory = sqlite3.Row
        conn.execute("PRAGMA foreign_keys = ON;")
        return conn

    @contextlib.contextmanager
    def session(self) -> Iterator[sqlite3.Connection]:
        conn = self.connect()
        try:
            yield conn
            conn.commit()
        except Exception:
            conn.rollback()
            raise
        finally:
            conn.close()

    def execute(self, sql: str, params: Iterable[Any] = ()) -> None:
        with self.session() as conn:
            conn.execute(sql, tuple(params))

    def executemany(self, sql: str, seq_of_params: Iterable[Iterable[Any]]) -> None:
        with self.session() as conn:
            conn.executemany(sql, [tuple(p) for p in seq_of_params])

    def fetchone(self, sql: str, params: Iterable[Any] = ()) -> sqlite3.Row | None:
        with self.session() as conn:
            cur = conn.execute(sql, tuple(params))
            return cur.fetchone()

    def fetchall(self, sql: str, params: Iterable[Any] = ()) -> list[sqlite3.Row]:
        with self.session() as conn:
            cur = conn.execute(sql, tuple(params))
            return list(cur.fetchall())

