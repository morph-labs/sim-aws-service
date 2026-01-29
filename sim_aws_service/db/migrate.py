from __future__ import annotations

from importlib import resources

from sim_aws_service.db.db import Database


def apply_migrations(db: Database) -> None:
    db.execute(
        """
        CREATE TABLE IF NOT EXISTS schema_migrations (
          version INTEGER PRIMARY KEY,
          applied_at TEXT NOT NULL
        );
        """
    )

    migration_dir = resources.files("sim_aws_service.db.migrations")
    migration_files = [p for p in migration_dir.iterdir() if p.name.endswith(".sql")]

    def version_key(p) -> int:
        return int(p.name.split("_", 1)[0])

    migration_files.sort(key=version_key)

    for p in migration_files:
        version = version_key(p)
        row = db.fetchone("SELECT 1 FROM schema_migrations WHERE version = ?;", (version,))
        if row is not None:
            continue
        sql = p.read_text(encoding="utf-8")
        with db.session() as conn:
            conn.executescript(sql)
            conn.execute(
                "INSERT INTO schema_migrations(version, applied_at) VALUES (?, datetime('now'));",
                (version,),
            )
